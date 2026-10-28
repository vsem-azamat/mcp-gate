package toolpins

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/sys/unix"
)

// Dir is the directory under the state directory that holds the pins, one file per server.
const Dir = "toolpins"

// maxFileBytes bounds a pins file.
const maxFileBytes = 64 << 20

// Locking: how long a lock another process holds is waited for, and how often it is tried.
const (
	lockWait = 5 * time.Second
	lockPoll = 20 * time.Millisecond
)

// Limits on a server whose tools keep changing.
const (
	// ReportLimit is how many changes of one server are reported per ReportWindow. The rest
	// stay unreported, and are reported by a listing after the window, while still listed.
	ReportLimit  = 20
	ReportWindow = time.Minute
	// suppressedNamed is how many of the changes left unreported a summary names.
	suppressedNamed = 3
)

// tmpPrefix starts the name of a temporary pins file: .tmp+<server>+<random>. Server names hold
// no "+", so the temporary files of one server cannot be taken for another's.
const tmpPrefix = ".tmp+"

// ErrNoPins is returned for a server that has no pins.
var ErrNoPins = errors.New("no tool pins")

// Store keeps the pins of servers: in <stateDir>/toolpins/<server>.json, or in memory when it
// has no state directory. Server names are config server names, which are safe file names.
type Store struct {
	dir string // "" keeps the pins in memory
	now func() time.Time
	// failWrite, if set, fails every write; for tests.
	failWrite error

	// mu guards servers and mem; it is never held while a server's own lock is waited for.
	mu      sync.Mutex
	servers map[string]*serverState
	mem     map[string]*File
}

// serverState is what the store keeps of one server in this process. mu serializes the
// server's operations here; the lock file serializes them between processes.
type serverState struct {
	mu sync.Mutex
	// reported holds, by tool, the hash and action of the change last reported, so that a
	// change is reported once per process and action.
	reported map[string]string
	// window is when the current report window began, reports how many changes were reported
	// in it, and summarized whether the changes left unreported in it were summarized.
	window     time.Time
	reports    int
	summarized bool
}

// New returns the store under a state directory; with an empty one it keeps the pins in memory.
func New(stateDir string) *Store {
	s := &Store{mem: map[string]*File{}, servers: map[string]*serverState{}, now: time.Now}
	if stateDir != "" {
		s.dir = filepath.Join(stateDir, Dir)
	}
	return s
}

// Persistent reports whether the pins are kept in a state directory.
func (s *Store) Persistent() bool { return s.dir != "" }

// state returns the server's state, locked; the caller unlocks it.
func (s *Store) state(server string) *serverState {
	s.mu.Lock()
	st := s.servers[server]
	if st == nil {
		st = &serverState{reported: map[string]string{}}
		s.servers[server] = st
	}
	s.mu.Unlock()
	st.mu.Lock()
	return st
}

// Change is a tool whose listed definition is not its accepted one, reported once per hash and
// action.
type Change struct {
	Tool string
	// Kind is Changed or Added.
	Kind string
	// Pinned is the accepted hash, "" for Added; Listed is the hash the server lists.
	Pinned, Listed string
}

// Result is what Check found.
type Result struct {
	// Held are the tools to leave out of the catalog, by name.
	Held map[string]bool
	// Changes are the changes to report, sorted by tool.
	Changes []Change
	// Suppressed, set once per ReportWindow, counts the changes this listing leaves unreported
	// because the server went over ReportLimit, and SuppressedTools names a few of them.
	Suppressed      int
	SuppressedTools []string
	// Pinned is how many tools a first listing pinned.
	Pinned int
	// Err is why the pins could not be read or written; under hold every listed tool is then
	// held, but for a write that only failed to record a pending definition.
	Err error
}

// Check compares a listing of the server's tools with its pins and records what differs: a
// server without pins has every listed tool pinned; a tool whose definition differs from its
// accepted one, or that has none, gets the listed definition as pending; a pending definition of
// a tool listed as accepted again or no longer listed is dropped, and a tool no longer listed
// with nothing accepted is forgotten. With
// hold, the changed and added tools are held. A name listed more than once counts once, as
// first listed.
func (s *Store) Check(server string, hold bool, tools []*mcp.Tool) Result {
	st := s.state(server)
	defer st.mu.Unlock()
	listed := map[string]*Pin{}
	var res Result
	holdAll := func(err error) Result {
		res.Err = err
		if hold {
			res.Held = map[string]bool{}
			for _, t := range tools {
				if t != nil {
					res.Held[t.Name] = true
				}
			}
		}
		return res
	}
	now := s.now().UTC()
	for _, t := range tools {
		if t == nil || listed[t.Name] != nil {
			continue
		}
		def, hash, err := Define(t)
		if err != nil {
			return holdAll(fmt.Errorf("a tool's definition does not encode: %w", err))
		}
		listed[t.Name] = &Pin{Hash: hash, Definition: def, At: now}
	}
	unlock, err := s.lock(server)
	if err != nil {
		return holdAll(err)
	}
	defer unlock()
	f, err := s.read(server)
	if errors.Is(err, ErrNoPins) {
		f = &File{Version: FileVersion, Server: server, Tools: map[string]*Entry{}}
		for name, p := range listed {
			f.Tools[name] = &Entry{Accepted: p}
		}
		clear(st.reported)
		if err := s.write(server, f); err != nil {
			// Nothing was pinned: trusting the listing would trust every later one too.
			return holdAll(err)
		}
		res.Pinned = len(listed)
		return res
	}
	if err != nil {
		return holdAll(err)
	}
	action := "warn"
	if hold {
		action = "hold"
	}
	if now.Sub(st.window) >= ReportWindow {
		st.window, st.reports, st.summarized = now, 0, false
	}
	dirty := false
	var suppressed []string
	for _, name := range slices.Sorted(maps.Keys(listed)) {
		p := listed[name]
		e := f.Tools[name]
		if e != nil && e.Accepted != nil && e.Accepted.Hash == p.Hash {
			if e.Pending != nil {
				e.Pending = nil
				dirty = true
			}
			delete(st.reported, name)
			continue
		}
		if e == nil {
			e = &Entry{}
			f.Tools[name] = e
		}
		if e.Pending == nil || e.Pending.Hash != p.Hash {
			e.Pending = p
			dirty = true
		}
		if hold {
			if res.Held == nil {
				res.Held = map[string]bool{}
			}
			res.Held[name] = true
		}
		if key := p.Hash + " " + action; st.reported[name] != key {
			if st.reports >= ReportLimit {
				suppressed = append(suppressed, name)
				continue
			}
			st.reported[name] = key
			st.reports++
			c := Change{Tool: name, Kind: e.Change(), Listed: p.Hash}
			if e.Accepted != nil {
				c.Pinned = e.Accepted.Hash
			}
			res.Changes = append(res.Changes, c)
		}
	}
	if len(suppressed) > 0 && !st.summarized {
		st.summarized = true
		res.Suppressed, res.SuppressedTools = len(suppressed), suppressed[:min(len(suppressed), suppressedNamed)]
	}
	for name, e := range f.Tools {
		if listed[name] != nil {
			continue
		}
		delete(st.reported, name)
		if e.Pending != nil {
			e.Pending = nil
			dirty = true
		}
		if e.Accepted == nil {
			delete(f.Tools, name)
		}
	}
	if dirty {
		res.Err = s.write(server, f)
	}
	return res
}

// Load returns the pins of a server; ErrNoPins when it has none.
func (s *Store) Load(server string) (*File, error) {
	st := s.state(server)
	defer st.mu.Unlock()
	unlock, err := s.lock(server)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return s.read(server)
}

// Servers returns the names of the servers with pins, sorted.
func (s *Store) Servers() ([]string, error) {
	if s.dir == "" {
		s.mu.Lock()
		defer s.mu.Unlock()
		return slices.Sorted(maps.Keys(s.mem)), nil
	}
	ents, err := os.ReadDir(s.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if name, ok := strings.CutSuffix(e.Name(), ".json"); ok && e.Type().IsRegular() && !strings.HasPrefix(name, tmpPrefix) {
			out = append(out, name)
		}
	}
	return out, nil
}

// Accept makes the pending definition of the tools in want, by name, their accepted one, each
// only when its pending hash is the one given, and returns the tools accepted, sorted. A tool
// with nothing pending, or with another pending hash, fails it, and nothing is accepted.
func (s *Store) Accept(server string, want map[string]string) ([]string, error) {
	if len(want) == 0 {
		return nil, errors.New("no tool named")
	}
	return s.accept(server, want)
}

// AcceptAll makes the pending definition of every pending tool its accepted one, and returns
// the tools accepted, sorted.
func (s *Store) AcceptAll(server string) ([]string, error) { return s.accept(server, nil) }

// accept is Accept with want nil taking every pending tool as it is.
func (s *Store) accept(server string, want map[string]string) ([]string, error) {
	st := s.state(server)
	defer st.mu.Unlock()
	unlock, err := s.lock(server)
	if err != nil {
		return nil, err
	}
	defer unlock()
	f, err := s.read(server)
	if err != nil {
		return nil, err
	}
	all := want == nil
	if all {
		want = map[string]string{}
		for _, name := range f.Pending() {
			want[name] = ""
		}
	}
	names := slices.Sorted(maps.Keys(want))
	var missing, moved []string
	for _, name := range names {
		e := f.Tools[name]
		switch {
		case e == nil || e.Pending == nil:
			missing = append(missing, name)
		case !all && want[name] != e.Pending.Hash:
			moved = append(moved, name)
		}
	}
	var errs []error
	if len(missing) > 0 {
		errs = append(errs, fmt.Errorf("nothing pending for %s", strings.Join(missing, ", ")))
	}
	if len(moved) > 0 {
		errs = append(errs, fmt.Errorf("the pending definition of %s is not the one given; review it again", strings.Join(moved, ", ")))
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	if len(names) == 0 {
		return nil, nil
	}
	now := s.now().UTC()
	for _, name := range names {
		e := f.Tools[name]
		e.Accepted, e.Pending = e.Pending, nil
		e.Accepted.At = now
	}
	if err := s.write(server, f); err != nil {
		return nil, err
	}
	return names, nil
}

func (s *Store) path(server string) string { return filepath.Join(s.dir, server+".json") }

// read returns the server's pins; ErrNoPins when there is no file. The caller holds the lock.
func (s *Store) read(server string) (*File, error) {
	if s.dir == "" {
		s.mu.Lock()
		defer s.mu.Unlock()
		f := s.mem[server]
		if f == nil {
			return nil, ErrNoPins
		}
		return cloneFile(f), nil
	}
	fh, err := os.OpenFile(s.path(server), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoPins
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read the tool pins: %w", bare(err))
	}
	defer fh.Close()
	data, err := io.ReadAll(io.LimitReader(fh, maxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read the tool pins: %w", bare(err))
	}
	if len(data) > maxFileBytes {
		return nil, errors.New("the tool pins file is too large")
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil || f.Version != FileVersion || f.Tools == nil {
		return nil, fmt.Errorf("%s/%s.json is not a tool pins file of version %d", Dir, server, FileVersion)
	}
	for name, e := range f.Tools {
		if e == nil || (e.Accepted == nil && e.Pending == nil) {
			delete(f.Tools, name)
		}
	}
	return &f, nil
}

// write stores the server's pins: to a temporary file in the same directory, synced, then
// renamed over the old one. Temporary files of the server left by a process that died are
// removed first. The caller holds the lock.
func (s *Store) write(server string, f *File) error {
	if s.failWrite != nil {
		return s.failWrite
	}
	if s.dir == "" {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.mem[server] = cloneFile(f)
		return nil
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	prefix := tmpPrefix + server + "+"
	if stale, err := filepath.Glob(filepath.Join(s.dir, prefix+"*")); err == nil {
		for _, p := range stale {
			_ = os.Remove(p) // under the lock, no other write is under way
		}
	}
	tmp, err := os.CreateTemp(s.dir, prefix+"*") // mode 0600
	if err != nil {
		return fmt.Errorf("cannot write the tool pins: %w", bare(err))
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // gone after the rename
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("cannot write the tool pins: %w", bare(err))
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("cannot write the tool pins: %w", bare(err))
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cannot write the tool pins: %w", bare(err))
	}
	if err := os.Rename(tmp.Name(), s.path(server)); err != nil {
		return fmt.Errorf("cannot write the tool pins: %w", bare(err))
	}
	if d, err := os.Open(s.dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// lock takes the server's lock file, creating the directory first; in memory it does nothing.
// The returned function releases it.
func (s *Store) lock(server string) (func(), error) {
	if s.dir == "" {
		return func() {}, nil
	}
	if err := s.ensureDir(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(s.dir, server+".lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // the pins directory and a config server name, which is a safe file name
	if err != nil {
		return nil, fmt.Errorf("cannot open the tool pins lock: %w", bare(err))
	}
	deadline := time.Now().Add(lockWait)
	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if (!errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR)) || time.Now().After(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("cannot take the tool pins lock: %w", err)
		}
		time.Sleep(lockPoll)
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}

// ensureDir creates the pins directory, readable by the owner only.
func (s *Store) ensureDir() error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("cannot create the tool pins directory: %w", bare(err))
	}
	fi, err := os.Lstat(s.dir)
	if err != nil {
		return fmt.Errorf("cannot create the tool pins directory: %w", bare(err))
	}
	if !fi.IsDir() {
		return errors.New("the tool pins directory is not a directory")
	}
	if fi.Mode().Perm() != 0o700 {
		if err := os.Chmod(s.dir, 0o700); err != nil { //nolint:gosec // a directory needs its search bit; 0700 is owner only
			return fmt.Errorf("cannot restrict the tool pins directory to 0700: %w", bare(err))
		}
	}
	return nil
}

// bare drops the path from a file system error; the rest says what failed.
func bare(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// cloneFile returns a copy of f that shares no entry with it; definitions are not changed in
// place, so they are shared.
func cloneFile(f *File) *File {
	out := &File{Version: f.Version, Server: f.Server, Tools: make(map[string]*Entry, len(f.Tools))}
	for name, e := range f.Tools {
		c := *e
		if c.Accepted != nil {
			p := *c.Accepted
			c.Accepted = &p
		}
		if c.Pending != nil {
			p := *c.Pending
			c.Pending = &p
		}
		out.Tools[name] = &c
	}
	return out
}

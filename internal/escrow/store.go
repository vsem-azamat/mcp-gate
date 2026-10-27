package escrow

import (
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// entry is one kept secret: a text value or a file.
type entry struct {
	handle   string
	kind     string // the finding's kind, or "file"
	server   string
	tool     string
	source   map[string]any // read only once stored
	created  time.Time
	expires  time.Time
	value    []byte // a text secret
	dedupKey string
	file     *fileRef
	// batch is the replacer whose result the entry was kept for, or nil once another result
	// has used it too (see Replacer.Discard).
	batch *batch
}

// batch is the set of entries one replacer kept: the findings of one result. It is compared by
// address, so it must not be zero-sized: distinct pointers to zero-sized values may be equal.
type batch struct{ _ byte }

// fileRef is where a kept file is and what it held when it was scanned.
type fileRef struct {
	root, rel, name string
	size            int64
	hash            [sha256.Size]byte
	kinds           []string
}

// wipe overwrites a value before it is dropped, so that it does not linger in the heap longer
// than needed. Best effort: Go may have copied it.
func (e *entry) wipe() {
	clear(e.value)
	e.value = nil
}

// clock is the time source of a store and its limiter; tests replace now.
type clock struct {
	mu  sync.Mutex
	now func() time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now()
}

type store struct {
	*clock
	logger     *slog.Logger
	mu         sync.Mutex
	entries    map[string]*entry
	byDedup    map[string]string
	maxEntries int
	totalBytes int
	// stored counts the entries inserted under a new handle.
	stored atomic.Uint64
}

func newStore(maxEntries int, logger *slog.Logger) *store {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	return &store{
		clock: &clock{now: time.Now}, logger: logger,
		entries: map[string]*entry{}, byDedup: map[string]string{}, maxEntries: maxEntries,
	}
}

// removeLocked drops an entry. Callers hold s.mu.
func (s *store) removeLocked(e *entry) {
	delete(s.entries, e.handle)
	s.totalBytes -= len(e.value)
	if e.dedupKey != "" && s.byDedup[e.dedupKey] == e.handle {
		delete(s.byDedup, e.dedupKey)
	}
	e.wipe()
}

// sweepLocked drops expired entries. Callers hold s.mu.
func (s *store) sweepLocked(now time.Time) {
	for _, e := range s.entries {
		if !now.Before(e.expires) {
			s.removeLocked(e)
		}
	}
}

func (s *store) sweep() {
	now := s.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
}

// insert adds e under a fresh handle, to expire after ttl (DefaultTTL when 0). A text value
// already held from the same server under the same kind keeps its handle, which is then kept
// alive for a full ttl. When the store is full, expired entries are dropped first and then the
// oldest ones.
func (s *store) insert(e *entry, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	now := s.Now()
	expires := now.Add(ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.dedupKey != "" {
		if handle, ok := s.byDedup[e.dedupKey]; ok {
			if existing := s.entries[handle]; existing != nil && now.Before(existing.expires) {
				if expires.After(existing.expires) {
					existing.expires = expires
				}
				if existing.batch != e.batch {
					existing.batch = nil // another result shows this handle too
				}
				e.wipe()
				return handle, nil
			}
		}
	}
	if len(s.entries) >= s.maxEntries {
		s.sweepLocked(now)
	}
	for len(s.entries) > 0 && (len(s.entries) >= s.maxEntries || s.totalBytes+len(e.value) > MaxTotalBytes) {
		var oldest *entry
		for _, c := range s.entries {
			if oldest == nil || c.created.Before(oldest.created) {
				oldest = c
			}
		}
		s.logger.Warn("escrow full, evicting the oldest entry", "handle", oldest.handle, "maxEntries", s.maxEntries)
		s.removeLocked(oldest)
	}
	for range 5 {
		handle, err := newHandle()
		if err != nil {
			return "", err
		}
		if _, taken := s.entries[handle]; taken {
			continue
		}
		e.handle, e.created, e.expires = handle, now, expires
		s.entries[handle] = e
		s.totalBytes += len(e.value)
		s.stored.Add(1)
		if e.dedupKey != "" {
			s.byDedup[e.dedupKey] = handle
		}
		return handle, nil
	}
	return "", errors.New("could not allocate an escrow handle")
}

// len returns the number of entries held, expired ones not yet swept included.
func (s *store) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// get returns a copy of a live entry, with its own copy of the value.
func (s *store) get(handle string) (entry, bool) {
	now := s.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[handle]
	if !ok {
		return entry{}, false
	}
	if !now.Before(e.expires) {
		s.removeLocked(e)
		return entry{}, false
	}
	c := *e
	c.value = slices.Clone(e.value)
	return c, true
}

// remove drops an entry and reports whether it was live.
func (s *store) remove(handle string) bool {
	now := s.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[handle]
	if !ok {
		return false
	}
	live := now.Before(e.expires)
	s.removeLocked(e)
	return live
}

// discard drops the entries among handles that only b's result has used.
func (s *store) discard(b *batch, handles []string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, h := range handles {
		if e, ok := s.entries[h]; ok && e.batch == b {
			s.removeLocked(e)
			n++
		}
	}
	return n
}

// errFileChanged is returned when a kept file is not the file that was scanned any more.
var errFileChanged = errors.New("file changed since it was scanned")

// readFile returns the file's bytes if it is still the file that was scanned: a regular file
// under its root, reached without following a symlink, of the same size and SHA-256.
func readFile(f *fileRef) ([]byte, error) {
	root, err := os.OpenRoot(f.root)
	if err != nil {
		return nil, errors.New("file root cannot be opened")
	}
	defer func() { _ = root.Close() }()
	file, err := root.OpenFile(f.rel, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("file cannot be opened")
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != f.size {
		return nil, errFileChanged
	}
	content, err := io.ReadAll(io.LimitReader(file, f.size+1))
	if err != nil {
		return nil, errors.New("file cannot be read")
	}
	if sha256.Sum256(content) != f.hash {
		clear(content)
		return nil, errFileChanged
	}
	return content, nil
}

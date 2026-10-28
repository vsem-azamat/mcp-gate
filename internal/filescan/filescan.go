// Package filescan scans the files that download tools write, and withholds from the result
// any file that holds secrets.
//
// A server's file tools are the tools that save a file locally and report its path. After such
// a call, the paths its result or its arguments name are looked up. A file is considered only
// when it lies under one of the server's roots, so that neither a client (through arguments)
// nor a server (through its result) can make the gate read a file outside them. A path only the
// arguments name must also have changed during the call (allowing clockSlack before it), so that
// a client cannot have an older file read. A file with secrets is kept in the escrow when there is one and the file changed
// since the gate started, and every mention of it is replaced by a marker. A file that should be
// scanned but cannot be is a failure: the caller withholds the whole result.
package filescan

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/escrow"
	"github.com/vsem-azamat/mcp-gate/internal/redact"
)

// DefaultMaxBytes is the largest file scanned unless configured otherwise.
const DefaultMaxBytes = 20 << 20

const (
	// headBytes is how much of a file decides whether it is text.
	headBytes = 8192
	// scanSlots bounds concurrent scans, so that parallel downloads cannot pull many large
	// files into memory at once.
	scanSlots = 2
	// clockSlack allows for the coarse clock of inode change times against the fine clock of
	// time.Now: a file changed at or after a moment can have an inode change time earlier by up
	// to the filesystem's timestamp granularity (2 seconds on FAT) plus one tick of the kernel's
	// coarse clock. It is applied to the gate's start and to the forward time of a call.
	clockSlack = 3 * time.Second
	// maxCandidates bounds the paths one call may name; a result naming more is withheld.
	maxCandidates = 64
	openFlags     = os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
)

var slots = make(chan struct{}, scanSlots)

var (
	// secretExtensions mark files whose content is a credential store even when it is binary
	// or matches no rule.
	secretExtensions = []string{".p12", ".pfx", ".jks", ".keystore", ".kdbx", ".ppk"}
	// textNames are scanned as text whatever their content looks like.
	textNames = regexp.MustCompile(`(?i)(^\.env(\..*)?$|\.env$|\.(pem|key|json|ya?ml|toml|ini|conf|cfg|properties|txt|log|sh|xml|csv|md|tf|tfvars)$|^id_[a-z0-9_]+$|kubeconfig|credentials|secrets?)`)
)

// ErrUnscannable is wrapped by the error Scan returns for a file it should scan but cannot.
var ErrUnscannable = errors.New("a file the tool wrote could not be scanned for secrets, so the result is withheld")

// Options configure the Scanner of one server.
type Options struct {
	Server string
	// Tools are the server's file tools.
	Tools []string
	// Roots are the absolute directories files are scanned under.
	Roots []string
	// MaxBytes is the largest file scanned; 0 means DefaultMaxBytes.
	MaxBytes int64
	// TTL is how long a kept file stays retrievable; 0 is the escrow's default.
	TTL    time.Duration
	Engine *redact.Engine
	// Keep keeps a file with secrets and returns its handle; nil keeps nothing, and the marker
	// has no handle.
	Keep   func(escrow.File) (string, error)
	Logger *slog.Logger
	// Started is when the gate started; only a file changed after it is kept. Zero means when
	// New is called.
	Started time.Time
}

// Scanner scans the files of one server's file tools.
type Scanner struct {
	o       Options
	tools   map[string]bool
	started time.Time
}

// New returns a scanner.
func New(o Options) *Scanner {
	if o.MaxBytes <= 0 {
		o.MaxBytes = DefaultMaxBytes
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	s := &Scanner{o: o, tools: map[string]bool{}, started: o.Started}
	if s.started.IsZero() {
		s.started = time.Now()
	}
	for _, t := range o.Tools {
		s.tools[t] = true
	}
	return s
}

// Scan checks the files a call of tool wrote, given its arguments (which may be nil), the result
// the server returned (downstream), the result redaction made of it with rep (redacted), and the
// time the call was forwarded. The paths are looked for in downstream and its arguments, since
// redaction can turn part of a path into a marker. It returns redacted with every file that
// holds secrets withheld, and how many were. An error wrapping ErrUnscannable means a file could
// not be scanned; the result must then be withheld as a whole. Neither result is modified, and
// no file is kept unless every file was scanned.
func (s *Scanner) Scan(ctx context.Context, tool string, args func() map[string]any, downstream, redacted *mcp.CallToolResult, start time.Time, rep redact.Replacer) (out *mcp.CallToolResult, withheld int, err error) {
	if downstream == nil || redacted == nil || downstream.IsError || !s.tools[tool] {
		return redacted, 0, nil
	}
	if len(downstream.Content) != len(redacted.Content) {
		// Mentions are matched block for block; without that, one could stay visible.
		s.o.Logger.Warn("file not scanned; withholding the result", "tool", tool, "reason", "the redacted result has other content blocks")
		return nil, 0, fmt.Errorf("%w (the redacted result does not match the server's)", ErrUnscannable)
	}
	defer func() {
		if v := recover(); v != nil {
			s.o.Logger.Error("file scan panicked", "tool", tool, "type", fmt.Sprintf("%T", v))
			out, withheld, err = nil, 0, fmt.Errorf("%w (internal error)", ErrUnscannable)
		}
	}()
	var arguments map[string]any
	if args != nil {
		arguments = args()
	}
	roots := s.rootForms()
	cands, overflow := candidates(arguments, downstream, func(path string) bool {
		return underAny(path, roots) && regularFile(path)
	})
	if overflow {
		s.o.Logger.Warn("file not scanned; withholding the result", "tool", tool, "reason", "too many paths")
		return nil, 0, fmt.Errorf("%w (the call names too many paths)", ErrUnscannable)
	}
	type hit struct {
		c     candidate
		f     *opened
		kinds []string
	}
	var hits []hit
	for _, c := range cands {
		// A path only the caller named must have changed after the call was forwarded, less the
		// clock slack, or a client could have any file under a root read. Without the slack a file
		// the tool wrote just after the forward could look older and pass unscanned. One
		// the result names may be older, since a tool that caches its downloads reports the same
		// file again (also across a restart of the gate), so it is scanned whatever its age.
		var since time.Time
		if c.fromArguments {
			since = start.Add(-clockSlack)
		}
		f, err := s.open(c.path, since)
		if err != nil {
			s.o.Logger.Warn("file not scanned; withholding the result", "tool", tool, "reason", err.Error())
			return nil, 0, fmt.Errorf("%w (%s)", ErrUnscannable, err.Error())
		}
		if f == nil {
			continue
		}
		kinds, err := s.scan(ctx, f)
		_ = f.file.Close()
		if err != nil {
			s.o.Logger.Warn("file not scanned; withholding the result", "tool", tool, "size", f.size, "reason", err.Error())
			return nil, 0, fmt.Errorf("%w (%s)", ErrUnscannable, err.Error())
		}
		if len(kinds) > 0 {
			hits = append(hits, hit{c, f, kinds})
		}
	}
	if len(hits) == 0 {
		return redacted, 0, nil
	}
	if rep == nil {
		rep = redact.Marker{}
	}
	files := make([]mention, 0, len(hits))
	for _, h := range hits {
		c, f := h.c, h.f
		marker := redact.MarkerText("file")
		release := ""
		// Only a file changed since the gate started is kept: an older one is withheld all the
		// same, but a server cannot pull any old file under a root into the escrow.
		if s.o.Keep != nil && !f.changed.Before(s.started.Add(-clockSlack)) {
			handle, err := s.o.Keep(escrow.File{
				Source: escrow.Source{Server: s.o.Server, Tool: tool, TTL: s.o.TTL, Arguments: func() map[string]any { return arguments }},
				Root:   f.root, Rel: f.rel, Name: f.name, Size: f.size, Hash: f.hash, Kinds: h.kinds,
			})
			if err == nil {
				marker = escrow.Marker("file", handle)
				release = "; the owner can release it"
			}
		}
		name := s.o.Engine.RedactText(f.name, redact.Marker{})
		notice := fmt.Sprintf("%s file_name=%s size=%d bytes; contains: %s. The file is withheld from this conversation%s.",
			marker, name, f.size, strings.Join(h.kinds, ", "), release)
		files = append(files, mention{paths: s.forms([]string{c.path, f.resolved, c.raw}, rep), blocks: c.blocks, marker: marker, notice: notice})
		s.o.Logger.Info("downloaded file withheld", "tool", tool, "kinds", h.kinds, "size", f.size)
	}
	return withhold(downstream, redacted, files), len(hits), nil
}

// issuer is a replacer that can tell the markers it issued without keeping anything new; see
// escrow.Replacer.Issued.
type issuer interface{ Issued() redact.Replacer }

// forms returns paths and, where redaction changes them, their redacted forms: what a mention
// of each looks like in the redacted result. rep is the call's replacer, so a finding gets the
// marker it got there; a replacer that keeps findings is asked only for the markers it issued,
// so that redacting a path keeps nothing the result did not show.
func (s *Scanner) forms(paths []string, rep redact.Replacer) []string {
	if is, ok := rep.(issuer); ok {
		rep = is.Issued()
	}
	out := slices.Clone(paths)
	for _, p := range paths {
		if r := s.o.Engine.RedactText(p, rep); r != p {
			out = append(out, r)
		}
	}
	return out
}

// opened is a file to scan, opened under its root.
type opened struct {
	file      *os.File
	resolved  string // the path with symlinks resolved; never logged
	root, rel string
	name      string
	size      int64
	hash      [sha256.Size]byte
	changed   time.Time // the inode change time
}

// open opens path when it is a candidate: under one of the roots, a regular file with one link,
// whose inode changed at or after since (at any time when since is zero). It returns nil when path is not a candidate, and an
// error when it is one but cannot be opened or checked. The file is opened through its root, so
// no symlink can lead outside it, and every check runs on the opened file.
func (s *Scanner) open(path string, since time.Time) (*opened, error) {
	resolved, err := filepath.EvalSymlinks(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil // a path that does not resolve names no file the tool wrote
	case err != nil && s.lexicallyUnderRoot(path):
		return nil, errors.New("the file cannot be resolved")
	case err != nil:
		return nil, nil
	}
	var root, rel string
	for _, r := range s.o.Roots {
		rr, err := filepath.EvalSymlinks(r)
		if err != nil {
			continue
		}
		if x, err := filepath.Rel(rr, resolved); err == nil && x != "." && x != ".." && !strings.HasPrefix(x, ".."+string(filepath.Separator)) {
			root, rel = rr, x
			break
		}
	}
	if root == "" {
		s.o.Logger.Warn("a file a download tool named is outside the file roots; not scanned")
		return nil, nil
	}
	dir, err := os.OpenRoot(root)
	if err != nil {
		return nil, errors.New("the file root cannot be opened")
	}
	defer func() { _ = dir.Close() }()
	f, err := dir.OpenFile(rel, openFlags, 0)
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ELOOP):
		return nil, nil // removed or replaced by a symlink since it was resolved
	case err != nil:
		return nil, errors.New("the file cannot be opened")
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, errors.New("the file cannot be checked")
	}
	links, changed, ok := inode(info)
	switch {
	case !ok:
		_ = f.Close()
		return nil, errors.New("the file cannot be checked")
	case !info.Mode().IsRegular() || links != 1:
		_ = f.Close()
		return nil, nil
	case changed.Before(since):
		_ = f.Close()
		s.o.Logger.Warn("a file a download tool named predates the call; not scanned")
		return nil, nil
	}
	return &opened{file: f, resolved: resolved, root: root, rel: rel, name: filepath.Base(resolved), size: info.Size(), changed: changed}, nil
}

// regularFile reports whether path names a regular file, following symlinks.
func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// lexicallyUnderRoot reports whether path, as written, lies under one of the roots, as written
// or with their symlinks resolved.
func (s *Scanner) lexicallyUnderRoot(path string) bool { return underAny(path, s.rootForms()) }

// rootForms returns the roots as written and, where it differs, with their symlinks resolved.
func (s *Scanner) rootForms() []string {
	forms := make([]string, 0, 2*len(s.o.Roots))
	for _, r := range s.o.Roots {
		forms = append(forms, r)
		if rr, err := filepath.EvalSymlinks(r); err == nil && rr != r {
			forms = append(forms, rr)
		}
	}
	return forms
}

// underAny reports whether path, as written, lies strictly under one of roots.
func underAny(path string, roots []string) bool {
	for _, r := range roots {
		x, err := filepath.Rel(r, path)
		if err == nil && x != "." && x != ".." && !strings.HasPrefix(x, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// MissingRoots returns the roots that do not resolve to a directory now.
func (s *Scanner) MissingRoots() []string {
	var missing []string
	for _, r := range s.o.Roots {
		if info, err := os.Stat(r); err != nil || !info.IsDir() {
			missing = append(missing, r)
		}
	}
	return missing
}

// scan returns the kinds of secret in an opened file, and none for a binary file. It fails for a
// file that is text, or named as text or as a credential store, but too large, not UTF-8, or
// changed while it was read.
func (s *Scanner) scan(ctx context.Context, f *opened) ([]string, error) {
	lower := strings.ToLower(f.name)
	secretFile := slices.ContainsFunc(secretExtensions, func(ext string) bool { return strings.HasSuffix(lower, ext) })
	textName := textNames.MatchString(f.name)
	if f.size > s.o.MaxBytes {
		head := make([]byte, headBytes)
		n, err := io.ReadFull(f.file, head)
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, errors.New("the file cannot be read")
		}
		if secretFile || textName || looksLikeText(head[:n]) {
			return nil, fmt.Errorf("the file is larger than %d bytes", s.o.MaxBytes)
		}
		return nil, nil // binary
	}
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	case <-ctx.Done():
		return nil, errors.New("the call ended before the file was scanned")
	}
	content, err := io.ReadAll(io.LimitReader(f.file, s.o.MaxBytes+1))
	if err != nil {
		return nil, errors.New("the file cannot be read")
	}
	defer clear(content)
	if int64(len(content)) != f.size {
		return nil, errors.New("the file changed while it was read")
	}
	f.hash = sha256.Sum256(content)
	if secretFile {
		return []string{"secret_file"}, nil
	}
	if !textName && !looksLikeText(content) {
		return nil, nil // binary
	}
	if !utf8.Valid(content) {
		return nil, errors.New("the file is text but not valid UTF-8")
	}
	var mu sync.Mutex
	found := map[string]bool{}
	s.o.Engine.RedactString(string(content), redact.ReplacerFunc(func(fd redact.Finding) string {
		mu.Lock()
		found[fd.Kind] = true
		mu.Unlock()
		return ""
	}))
	kinds := make([]string, 0, len(found))
	for k := range found {
		kinds = append(kinds, k)
	}
	slices.Sort(kinds)
	return kinds, nil
}

// looksLikeText reports whether the first headBytes of content hold no NUL and are UTF-8,
// allowing a character cut at the end.
func looksLikeText(content []byte) bool {
	head := content[:min(len(content), headBytes)]
	if slices.Contains(head, 0) {
		return false
	}
	for i := 0; i < 4 && len(head) > 0 && !utf8.Valid(head); i++ {
		head = head[:len(head)-1]
	}
	return utf8.Valid(head)
}

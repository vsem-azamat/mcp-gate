// Package escrow keeps redacted secrets in memory under random handles, so that the owner can
// release them through an authenticated HTTP API (/_escrow/) without the values ever entering a
// client's context. Values live only in this process: never on disk, never in logs.
//
// The HTTP API is a frozen contract: paths, methods, the auth scheme, response fields, status
// codes and bodies are those of the mcp-proxy fork it replaces, so that its consumers need no
// change. The one addition is a limit on failed authentication per client address.
package escrow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"log/slog"
	"net/http"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vsem-azamat/mcp-gate/internal/redact"
)

// The contract and its limits.
const (
	// Route is the path prefix of the API.
	Route = "/_escrow/"

	// DefaultTTL is how long an entry stays retrievable unless configured otherwise.
	DefaultTTL = 24 * time.Hour
	// DefaultMaxEntries caps the store unless configured otherwise; the oldest entry is evicted.
	DefaultMaxEntries = 1000
	// MaxValueBytes bounds one text value. A larger finding is still redacted, without a handle.
	MaxValueBytes = 64 << 10
	// MaxTotalBytes bounds the text values held at once; the oldest entries are evicted beyond it.
	MaxTotalBytes = 16 << 20
	// sweepInterval is how often expired entries are dropped.
	sweepInterval = time.Minute
)

// handleEncoding is lower-case RFC 4648 base32 without padding.
var handleEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// HandleRE is the form of a handle: "k" and ten base32 characters (50 random bits).
var HandleRE = regexp.MustCompile(`^k[a-z2-7]{10}$`)

// Marker is the text that replaces a finding kept under handle: "[REDACTED:<kind> #<handle>]".
func Marker(kind, handle string) string {
	return "[REDACTED:" + kind + " #" + handle + "]"
}

func newHandle() (string, error) {
	var raw [7]byte // 56 bits; 10 base32 characters use 50 of them
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "k" + handleEncoding.EncodeToString(raw[:])[:10], nil
}

// Options configure an Escrow.
type Options struct {
	// KeyHash is the SHA-256 of the API key.
	KeyHash [sha256.Size]byte
	// MaxEntries caps the store; 0 means DefaultMaxEntries.
	MaxEntries int
	// SourceArguments are the request arguments kept in an entry's source summary; nil means
	// DefaultSourceArguments and an empty list keeps none.
	SourceArguments []string
	// AllowUIDs are the user IDs of escrow socket peers served without a key (see ConnContext).
	// Requests that did not come through the socket always need the key.
	AllowUIDs []int
	// Remote returns a request's client address, which the failed-auth limit is keyed by and
	// the access log names. Nil uses the peer address.
	Remote func(*http.Request) string
	Logger *slog.Logger
}

// Escrow is the store and its API.
type Escrow struct {
	store   *store
	keyHash [sha256.Size]byte
	sources map[string]bool // the arguments kept in a summary
	allowed map[int]bool    // socket peers served without a key
	remote  func(*http.Request) string
	limit   *limiter
	logger  *slog.Logger
	// authFailures counts the requests answered with 401.
	authFailures atomic.Uint64
}

// Stats are the escrow's counts.
type Stats struct {
	// Entries is the number of entries held.
	Entries int
	// Stored counts the entries stored under a new handle since the start.
	Stored uint64
	// AuthFailures counts the API requests answered with 401 since the start.
	AuthFailures uint64
}

// Stats returns the escrow's counts.
func (e *Escrow) Stats() Stats {
	return Stats{Entries: e.store.len(), Stored: e.store.stored.Load(), AuthFailures: e.authFailures.Load()}
}

// New returns an escrow. Run drops expired entries while it runs.
func New(o Options) *Escrow {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Remote == nil {
		o.Remote = peer
	}
	if o.SourceArguments == nil {
		o.SourceArguments = DefaultSourceArguments
	}
	sources := make(map[string]bool, len(o.SourceArguments))
	for _, name := range o.SourceArguments {
		sources[name] = true
	}
	allowed := make(map[int]bool, len(o.AllowUIDs))
	for _, uid := range o.AllowUIDs {
		allowed[uid] = true
	}
	s := newStore(o.MaxEntries, o.Logger)
	return &Escrow{
		store: s, keyHash: o.KeyHash, sources: sources, allowed: allowed, remote: o.Remote,
		limit: newLimiter(s.clock), logger: o.Logger,
	}
}

// MaxEntries returns the store's cap.
func (e *Escrow) MaxEntries() int { return e.store.maxEntries }

// Run drops expired entries every minute until ctx ends.
func (e *Escrow) Run(ctx context.Context) {
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.store.sweep()
		}
	}
}

// Source is the request a finding or a file came from.
type Source struct {
	Server string
	// Tool is the tool or prompt name, or the resource URI.
	Tool string
	// TTL is how long entries from it stay retrievable; 0 means DefaultTTL.
	TTL time.Duration
	// Arguments returns the request's arguments, or nil; only the members named by
	// Options.SourceArguments are kept (see summarize). It is called at most once per Replacer.
	Arguments func() map[string]any
}

// Replacer returns a replacer that keeps each finding from src and writes its marker. A
// finding over MaxValueBytes, or one the store cannot take, gets the plain redact marker. One
// replacer serves one result; Discard drops what it kept when that result is withheld.
func (e *Escrow) Replacer(src Source) *Replacer {
	summary := sync.OnceValue(func() map[string]any {
		if src.Arguments == nil {
			return map[string]any{}
		}
		return e.summarize(src.Arguments())
	})
	return &Replacer{e: e, src: src, summary: summary, batch: &batch{}}
}

// Replacer keeps the findings of one result in the escrow; see Escrow.Replacer.
type Replacer struct {
	e       *Escrow
	src     Source
	summary func() map[string]any
	batch   *batch

	mu      sync.Mutex
	handles []string          // the handles it returned, each once
	issued  map[string]string // the marker it returned, by issuedKey
}

// issuedKey is the key of a finding in Replacer.issued: its kind and the SHA-256 of its value,
// so that the memo holds no second copy of the value.
func issuedKey(kind string, sum [sha256.Size]byte) string { return kind + "\x00" + string(sum[:]) }

// Replace implements redact.Replacer. A value it has replaced before gets the same marker
// again, without a second insert.
func (r *Replacer) Replace(f redact.Finding) string {
	sum := sha256.Sum256([]byte(f.Value))
	key := issuedKey(f.Kind, sum)
	r.mu.Lock()
	marker, seen := r.issued[key]
	r.mu.Unlock()
	if seen {
		return marker
	}
	marker, handle := r.keep(f, sum)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.issued == nil {
		r.issued = map[string]string{}
	}
	if _, seen := r.issued[key]; !seen && handle != "" {
		r.handles = append(r.handles, handle)
	}
	r.issued[key] = marker
	return marker
}

// keep inserts a finding and returns its marker, and its handle when it was kept.
func (r *Replacer) keep(f redact.Finding, sum [sha256.Size]byte) (marker, handle string) {
	if len(f.Value) > MaxValueBytes {
		return redact.MarkerText(f.Kind), ""
	}
	handle, err := r.e.store.insert(&entry{
		kind: f.Kind, server: r.src.Server, tool: r.src.Tool, source: r.summary(),
		value:    []byte(f.Value),
		dedupKey: r.src.Server + "\x00" + f.Kind + "\x00" + hex.EncodeToString(sum[:]),
		batch:    r.batch,
	}, r.src.TTL)
	if err != nil {
		r.e.logger.Error("escrow insert failed", "error", err.Error())
		return redact.MarkerText(f.Kind), ""
	}
	// The tool is not logged: for a resource read it is the client's URI, which the audit
	// line logs redacted.
	r.e.logger.Info("escrowed secret", "handle", handle, "type", f.Kind, "server", r.src.Server)
	return Marker(f.Kind, handle), handle
}

// Issued returns a replacer that only looks up: a finding this replacer has replaced gets the
// same marker, and any other finding is left as it is. It keeps nothing, so it can redact a text
// that is not part of the result, to see how the result wrote it.
func (r *Replacer) Issued() redact.Replacer {
	return redact.ReplacerFunc(func(f redact.Finding) string {
		r.mu.Lock()
		defer r.mu.Unlock()
		if marker, ok := r.issued[issuedKey(f.Kind, sha256.Sum256([]byte(f.Value)))]; ok {
			return marker
		}
		return f.Value
	})
}

// Discard drops the entries this replacer kept that no other result has used since, because
// the result it replaced findings in was withheld and its markers never reached a client. An
// entry that already held the value before, or that another result's marker carries too, stays.
func (r *Replacer) Discard() {
	r.mu.Lock()
	handles := r.handles
	r.handles, r.issued = nil, nil
	r.mu.Unlock()
	if n := r.e.store.discard(r.batch, handles); n > 0 {
		r.e.logger.Info("dropped the escrowed secrets of a withheld result", "entries", n, "server", r.src.Server)
	}
}

// File is a scanned file that holds secrets. The API serves it only while it is still the file
// that was scanned.
type File struct {
	Source
	// Root is the resolved directory the file was opened under, and Rel its path below it.
	Root, Rel string
	// Name is the file's base name.
	Name string
	Size int64
	Hash [sha256.Size]byte
	// Kinds are the kinds of secret found in it.
	Kinds []string
}

// KeepFile keeps f and returns its handle.
func (e *Escrow) KeepFile(f File) (string, error) {
	var summary map[string]any
	if f.Arguments != nil {
		summary = e.summarize(f.Arguments())
	}
	handle, err := e.store.insert(&entry{
		kind: "file", server: f.Server, tool: f.Tool, source: summary,
		file: &fileRef{root: f.Root, rel: f.Rel, name: f.Name, size: f.Size, hash: f.Hash, kinds: f.Kinds},
	}, f.TTL)
	if err != nil {
		e.logger.Error("escrow insert failed", "error", err.Error())
		return "", err
	}
	e.logger.Info("escrowed file", "handle", handle, "server", f.Server, "tool", f.Tool, "kinds", f.Kinds, "size", f.Size)
	return handle, nil
}

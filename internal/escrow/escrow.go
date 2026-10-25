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
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/vsem-azamat/mcp-gate/internal/redact"
)

// The contract and its limits.
const (
	// KeyHashEnv names the environment variable that holds the hex SHA-256 of the API key. The
	// key itself never reaches the gate; without the variable the escrow is off.
	KeyHashEnv = "MCP_HUB_ESCROW_KEY_SHA256"
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

// ParseKeyHash decodes the value of KeyHashEnv: 64 hex digits in either case, surrounding space
// ignored. The error never quotes the value.
func ParseKeyHash(s string) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	decoded, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(s)))
	if err != nil || len(decoded) != sha256.Size {
		return out, errors.New(KeyHashEnv + " is not a hex SHA-256")
	}
	copy(out[:], decoded)
	return out, nil
}

// Options configure an Escrow.
type Options struct {
	// KeyHash is the SHA-256 of the API key.
	KeyHash [sha256.Size]byte
	// MaxEntries caps the store; 0 means DefaultMaxEntries.
	MaxEntries int
	// Remote returns a request's client address, which the failed-auth limit is keyed by and
	// the access log names. Nil uses the peer address.
	Remote func(*http.Request) string
	Logger *slog.Logger
}

// Escrow is the store and its API.
type Escrow struct {
	store   *store
	keyHash [sha256.Size]byte
	remote  func(*http.Request) string
	limit   *limiter
	logger  *slog.Logger
}

// New returns an escrow. Run drops expired entries while it runs.
func New(o Options) *Escrow {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Remote == nil {
		o.Remote = peer
	}
	s := newStore(o.MaxEntries, o.Logger)
	return &Escrow{store: s, keyHash: o.KeyHash, remote: o.Remote, limit: newLimiter(s.clock), logger: o.Logger}
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
	// Arguments returns the request's arguments, or nil; only identifying members are kept
	// (see Summarize). It is called at most once per Replacer.
	Arguments func() map[string]any
}

// Replacer returns a replacer that keeps each finding from src and writes its marker. A
// finding over MaxValueBytes, or one the store cannot take, gets the plain redact marker.
func (e *Escrow) Replacer(src Source) redact.Replacer {
	summary := sync.OnceValue(func() map[string]any {
		if src.Arguments == nil {
			return map[string]any{}
		}
		return Summarize(src.Arguments())
	})
	return redact.ReplacerFunc(func(f redact.Finding) string {
		if len(f.Value) > MaxValueBytes {
			return redact.MarkerText(f.Kind)
		}
		sum := sha256.Sum256([]byte(f.Value))
		handle, err := e.store.insert(&entry{
			kind: f.Kind, server: src.Server, tool: src.Tool, source: summary(),
			value:    []byte(f.Value),
			dedupKey: src.Server + "\x00" + f.Kind + "\x00" + hex.EncodeToString(sum[:]),
		}, src.TTL)
		if err != nil {
			e.logger.Error("escrow insert failed", "error", err.Error())
			return redact.MarkerText(f.Kind)
		}
		// The tool is not logged: for a resource read it is the client's URI, which the audit
		// line logs redacted.
		e.logger.Info("escrowed secret", "handle", handle, "type", f.Kind, "server", src.Server)
		return Marker(f.Kind, handle)
	})
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
		summary = Summarize(f.Arguments())
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

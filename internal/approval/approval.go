// Package approval holds tool calls for the owner's approval: the rules that say which calls
// wait, the in-memory store of pending approvals, the webhook that announces them, and the HTTP
// endpoints that decide them. Nothing of it is kept across a restart.
package approval

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/vsem-azamat/mcp-gate/internal/audit"
	"github.com/vsem-azamat/mcp-gate/internal/config"
)

// Approvers that are not an admin token.
const (
	// ByLink decided through a one-time link of a notice.
	ByLink = "link"
	// ByGate is the gate itself: a reload, the shutdown, or too many calls waiting.
	ByGate = "gate"
)

// Bounds of the store.
const (
	// MaxPending is how many calls may wait at a time, and MaxPendingPerPrincipal how many of
	// them one token's (or the calls without a token).
	MaxPending             = 64
	MaxPendingPerPrincipal = 16
	// maxNotifiers is how many notices are sent at a time; the others queue, at most
	// MaxPending, and a notice that finds the queue full is dropped.
	maxNotifiers = 4
)

// ProgressInterval is how often a waiting call that carries a progress token is told it waits.
// A variable for tests.
var ProgressInterval = 10 * time.Second

// Patterns are tool name patterns: a name, or a prefix ending in "*".
type Patterns []string

// Match reports whether a pattern matches the tool name.
func (p Patterns) Match(tool string) bool {
	return slices.ContainsFunc(p, func(pat string) bool {
		if prefix, ok := strings.CutSuffix(pat, "*"); ok {
			return strings.HasPrefix(tool, prefix)
		}
		return pat == tool
	})
}

// Rules say which tool calls of one server wait for approval: the server's patterns, and those
// each token's policy adds. They do not change once made.
type Rules struct {
	server Patterns
	tokens map[string]Patterns
}

// NewRules returns the rules cfg sets on server; nil when it sets none.
func NewRules(cfg *config.Config, server string) *Rules {
	r := &Rules{tokens: map[string]Patterns{}}
	if s := cfg.Servers[server]; s != nil {
		r.server = s.Approve
	}
	for token := range cfg.Policies {
		if p := cfg.ServerPolicy(token, server); p != nil && len(p.Approve) > 0 {
			r.tokens[token] = p.Approve
		}
	}
	if len(r.server) == 0 && len(r.tokens) == 0 {
		return nil
	}
	return r
}

// Holds reports whether a call of tool by the token named principal waits for approval; false on
// nil rules.
func (r *Rules) Holds(principal, tool string) bool {
	if r == nil {
		return false
	}
	return r.server.Match(tool) || (principal != "" && r.tokens[principal].Match(tool))
}

// Unmatched returns the exact patterns (not ending in *) of the server's list and of every
// token's that name no tool in listed, sorted and once each: a misspelt pattern holds nothing.
func (r *Rules) Unmatched(listed map[string]bool) []string {
	if r == nil {
		return nil
	}
	var out []string
	check := func(p Patterns) {
		for _, pat := range p {
			if !strings.HasSuffix(pat, "*") && !listed[pat] && !slices.Contains(out, pat) {
				out = append(out, pat)
			}
		}
	}
	check(r.server)
	for _, p := range r.tokens {
		check(p)
	}
	slices.Sort(out)
	return out
}

// Question is a held call as the owner is shown it.
type Question struct {
	Server, Tool, Principal string
	// Arguments are the call's arguments as JSON text, redacted, with long values cut; Size is
	// the length of the arguments forwarded, and Truncated reports a value that was cut.
	Arguments string
	Size      int
	Truncated bool
}

// Settings say how a call is asked about: how long it waits, and who is told.
type Settings struct {
	Timeout time.Duration
	// Notifier, if set, announces the pending approval.
	Notifier Notifier
	// LinkURL, if set, is the gate's base URL for the one-time links of the notice.
	LinkURL string
}

// Decision is what came of a held call, and who decided it.
type Decision struct {
	Approval audit.Approval
	By       string
}

// Pending is a pending approval as the admin endpoint lists it and the notice sends it.
type Pending struct {
	ID        string    `json:"id"`
	Server    string    `json:"server"`
	Tool      string    `json:"tool"`
	Principal string    `json:"principal"`
	Arguments string    `json:"arguments"`
	Size      int       `json:"size"`
	Truncated bool      `json:"truncated"`
	Created   time.Time `json:"created"`
	Expires   time.Time `json:"expires"`
}

type entry struct {
	Pending
	link [sha256.Size]byte // digest of the link token; zero without links
	done chan Decision     // receives the one decision
}

// Store holds the pending approvals.
type Store struct {
	logger *slog.Logger
	// ctx ends with Close; the notices in flight are cancelled with it.
	ctx    context.Context
	cancel context.CancelFunc
	// notices queues the notices to send; Dropped counts those that found it full.
	notices chan notice
	dropped atomic.Int64

	mu      sync.Mutex
	pending map[string]*entry
	links   map[[sha256.Size]byte]*entry
	byWho   map[string]int // pending approvals by principal
	closed  bool
	senders int // goroutines sending notices
}

// notice is a notice waiting to be sent.
type notice struct {
	e  *entry
	n  Notice
	to Notifier
}

// NewStore returns an empty store.
func NewStore(logger *slog.Logger) *Store {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Store{
		logger: logger, ctx: ctx, cancel: cancel, notices: make(chan notice, MaxPending),
		pending: map[string]*entry{}, links: map[[sha256.Size]byte]*entry{}, byWho: map[string]int{},
	}
}

// Dropped counts the notices dropped because too many were waiting to be sent.
func (st *Store) Dropped() int64 { return st.dropped.Load() }

// notify queues a notice, and starts a sender when fewer than maxNotifiers run. The senders
// skip a notice whose approval is no longer pending, and end when the queue is empty.
func (st *Store) notify(e *entry, n Notice, to Notifier) {
	select {
	case st.notices <- notice{e: e, n: n, to: to}:
	default:
		st.dropped.Add(1)
		st.logger.Warn("too many approval notices waiting to be sent; this one is dropped", "server", e.Server, "tool", e.Tool, "id", e.ID)
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.senders < maxNotifiers {
		st.senders++
		go st.send()
	}
}

func (st *Store) send() {
	for {
		select {
		case j := <-st.notices:
			if st.isPending(j.e) && st.ctx.Err() == nil {
				j.to.Notify(st.ctx, j.n)
			}
			continue
		default:
		}
		st.mu.Lock()
		if len(st.notices) == 0 {
			st.senders--
			st.mu.Unlock()
			return
		}
		st.mu.Unlock()
	}
}

// isPending reports whether e still waits for a decision.
func (st *Store) isPending(e *entry) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.pending[e.ID] == e
}

// Ask holds a call until it is decided, it expires after s.Timeout, or ctx is done, and returns
// what came of it. waiting, if set, is called every ProgressInterval while the call waits, with
// the approval's identifier and how many times it was called before, plus one.
func (st *Store) Ask(ctx context.Context, q Question, s Settings, waiting func(id string, n int)) Decision {
	e, token := st.add(q, s.Timeout, s.LinkURL != "")
	if e == nil {
		return Decision{Approval: audit.ApprovalDenied, By: ByGate}
	}
	if s.Notifier != nil {
		n := Notice{Pending: e.Pending}
		if token != "" {
			base := strings.TrimSuffix(s.LinkURL, "/") + LinkRoute
			n.ApproveURL, n.DenyURL, n.LinkToken = base+"approve", base+"deny", token
		}
		st.notify(e, n, s.Notifier)
	}
	timer := time.NewTimer(s.Timeout)
	defer timer.Stop()
	tick := time.NewTicker(ProgressInterval)
	defer tick.Stop()
	for n := 1; ; {
		select {
		case d := <-e.done:
			return d
		case <-timer.C:
			if d, ok := st.end(e, Decision{Approval: audit.ApprovalExpired}); ok {
				return d
			}
		case <-ctx.Done():
			if d, ok := st.end(e, Decision{Approval: audit.ApprovalCancelled}); ok {
				return d
			}
		case <-tick.C:
			if waiting != nil {
				waiting(e.ID, n)
			}
			n++
		}
	}
}

// add records a pending approval, with a link token when links is set; nil when the store is
// closed or full.
func (st *Store) add(q Question, timeout time.Duration, links bool) (*entry, string) {
	now := time.Now().UTC()
	e := &entry{
		Pending: Pending{
			ID: randomHex(8), Server: q.Server, Tool: q.Tool, Principal: q.Principal, Arguments: q.Arguments,
			Size: q.Size, Truncated: q.Truncated, Created: now, Expires: now.Add(timeout),
		},
		done: make(chan Decision, 1),
	}
	var token string
	if links {
		b := make([]byte, 32)
		_, _ = rand.Read(b) // never fails
		token = base64.RawURLEncoding.EncodeToString(b)
		e.link = sha256.Sum256([]byte(token))
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.closed {
		return nil, ""
	}
	if len(st.pending) >= MaxPending {
		st.logger.Warn("too many calls wait for approval; denied", "server", q.Server, "tool", q.Tool, "principal", q.Principal, "max", MaxPending)
		return nil, ""
	}
	if st.byWho[q.Principal] >= MaxPendingPerPrincipal {
		st.logger.Warn("too many calls of one token wait for approval; denied", "server", q.Server, "tool", q.Tool, "principal", q.Principal, "max", MaxPendingPerPrincipal)
		return nil, ""
	}
	st.byWho[q.Principal]++
	for st.pending[e.ID] != nil {
		e.ID = randomHex(8)
	}
	st.pending[e.ID] = e
	if links {
		st.links[e.link] = e
	}
	return e, token
}

// end ends a call that its waiter gives up on with d, unless it was decided first: then ok is
// false, and the decision is on e.done.
func (st *Store) end(e *entry, d Decision) (_ Decision, ok bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.pending[e.ID] != e {
		return Decision{}, false
	}
	st.remove(e)
	return d, true
}

// remove drops e from the maps; the caller holds mu.
func (st *Store) remove(e *entry) {
	delete(st.pending, e.ID)
	if st.byWho[e.Principal]--; st.byWho[e.Principal] <= 0 {
		delete(st.byWho, e.Principal)
	}
	if e.link != ([sha256.Size]byte{}) {
		delete(st.links, e.link)
	}
}

// decide gives e the decision, once; the caller holds mu.
func (st *Store) decide(e *entry, approve bool, by string) audit.Approval {
	st.remove(e)
	a := audit.ApprovalDenied
	if approve {
		a = audit.Approved
	}
	e.done <- Decision{Approval: a, By: by}
	return a
}

// Decide approves or denies the pending approval with the identifier id, by the admin token
// named by; ok is false when none has that identifier.
func (st *Store) Decide(id string, approve bool, by string) (_ audit.Approval, ok bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	e := st.pending[id]
	if e == nil {
		return "", false
	}
	return st.decide(e, approve, by), true
}

// DecideLink approves or denies the pending approval whose link token is token; ok is false
// when none has it.
func (st *Store) DecideLink(token string, approve bool) (id string, _ audit.Approval, ok bool) {
	if token == "" {
		return "", "", false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	e := st.links[sha256.Sum256([]byte(token))]
	if e == nil {
		return "", "", false
	}
	return e.ID, st.decide(e, approve, ByLink), true
}

// List returns the pending approvals, oldest first.
func (st *Store) List() []Pending {
	st.mu.Lock()
	out := make([]Pending, 0, len(st.pending))
	for _, e := range st.pending {
		out = append(out, e.Pending)
	}
	st.mu.Unlock()
	slices.SortFunc(out, func(a, b Pending) int {
		if c := a.Created.Compare(b.Created); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

// DenyAll denies every pending approval, by the gate; a reload calls it.
func (st *Store) DenyAll() {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, e := range st.pending {
		st.decide(e, false, ByGate)
	}
}

// Close denies every pending approval and every call held from then on, by the gate; the
// shutdown calls it.
func (st *Store) Close() {
	st.mu.Lock()
	st.closed = true
	st.mu.Unlock()
	st.DenyAll()
	st.cancel()
}

// Printable returns s with every rune that is not printable, or is a format character such as
// a bidirectional override, written as \uXXXX (\UXXXXXXXX above the BMP), so that a terminal
// or a chat client shows the text as it is.
func Printable(s string) string {
	if !strings.ContainsFunc(s, unsafeRune) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case !unsafeRune(r):
			b.WriteRune(r)
		case r > 0xFFFF:
			fmt.Fprintf(&b, "\\U%08X", r)
		default:
			fmt.Fprintf(&b, "\\u%04X", r)
		}
	}
	return b.String()
}

func unsafeRune(r rune) bool { return !unicode.IsPrint(r) || unicode.Is(unicode.Cf, r) }

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // never fails
	return hex.EncodeToString(b)
}

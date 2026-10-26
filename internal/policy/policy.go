// Package policy decides which tools, prompts and resources of a server are exposed, to every
// caller (a server's filters) and to each token (token policies).
//
// Both kinds of filter are an allow list or a deny list: an entry passes an allow list when any
// of its keys is listed, and fails a deny list when any of its keys is listed. They differ in
// what an empty allow list means, so they are distinct types made by distinct constructors. A
// server's tool filter with an empty allow list filters nothing, as mcp-proxy's toolFilter did,
// and a server's prompt or resource filter with one exposes nothing. A token policy has no empty
// lists; its filter of PolicyNone exposes nothing.
//
// Which resource URIs may be read is decided by one algorithm, Reads, for a server's resource
// filter and for a token's.
package policy

import (
	"regexp"
	"strings"
	"sync"

	"github.com/yosida95/uritemplate/v3"

	"github.com/vsem-azamat/mcp-gate/internal/config"
)

// list is the matching shared by both kinds of filter. The zero list passes everything.
type list struct {
	set   map[string]struct{}
	allow bool
	none  bool // passes nothing
	any   bool // passes everything
}

func newList(allow, deny []string) list {
	entries, isAllow := deny, false
	if allow != nil {
		entries, isAllow = allow, true
	}
	set := make(map[string]struct{}, len(entries))
	for _, v := range entries {
		set[v] = struct{}{}
	}
	return list{set: set, allow: isAllow}
}

// ExposesNothing reports whether no entry can pass.
func (l list) ExposesNothing() bool { return l.none }

// Deny reports whether l is a deny list.
func (l list) Deny() bool { return !l.any && !l.none && !l.allow }

// Allows reports whether an entry listed under keys passes.
func (l list) Allows(keys ...string) bool {
	switch {
	case l.any:
		return true
	case l.none:
		return false
	}
	listed := false
	for _, k := range keys {
		if _, ok := l.set[k]; ok {
			listed = true
		}
	}
	return listed == l.allow
}

// Listed returns the entries of a deny list.
func (l list) Listed() []string {
	if !l.Deny() {
		return nil
	}
	out := make([]string, 0, len(l.set))
	for k := range l.set {
		out = append(out, k)
	}
	return out
}

// ServerFilter is one of a server's filters, which every caller of the server is subject to.
type ServerFilter struct{ list }

// NewServerToolFilter returns a server's tool filter, in which an empty allow list filters
// nothing; f may be nil.
func NewServerToolFilter(f *config.Filter) ServerFilter { return newServerFilter(f, true) }

// NewServerFilter returns a server's prompt or resource filter, in which an empty allow list
// exposes nothing; f may be nil.
func NewServerFilter(f *config.Filter) ServerFilter { return newServerFilter(f, false) }

func newServerFilter(f *config.Filter, emptyAllowPasses bool) ServerFilter {
	switch {
	case f == nil:
		return ServerFilter{list{any: true}}
	case f.Allow != nil && len(f.Allow) == 0 && emptyAllowPasses:
		return ServerFilter{list{any: true}}
	case f.Allow != nil && len(f.Allow) == 0:
		return ServerFilter{list{none: true}}
	}
	return ServerFilter{newList(f.Allow, f.Deny)}
}

// TokenFilter is one filter of a token's policy on a server, applied after the server's.
type TokenFilter struct{ list }

// NewTokenFilter returns a token policy's filter: PolicyNone exposes nothing; f may be nil.
// Validation keeps its lists from being empty.
func NewTokenFilter(f *config.PolicyFilter) TokenFilter {
	switch {
	case f == nil:
		return TokenFilter{list{any: true}}
	case f.None:
		return TokenFilter{list{none: true}}
	}
	return TokenFilter{newList(f.Allow, f.Deny)}
}

// Policy is the exposure policy of one server.
type Policy struct {
	Tools, Prompts, Resources ServerFilter

	mu    sync.RWMutex
	reads *Reads
}

// New returns the policy for a server's config.
func New(s *config.Server) *Policy {
	p := &Policy{
		Tools:     NewServerToolFilter(s.Tools),
		Prompts:   NewServerFilter(s.Prompts),
		Resources: NewServerFilter(s.Resources),
	}
	p.SetCatalog(nil, nil)
	return p
}

// SetCatalog records the resources and resource templates the server lists, before its
// resource filter, which decide what ReadAllowed passes.
func (p *Policy) SetCatalog(resources, templates []Entry) {
	r := NewReads(p.Resources.list, resources, templates)
	p.mu.Lock()
	p.reads = r
	p.mu.Unlock()
}

// ReadAllowed reports whether a resource URI may be read, by Reads.
func (p *Policy) ReadAllowed(uri string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.reads.Allowed(uri)
}

// Decision is what a token policy decided about an entry, as the audit line records it.
type Decision string

// The decisions of a token policy.
const (
	// NoPolicy is the decision for a caller without a policy on the server, and for an entry
	// the server does not have.
	NoPolicy Decision = "none"
	// Allowed is the decision for an entry the caller's policy passes.
	Allowed Decision = "allow"
	// Denied is the decision for an entry the caller's policy hides.
	Denied Decision = "deny"
)

// DecisionOf returns the decision for an entry a policy passes or not.
func DecisionOf(passes bool) Decision {
	if passes {
		return Allowed
	}
	return Denied
}

// Token is the policy of one token on one server, applied on top of the server's own filters.
// It does not change once made.
type Token struct {
	Tools, Prompts, Resources TokenFilter
}

// Tokens are the token policies of one server, by token name. They do not change once made.
type Tokens map[string]*Token

// NewTokens returns the token policies cfg sets on server.
func NewTokens(cfg *config.Config, server string) Tokens {
	out := Tokens{}
	for name := range cfg.Policies {
		if p := cfg.ServerPolicy(name, server); p != nil {
			out[name] = &Token{Tools: NewTokenFilter(p.Tools), Prompts: NewTokenFilter(p.Prompts), Resources: NewTokenFilter(p.Resources)}
		}
	}
	return out
}

// For returns the policy of the token named token; nil when it has none.
func (ts Tokens) For(token string) *Token {
	if token == "" {
		return nil
	}
	return ts[token]
}

// Reads returns what the token may read of a catalog that lists resources and templates.
func (t *Token) Reads(resources, templates []Entry) *Reads {
	return NewReads(t.Resources.list, resources, templates)
}

// Entry is a resource or a resource template of a catalog: its URI or URI template, and its
// name.
type Entry struct{ Key, Name string }

// Reads decides which resource URIs may be read, under one resource filter, from a catalog that
// lists resources and resource templates. It does not change once made.
//
// A read reaches the resource listed under its URI, or else a template that matches it, so it
// passes when that entry passes: a listed resource the filter passes, or, for a URI not listed,
// under an allow list a matching template the filter passes and under a deny list no matching
// template the filter hides. It is also refused when the comparison key of the URI is that of a
// listed resource the filter hides or, under a deny list, of an entry the list names, so that a
// template does not reach a hidden resource by another spelling. Under a deny list the key drops
// the query, so every query of a hidden URI is refused; under an allow list it keeps it, so
// that hiding db://t?id=1 does not refuse db://t?id=2. It errs towards refusing.
type Reads struct {
	key       func(string) string // the comparison key: NormalizeURI, keeping the query unless under a deny list
	all       bool                // no filter
	none      bool
	deny      bool
	listed    map[string]bool     // listed URI → whether the filter passes it
	blocked   map[string]struct{} // comparison keys refused
	templates []readTemplate
}

type readTemplate struct {
	re     *regexp.Regexp
	passes bool
}

// NewReads compiles the reads l allows from a catalog.
func NewReads(l list, resources, templates []Entry) *Reads {
	r := &Reads{
		key: normalizeKeepingQuery, all: l.any, none: l.none, deny: l.Deny(),
		listed: make(map[string]bool, len(resources)), blocked: map[string]struct{}{},
	}
	if r.deny {
		// A deny list refuses every query of a URI it names or hides.
		r.key = NormalizeURI
	}
	for _, v := range l.Listed() {
		r.blocked[r.key(v)] = struct{}{}
	}
	for _, e := range resources {
		passes := l.Allows(e.Key, e.Name)
		r.listed[e.Key] = passes
		if !passes {
			r.blocked[r.key(e.Key)] = struct{}{}
		}
	}
	for _, e := range templates {
		if t, err := uritemplate.New(e.Key); err == nil {
			r.templates = append(r.templates, readTemplate{re: t.Regexp(), passes: l.Allows(e.Key, e.Name)})
		}
	}
	return r
}

// Allowed reports whether uri may be read.
func (r *Reads) Allowed(uri string) bool {
	switch {
	case r.all:
		return true
	case r.none:
		return false
	}
	if _, blocked := r.blocked[r.key(uri)]; blocked {
		return false
	}
	if passes, ok := r.listed[uri]; ok {
		return passes
	}
	matched := false
	for _, t := range r.templates {
		if !t.re.MatchString(uri) {
			continue
		}
		if r.deny && !t.passes {
			return false
		}
		matched = matched || t.passes
	}
	return r.deny || matched
}

// NormalizeURI returns the key a URI is compared by, so that a deny list is not sidestepped by
// another spelling of a denied URI that a server would read the same: every percent-encoding is
// decoded until none is left, the query and fragment are dropped, the scheme and authority are
// lower-cased, user information, a port and a trailing dot are dropped from the authority and so
// is a "localhost" authority, and the authority and path are taken as
// one path in which ";" parameters, surrounding spaces and NULs, and empty and "." segments are
// dropped and ".." segments resolved. The key is "<scheme>:<path>", so "fake://hidden",
// "fake:///hidden" and "fake:hidden" share it. It keeps the case of the path and errs towards
// treating different URIs as one, which under a deny list refuses more, never less.
func NormalizeURI(raw string) string {
	raw, _, _ = strings.Cut(decodeAll(raw), "?")
	return normalizeDecoded(raw)
}

// normalizeKeepingQuery returns the key of NormalizeURI followed by the URI's decoded query,
// if it has one, so that URIs that differ only in their query keep different keys.
func normalizeKeepingQuery(raw string) string {
	raw, query, _ := strings.Cut(decodeAll(raw), "?")
	key := normalizeDecoded(raw)
	if query == "" {
		return key
	}
	return key + "?" + query
}

// decodeAll decodes every percent-encoding until none is left and drops the fragment.
func decodeAll(raw string) string {
	// Decoding can form a new escape ("%7%30" becomes "%70"), so repeat until nothing changes.
	// Each pass shortens the string or leaves it unchanged.
	for {
		n := decodeOnce(raw)
		if n == raw {
			break
		}
		raw = n
	}
	raw, _, _ = strings.Cut(raw, "#")
	return raw
}

// normalizeDecoded is NormalizeURI for a decoded URI without query or fragment.
func normalizeDecoded(raw string) string {
	scheme, rest, ok := strings.Cut(raw, ":")
	if !ok || scheme == "" || strings.ContainsAny(scheme, "/") {
		return cleanPath(raw)
	}
	if hier, ok := strings.CutPrefix(rest, "//"); ok {
		authority, path := hier, ""
		if i := strings.IndexByte(hier, '/'); i >= 0 {
			authority, path = hier[:i], hier[i:]
		}
		// The authority is cleaned as the first segment of the path, since for many schemes
		// (such as "fake://hidden") it names the resource itself.
		if authority = hostOf(authority); authority == "localhost" {
			authority = ""
		}
		rest = authority + path
	}
	return strings.ToLower(scheme) + ":" + cleanPath(rest)
}

// hostOf returns the host of an authority, lower-cased, without user information, port or a
// trailing dot.
func hostOf(authority string) string {
	if i := strings.LastIndexByte(authority, '@'); i >= 0 {
		authority = authority[i+1:]
	}
	if i := strings.LastIndexByte(authority, ':'); i >= 0 && !strings.Contains(authority[i:], "]") {
		authority = authority[:i]
	}
	return strings.TrimSuffix(strings.ToLower(authority), ".")
}

// cleanPath joins the segments of path with "/" after dropping ";" parameters, surrounding
// spaces and NULs, and empty and "." segments, and resolving ".." segments.
func cleanPath(path string) string {
	var out []string
	for seg := range strings.SplitSeq(path, "/") {
		seg, _, _ = strings.Cut(seg, ";")
		seg = strings.Trim(seg, " \t\r\n\x00")
		switch seg {
		case "", ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, seg)
		}
	}
	return strings.Join(out, "/")
}

func decodeOnce(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		if raw[i] == '%' && i+2 < len(raw) && isHex(raw[i+1]) && isHex(raw[i+2]) {
			b.WriteByte(unhex(raw[i+1])<<4 | unhex(raw[i+2]))
			i += 2
			continue
		}
		b.WriteByte(raw[i])
	}
	return b.String()
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

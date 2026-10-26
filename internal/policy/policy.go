// Package policy decides which tools, prompts and resources of a server are exposed, to every
// caller and to each token.
//
// A filter is an allow list or a deny list. An entry passes an allow list when any of its keys
// is listed, and fails a deny list when any of its keys is listed. A server's tool filter with
// an empty allow list filters nothing, as mcp-proxy's toolFilter did; a prompt or resource
// filter with an empty allow list, and every filter of a token policy with one, exposes nothing.
package policy

import (
	"strings"
	"sync"

	"github.com/vsem-azamat/mcp-gate/internal/config"
)

// Filter is one allow or deny list. The zero Filter passes everything.
type Filter struct {
	set   map[string]struct{}
	allow bool
	none  bool // an empty allow list of a prompt or resource filter
	any   bool // no filter, or an empty tool allow list
}

// NewToolFilter returns the filter for tools; f may be nil.
func NewToolFilter(f *config.Filter) Filter { return newFilter(f, true) }

// NewFilter returns the filter for prompts or resources; f may be nil.
func NewFilter(f *config.Filter) Filter { return newFilter(f, false) }

func newFilter(f *config.Filter, emptyAllowPasses bool) Filter {
	if f == nil {
		return Filter{any: true}
	}
	list, allow := f.Deny, false
	if f.Allow != nil {
		list, allow = f.Allow, true
	}
	if allow && len(list) == 0 {
		if emptyAllowPasses {
			return Filter{any: true}
		}
		return Filter{none: true}
	}
	set := make(map[string]struct{}, len(list))
	for _, v := range list {
		set[v] = struct{}{}
	}
	return Filter{set: set, allow: allow}
}

// ExposesNothing reports whether no entry can pass: a prompt or resource filter with an empty
// allow list. Such a server does not advertise the capability.
func (f Filter) ExposesNothing() bool { return f.none }

// Deny reports whether f is a deny list.
func (f Filter) Deny() bool { return !f.any && !f.none && !f.allow }

// Allows reports whether an entry listed under keys passes the filter.
func (f Filter) Allows(keys ...string) bool {
	switch {
	case f.any:
		return true
	case f.none:
		return false
	}
	listed := false
	for _, k := range keys {
		if _, ok := f.set[k]; ok {
			listed = true
		}
	}
	return listed == f.allow
}

// Listed returns the entries of a deny list.
func (f Filter) Listed() []string {
	if !f.Deny() {
		return nil
	}
	out := make([]string, 0, len(f.set))
	for k := range f.set {
		out = append(out, k)
	}
	return out
}

// Policy is the exposure policy of one server.
type Policy struct {
	Tools, Prompts, Resources Filter

	mu      sync.RWMutex
	blocked map[string]struct{} // normalized URIs a deny list hides; nil without one
}

// New returns the policy for a server's config.
func New(s *config.Server) *Policy {
	p := &Policy{
		Tools:     NewToolFilter(s.Tools),
		Prompts:   NewFilter(s.Prompts),
		Resources: NewFilter(s.Resources),
	}
	p.SetHiddenResources(nil)
	return p
}

// SetHiddenResources records the URIs of resources hidden by a resource deny list, so that a
// read of one through a resource template is refused too. It does nothing without a deny list.
func (p *Policy) SetHiddenResources(uris []string) {
	if !p.Resources.Deny() {
		return
	}
	listed := p.Resources.Listed()
	blocked := make(map[string]struct{}, len(listed)+len(uris))
	for _, u := range listed {
		blocked[NormalizeURI(u)] = struct{}{}
	}
	for _, u := range uris {
		blocked[NormalizeURI(u)] = struct{}{}
	}
	p.mu.Lock()
	p.blocked = blocked
	p.mu.Unlock()
}

// ReadAllowed reports whether a resource URI may be read. Lists are filtered when the catalog is
// mirrored, but a read of a URI that is not listed reaches the first template it matches, so
// under a deny list the URI is checked again: its comparison key against the keys of the listed
// entries and of the URIs of hidden resources. Under an allow list a read can only reach an
// allowed resource or template.
func (p *Policy) ReadAllowed(uri string) bool {
	if p.Resources.ExposesNothing() {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.blocked == nil {
		return true
	}
	_, blocked := p.blocked[NormalizeURI(uri)]
	return !blocked
}

// Decision is what a token policy decided about an entry, as the audit line records it.
type Decision string

// The decisions of a token policy.
const (
	// NoPolicy is the decision for a caller without a policy on the server.
	NoPolicy Decision = "none"
	// Allowed is the decision for an entry the caller's policy passes.
	Allowed Decision = "allow"
	// Denied is the decision for an entry the caller's policy hides.
	Denied Decision = "deny"
)

// Token is the policy of one token on one server, applied on top of the server's own filters.
// It does not change once made. A nil *Token decides NoPolicy for everything.
type Token struct {
	tools, prompts, resources Filter
}

// Tokens are the token policies of one server, by token name. They do not change once made.
type Tokens map[string]*Token

// NewTokens returns the token policies cfg sets on server.
func NewTokens(cfg *config.Config, server string) Tokens {
	out := Tokens{}
	for name := range cfg.Policies {
		if p := cfg.ServerPolicy(name, server); p != nil {
			out[name] = &Token{tools: NewFilter(p.Tools), prompts: NewFilter(p.Prompts), resources: NewFilter(p.Resources)}
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

func decide(f Filter, keys ...string) Decision {
	if f.Allows(keys...) {
		return Allowed
	}
	return Denied
}

// Tool decides a tool by name.
func (t *Token) Tool(name string) Decision {
	if t == nil {
		return NoPolicy
	}
	return decide(t.tools, name)
}

// Prompt decides a prompt by name.
func (t *Token) Prompt(name string) Decision {
	if t == nil {
		return NoPolicy
	}
	return decide(t.prompts, name)
}

// Resource decides a listed resource by its URI and name, or a resource template by its URI
// template and name.
func (t *Token) Resource(key, name string) Decision {
	if t == nil {
		return NoPolicy
	}
	return decide(t.resources, key, name)
}

// Entry is a resource or a resource template of a server's catalog: its URI or URI template,
// and its name.
type Entry struct{ Key, Name string }

// Read decides a read of uri, given the resources the server lists and the templates of its
// catalog that match uri. A read reaches the resource listed under uri, or else a template
// that matches it, so it passes when that entry passes. Under a deny list it is refused, as
// under a server's deny list, when the comparison key of uri is the key of a listed entry or of
// the URI of a resource the list hides, and when any template that matches it is hidden; it
// errs towards refusing.
func (t *Token) Read(uri string, resources, matching []Entry) Decision {
	if t == nil {
		return NoPolicy
	}
	f := t.resources
	switch {
	case f.any:
		return Allowed
	case f.none:
		return Denied
	}
	for _, r := range resources {
		if r.Key == uri {
			return t.readListed(uri, r, resources)
		}
	}
	if f.Deny() {
		if t.blocked(uri, resources) {
			return Denied
		}
		for _, e := range matching {
			if !f.Allows(e.Key, e.Name) {
				return Denied
			}
		}
		return Allowed
	}
	for _, e := range matching {
		if f.Allows(e.Key, e.Name) {
			return Allowed
		}
	}
	return Denied
}

// readListed decides a read of a URI the server lists as r.
func (t *Token) readListed(uri string, r Entry, resources []Entry) Decision {
	if !t.resources.Allows(r.Key, r.Name) || t.resources.Deny() && t.blocked(uri, resources) {
		return Denied
	}
	return Allowed
}

// blocked reports, under a deny list, whether the comparison key of uri is that of a listed
// entry or of the URI of a resource the list hides.
func (t *Token) blocked(uri string, resources []Entry) bool {
	key := NormalizeURI(uri)
	for _, l := range t.resources.Listed() {
		if NormalizeURI(l) == key {
			return true
		}
	}
	for _, r := range resources {
		if !t.resources.Allows(r.Key, r.Name) && NormalizeURI(r.Key) == key {
			return true
		}
	}
	return false
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
	raw, _, _ = strings.Cut(raw, "?")
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

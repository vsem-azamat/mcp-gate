// Package policy decides which tools, prompts and resources of a server are exposed.
//
// A filter is an allow list or a deny list. An entry passes an allow list when any of its keys
// is listed, and fails a deny list when any of its keys is listed. A tool filter with an empty
// allow list filters nothing, as mcp-proxy's toolFilter did; a prompt or resource filter with an
// empty allow list exposes nothing.
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
// under a deny list the URI is checked again: against the listed entries and the URIs of hidden
// resources, after normalization. Under an allow list a read can only reach an allowed resource
// or template.
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

// NormalizeURI gives equivalent spellings of a URI one form, so that a deny list cannot be
// sidestepped by "test://echo/%73ecret" or "TEST://Host/secret": the fragment is dropped, the
// scheme and host are lower-cased, percent-encoded unreserved characters are decoded and other
// percent-encodings are upper-cased (RFC 3986 section 6.2.2). The path keeps its case.
func NormalizeURI(raw string) string {
	// Decoding can form a new escape ("%7%30" becomes "%70"), so repeat until the form is
	// stable. Each pass shortens the string or leaves it unchanged.
	for {
		n := normalizeOnce(raw)
		if n == raw {
			return n
		}
		raw = n
	}
}

func normalizeOnce(raw string) string {
	raw, _, _ = strings.Cut(raw, "#")
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		if raw[i] == '%' && i+2 < len(raw) && isHex(raw[i+1]) && isHex(raw[i+2]) {
			c := unhex(raw[i+1])<<4 | unhex(raw[i+2])
			if isUnreserved(c) {
				b.WriteByte(c)
			} else {
				b.WriteByte('%')
				b.WriteString(strings.ToUpper(raw[i+1 : i+3]))
			}
			i += 2
			continue
		}
		b.WriteByte(raw[i])
	}
	uri := b.String()
	scheme, rest, ok := strings.Cut(uri, ":")
	if !ok || scheme == "" || strings.ContainsAny(scheme, "/?") {
		return uri
	}
	scheme = strings.ToLower(scheme)
	if authority, ok := strings.CutPrefix(rest, "//"); ok {
		end := strings.IndexAny(authority, "/?")
		if end < 0 {
			end = len(authority)
		}
		return scheme + "://" + strings.ToLower(authority[:end]) + authority[end:]
	}
	return scheme + ":" + rest
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

func isUnreserved(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~'
}

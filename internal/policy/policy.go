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
	"math/big"
	"regexp"
	"slices"
	"strings"
	"sync"
	"unicode"

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
// template the filter hides. So that a template does not reach a hidden resource by another
// spelling, a read is also refused when the comparison key of its URI (NormalizeURI, without
// the query) is that of an entry a deny list names, or of a listed resource the filter hides,
// with these exceptions for a hidden resource whose URI has a query, under an allow list only:
// the read is refused when its query, with the ";" parameters of its path, holds every
// parameter of the hidden URI's query (see readParams, queryParams and containsParams), and
// passes otherwise, so that hiding db://t?id=1 does not refuse db://t?id=2.
// Under a deny list every query of a hidden URI is refused. It errs towards refusing.
type Reads struct {
	all       bool // no filter
	none      bool
	deny      bool
	listed    map[string]bool                  // listed URI → whether the filter passes it
	blocked   map[string]struct{}              // comparison keys refused whatever the query
	queries   map[string][]map[string][]string // comparison key → the parameters of hidden URIs with a query, under an allow list
	templates []readTemplate
}

type readTemplate struct {
	re     *regexp.Regexp
	passes bool
}

// NewReads compiles the reads l allows from a catalog.
func NewReads(l list, resources, templates []Entry) *Reads {
	r := &Reads{
		all: l.any, none: l.none, deny: l.Deny(),
		listed: make(map[string]bool, len(resources)), blocked: map[string]struct{}{}, queries: map[string][]map[string][]string{},
	}
	for _, v := range l.Listed() {
		r.blocked[NormalizeURI(v)] = struct{}{}
	}
	for _, e := range resources {
		passes := l.Allows(e.Key, e.Name)
		r.listed[e.Key] = passes
		if passes {
			continue
		}
		key := NormalizeURI(e.Key)
		if params := queryParams(e.Key); !r.deny && len(params) > 0 {
			r.queries[key] = append(r.queries[key], params)
		} else {
			r.blocked[key] = struct{}{}
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
	key := NormalizeURI(uri)
	if _, blocked := r.blocked[key]; blocked {
		return false
	}
	if hidden := r.queries[key]; len(hidden) > 0 {
		params := readParams(uri)
		for _, h := range hidden {
			if containsParams(params, h) {
				return false
			}
		}
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

// queryParams returns the parameters of a URI's query, as compared to tell whether a read names
// a hidden resource: the query decoded as NormalizeURI decodes, split at "&" and ";", each
// parameter at its first "="; "+" read as a space; format characters (such as a zero-width
// space) and control characters removed from keys and values, which are then trimmed of spaces
// and "=" and lower-cased; a key without a "[...]" suffix; a value that reads as a number in its
// canonical form (see canonicalNumber); empty parameters dropped. Every choice makes more
// queries alike, which refuses more, never less.
func queryParams(raw string) map[string][]string {
	_, query, _ := strings.Cut(decodeAll(raw), "?")
	return parseParams(query)
}

// readParams returns the parameters of a read's URI: those of its query and the ";" parameters
// of its path, which some servers read as query parameters. A read gains parameters by them, so
// it refuses more, never less; a hidden URI's parameters are those of its query only.
func readParams(raw string) map[string][]string {
	decoded := decodeAll(raw)
	path, query, _ := strings.Cut(decoded, "?")
	var b strings.Builder
	b.WriteString(query)
	for seg := range strings.SplitSeq(path, "/") {
		if _, p, ok := strings.Cut(seg, ";"); ok {
			b.WriteString("&")
			b.WriteString(p)
		}
	}
	return parseParams(b.String())
}

func parseParams(query string) map[string][]string {
	params := map[string][]string{}
	for part := range strings.FieldsFuncSeq(query, func(r rune) bool { return r == '&' || r == ';' }) {
		k, v, _ := strings.Cut(strings.ReplaceAll(part, "+", " "), "=")
		k, v = queryText(k), queryText(v)
		if i := strings.IndexByte(k, '['); i > 0 {
			k = queryText(k[:i])
		}
		if k == "" && v == "" {
			continue
		}
		if n, ok := canonicalNumber(v); ok {
			v = n
		}
		params[k] = append(params[k], v)
	}
	return params
}

// queryText removes format characters (such as a zero-width space) and control characters from
// s, trims it of spaces and "=", and lower-cases it.
func queryText(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) || unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	return strings.ToLower(strings.TrimFunc(s, func(r rune) bool { return unicode.IsSpace(r) || r == '=' }))
}

// numberPrec is the precision, in bits, at which canonicalNumber compares numbers: integers up
// to 2^256 stay exact, and numbers that differ by less round alike, which refuses more.
const numberPrec = 256

// maxNumberLen is the longest value, once its padding zeros are dropped, that canonicalNumber
// parses, which bounds the time it takes. Its canonical form is binary, so that the time does
// not grow with the exponent.
const maxNumberLen = 128

// numberChars are the characters a value read as a number may have, once lower-cased.
const numberChars = "0123456789abcdefopx.+-_ "

var numberSeparators = strings.NewReplacer("_", "", " ", "")

// canonicalNumber returns the canonical form of a value that reads as a number, in decimal or
// with a "0x", "0o" or "0b" prefix, with a sign, a fraction and an exponent, after dropping
// every "_" and space, so that "01", "1.0", "0x1" and "1e0" share one. Padding zeros are dropped
// before the value is parsed; a value still longer than maxNumberLen is read as a number only
// when it is all digits, and is then kept as it is.
func canonicalNumber(v string) (string, bool) {
	if v == "" || strings.Trim(v, numberChars) != "" || !strings.ContainsAny(v, "0123456789") {
		return "", false
	}
	if v = dropPaddingZeros(numberSeparators.Replace(v)); len(v) > maxNumberLen {
		return v, strings.Trim(v, "0123456789") == ""
	}
	f, _, err := big.ParseFloat(v, 0, numberPrec, big.ToNearestEven)
	if err != nil || f.IsInf() {
		return "", false
	}
	if f.Sign() == 0 {
		return "0", true
	}
	return f.Text('p', 0), true
}

// dropPaddingZeros drops the leading zeros of the integer part, after any sign and base prefix,
// and the trailing zeros of the fraction of a value written as a number. A value that is not a
// number may become one ("0-5" becomes "-5"), which only makes more values alike.
func dropPaddingZeros(v string) string {
	sign := ""
	if v != "" && (v[0] == '+' || v[0] == '-') {
		sign, v = v[:1], v[1:]
	}
	prefix, expMark := "", "e"
	if len(v) > 1 && v[0] == '0' && strings.ContainsRune("xob", rune(v[1])) {
		prefix, v, expMark = v[:2], v[2:], "p"
	}
	mantissa, exp, hasExp := strings.Cut(v, expMark)
	whole, frac, _ := strings.Cut(mantissa, ".")
	if trimmed := strings.TrimLeft(whole, "0"); trimmed != "" || whole == "" {
		whole = trimmed
	} else {
		whole = "0"
	}
	frac = strings.TrimRight(frac, "0")
	out := sign + prefix + whole
	if frac != "" {
		out += "." + frac
	}
	if hasExp {
		out += expMark + exp
	}
	return out
}

// containsParams reports whether params has every parameter of hidden, each with one of its
// values; a hidden parameter without a value is held by the key with any value.
func containsParams(params, hidden map[string][]string) bool {
	for k, values := range hidden {
		for _, v := range values {
			if v == "" && len(params[k]) > 0 {
				continue
			}
			if !slices.Contains(params[k], v) {
				return false
			}
		}
	}
	return true
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

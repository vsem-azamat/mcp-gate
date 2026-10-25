// Package redact finds credentials in text and replaces them.
//
// The scan is pattern based: vendor token formats, PEM private keys, URL userinfo, .env-style
// assignments, password and token key-value pairs, optional Russian credential labels and an
// optional high-entropy heuristic. It cannot recognise a secret that has no shape (a password
// mentioned in plain prose), nor one that is encoded or split across messages.
//
// The package knows nothing about MCP or HTTP; package mcpredact applies it to MCP results.
package redact

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Options select the rules an Engine runs.
type Options struct {
	// Russian adds the Russian credential-label rules.
	Russian bool
	// HighEntropy adds the high-entropy heuristic, which flags long random-looking tokens.
	HighEntropy bool
	// DisableRules lists finding kinds (see Kinds) that are never reported.
	DisableRules []string
}

// Engine finds and replaces credentials. It holds no mutable state and is safe for concurrent
// use.
type Engine struct {
	rules    []*rule
	disabled map[string]bool
}

// New returns an Engine for opts. It fails when DisableRules names an unknown kind.
func New(opts Options) (*Engine, error) {
	kinds := Kinds()
	e := &Engine{disabled: make(map[string]bool, len(opts.DisableRules))}
	var errs []error
	for i, kind := range opts.DisableRules {
		if !slices.Contains(kinds, kind) {
			errs = append(errs, fmt.Errorf("disableRules[%d]: unknown rule %q (known: %s)", i, kind, strings.Join(kinds, ", ")))
			continue
		}
		e.disabled[kind] = true
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	for _, r := range allRules() {
		switch {
		case r.set == setHighEntropy && !opts.HighEntropy:
		case r.set == setRussian && !opts.Russian:
		default:
			e.rules = append(e.rules, r)
		}
	}
	return e, nil
}

// Kinds returns every kind a finding can have, sorted. DisableRules takes these names.
func Kinds() []string {
	var kinds []string
	for _, r := range allRules() {
		kinds = append(kinds, r.kind)
	}
	// Kinds that rules emit through their accept function rather than declare.
	kinds = append(kinds, kindPassword)
	slices.Sort(kinds)
	return slices.Compact(kinds)
}

// Finding is one detected secret.
type Finding struct {
	// Kind names what was found, such as "github_token" or "password".
	Kind string
	// Value is the secret. A value written inside a JSON string literal is given decoded.
	Value string
}

// Span is a finding located in a text: Start and End are byte offsets, with End exclusive.
type Span struct {
	Start, End int
	Finding    Finding
}

// Replacer decides what replaces each finding. Replace may be called from many goroutines at
// once and must not return the value it was given.
type Replacer interface {
	Replace(f Finding) string
}

// ReplacerFunc adapts a function to a Replacer.
type ReplacerFunc func(f Finding) string

// Replace calls fn(f).
func (fn ReplacerFunc) Replace(f Finding) string { return fn(f) }

// Marker is the default Replacer: it writes MarkerText(f.Kind).
type Marker struct{}

// Replace returns MarkerText(f.Kind).
func (Marker) Replace(f Finding) string { return MarkerText(f.Kind) }

// MarkerText is the default replacement for a finding of the given kind: "[REDACTED:<kind>]".
func MarkerText(kind string) string {
	return markerPrefix + kind + "]"
}

// markerPrefix starts every marker; a value that contains it is never reported again.
const markerPrefix = "[REDACTED:"

// RedactText replaces every finding in text with what r returns. JSON in text is matched as
// text; see RedactString.
func (e *Engine) RedactText(text string, r Replacer) string {
	spans := e.Find(text)
	if len(spans) == 0 {
		return text
	}
	var b strings.Builder
	b.Grow(len(text))
	last := 0
	for _, s := range spans {
		b.WriteString(text[last:s.Start])
		b.WriteString(r.Replace(s.Finding))
		last = s.End
	}
	b.WriteString(text[last:])
	return b.String()
}

// RedactString is RedactText, except that a text that is a JSON object or array is rewritten
// value by value (see RedactJSON), so escaped content is matched decoded and member names
// mark secret values.
func (e *Engine) RedactString(text string, r Replacer) string {
	return e.redactString(text, r, 0)
}

// ErrInvalidJSON is returned by RedactJSON for data that is not valid JSON.
var ErrInvalidJSON = errors.New("redact: invalid JSON")

// RedactJSON rewrites the string values of a JSON document, leaving every other byte (key
// order, numbers, whitespace) as it was. A value under a member whose name marks a secret
// ("password", "client_secret", "Authorization") is replaced as a whole, and so is a number of
// three or more characters there, which becomes a JSON string. Strings that hold JSON
// documents are followed up to five levels deep. Data that is not valid JSON yields
// ErrInvalidJSON.
func (e *Engine) RedactJSON(data []byte, r Replacer) ([]byte, error) {
	if !json.Valid(data) {
		return nil, ErrInvalidJSON
	}
	out, err := e.rewriteJSON(data, r, 1, "")
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (e *Engine) redactString(text string, r Replacer, depth int) string {
	if depth < maxJSONDepth && looksLikeJSON(text) {
		if out, err := e.rewriteJSON([]byte(text), r, depth+1, ""); err == nil {
			return string(out)
		}
	}
	return e.RedactText(text, r)
}

// Find returns the findings in text, ordered by position and never overlapping. Candidates
// that overlap become one finding covering all of them, with the kind from the rule with the
// lowest priority number.
func (e *Engine) Find(text string) []Span {
	if text == "" {
		return nil
	}
	// The rules run on text with its escaped line breaks masked, which keeps every position, so
	// the spans cut the original text.
	masked := maskEscapedBreaks(text)
	var lowered string
	lower := func() string {
		if lowered == "" {
			lowered = strings.ToLower(masked)
		}
		return lowered
	}
	var kept []span
	for _, r := range e.rules {
		if len(r.prefilter) > 0 && !containsAny(lower(), r.prefilter) {
			continue
		}
		if r.precheck != nil && !r.precheck(masked) {
			continue
		}
		kept = mergeSpans(kept, e.ruleSpans(r, masked))
	}
	if len(kept) == 0 {
		return nil
	}
	spans := make([]Span, len(kept))
	for i, s := range kept {
		spans[i] = Span{Start: s.start, End: s.end, Finding: Finding{Kind: s.kind, Value: s.value(text)}}
	}
	return spans
}

func containsAny(text string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

// ruleSpans returns the accepted matches of one rule, in order.
func (e *Engine) ruleSpans(r *rule, text string) []span {
	var spans []span
	for _, match := range r.re.FindAllStringSubmatchIndex(text, -1) {
		start, end := match[0], match[1]
		if len(r.groups) > 0 {
			start, end = -1, -1
			for _, group := range r.groups {
				if 2*group+1 < len(match) && match[2*group] >= 0 && match[2*group+1] > match[2*group] {
					start, end = match[2*group], match[2*group+1]
					break
				}
			}
			if start < 0 {
				continue
			}
		}
		accept := r.accept
		if accept == nil {
			accept = acceptAll
		}
		newStart, newEnd, kind, ok := accept(text, match, start, end)
		if !ok || newEnd <= newStart {
			continue
		}
		if kind == "" {
			kind = r.kind
		}
		if e.disabled[kind] {
			continue
		}
		spans = append(spans, span{start: newStart, end: newEnd, kind: kind, priority: r.priority, jsonEscaped: r.jsonEscaped})
	}
	return spans
}

// span is a finding while the rules run.
type span struct {
	start, end int
	kind       string
	// priority is that of the rule that decided the kind.
	priority    int
	jsonEscaped bool
}

// value returns the secret as a Replacer sees it: decoded when it was written inside a JSON
// string literal.
func (s span) value(text string) string {
	raw := text[s.start:s.end]
	if s.jsonEscaped && strings.Contains(raw, `\`) {
		if decoded, err := decodeJSONString([]byte(`"` + raw + `"`)); err == nil {
			return decoded
		}
	}
	return raw
}

// mergeSpans adds the spans of a lower-priority rule to kept. Spans that overlap are merged
// into one span covering all of them, with the kind of the one from the rule with the lowest
// priority number, so that no part of an overlapping candidate stays visible. Both inputs are
// sorted by position and free of overlaps, so one linear pass suffices.
func mergeSpans(kept, added []span) []span {
	if len(added) == 0 {
		return kept
	}
	if len(kept) == 0 {
		return added
	}
	merged := make([]span, 0, len(kept)+len(added))
	push := func(s span) {
		n := len(merged)
		if n == 0 || merged[n-1].end <= s.start {
			merged = append(merged, s)
			return
		}
		last := &merged[n-1]
		last.end = max(last.end, s.end)
		if s.priority < last.priority {
			last.kind, last.priority, last.jsonEscaped = s.kind, s.priority, s.jsonEscaped
		}
	}
	i, j := 0, 0
	for i < len(kept) || j < len(added) {
		if j == len(added) || (i < len(kept) && kept[i].start <= added[j].start) {
			push(kept[i])
			i++
		} else {
			push(added[j])
			j++
		}
	}
	return merged
}

// maskEscapedBreaks returns text with each escaped line break or tab (\n, \r, \t written as a
// backslash and a letter, as in JSON, a log or a repr that was not decoded) replaced by two NUL
// bytes, so it has the same length. NUL is no word character, so the rules see a boundary
// before what follows ("API:\n123:AA…" left none between n and the digit), and it is no line
// break, quote or backslash, so a quoted value that contains one still ends at its quote. An
// escaped backslash (\\n) is left alone.
func maskEscapedBreaks(text string) string {
	if !strings.Contains(text, `\`) {
		return text
	}
	b := []byte(text)
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' {
			continue
		}
		j := i
		for j < len(b) && b[j] == '\\' {
			j++
		}
		if (j-i)%2 == 1 && j < len(b) && (b[j] == 'n' || b[j] == 'r' || b[j] == 't') {
			b[j-1], b[j] = 0, 0
		}
		i = j - 1
	}
	return string(b)
}

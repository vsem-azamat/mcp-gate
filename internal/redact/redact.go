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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"
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
	// literals are the forms of the values found whatever their shape; see WithLiterals.
	literals []literalForm
}

// Literal is a known secret that an engine finds wherever it appears; see WithLiterals.
type Literal struct {
	Kind, Value string
}

// literalForm is one way a literal is written in a text: as it is, or as a JSON string escapes
// it.
type literalForm struct {
	kind, value, form string
}

// literalPriority is the priority of a literal finding: lower than every rule's, so that a
// finding that overlaps it takes its kind.
const literalPriority = -1

// WithLiterals returns an engine that runs e's rules and also finds each literal's value
// wherever it appears in a text, as written or as the body of a JSON string literal that
// escapes it, with the literal's kind. A finding that covers exactly one occurrence of a value
// has that value; one merged with other findings has the covered text, as always. Empty
// values are ignored. e is not changed.
func (e *Engine) WithLiterals(literals []Literal) *Engine {
	out := *e
	out.literals = slices.Clone(e.literals)
	for _, l := range literals {
		if l.Value == "" {
			continue
		}
		for _, form := range LiteralForms(l.Value) {
			out.literals = append(out.literals, literalForm{kind: l.Kind, value: l.Value, form: form})
		}
	}
	return &out
}

// LiteralForms returns the forms in which WithLiterals finds a value, each once: as written, as
// the body of a JSON string literal, percent-encoded as a query value and as a path segment, and
// in base64 with the standard and the URL alphabet, without padding (so that a padded form is
// found too, its padding left). Base64 is found only where the value's encoding starts on a
// group of the surrounding base64, as when the value is encoded alone. Other transformations
// (case, a split, another encoding) are not found.
func LiteralForms(value string) []string {
	escaped := string(encodeJSONString(value))
	var forms []string
	for _, f := range []string{
		value, escaped[1 : len(escaped)-1], url.QueryEscape(value), url.PathEscape(value),
		base64.RawStdEncoding.EncodeToString([]byte(value)), base64.RawURLEncoding.EncodeToString([]byte(value)),
	} {
		if !slices.Contains(forms, f) {
			forms = append(forms, f)
		}
	}
	return forms
}

// literalSpans returns the occurrences of one form of a literal in text, in order and without
// overlaps.
func literalSpans(l literalForm, text string) []span {
	var spans []span
	for from := 0; from < len(text); {
		i := strings.Index(text[from:], l.form)
		if i < 0 {
			break
		}
		start := from + i
		spans = append(spans, span{start: start, end: start + len(l.form), kind: l.kind, priority: literalPriority, literal: l.value})
		from = start + len(l.form)
	}
	return spans
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

// Cut returns text cut to at most n bytes, followed by "…" when it was cut. A UTF-8 character
// is never split; in text that is not UTF-8 the cut moves back by at most utf8.UTFMax-1 bytes.
func Cut(text string, n int) string {
	if len(text) <= n {
		return text
	}
	for back := 0; back < utf8.UTFMax-1 && n > 0 && !utf8.RuneStart(text[n]); back++ {
		n--
	}
	return text[:n] + "…"
}

// The bytes that stand for an escaped line break and an escaped tab in the text the rules see;
// the unquoted value classes of the rules exclude maskedBreak (\x00).
const (
	maskedBreak = 0x00
	maskedTab   = 0x01
)

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
	// Rules that share a prefilter (the Russian label rules) check it once.
	var lastPrefilter *string
	lastFound := false
	for _, r := range e.rules {
		if len(r.prefilter) > 0 {
			if &r.prefilter[0] != lastPrefilter {
				lastPrefilter, lastFound = &r.prefilter[0], containsAny(lower(), r.prefilter)
			}
			if !lastFound {
				continue
			}
		}
		if r.precheck != nil && !r.precheck(masked) {
			continue
		}
		kept = mergeSpans(kept, e.ruleSpans(r, masked))
	}
	for _, l := range e.literals {
		kept = mergeSpans(kept, literalSpans(l, text))
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
	if r.rescan {
		return e.rescanSpans(r, text)
	}
	if r.regions == nil {
		return e.matchSpans(r, text, r.re.FindAllStringSubmatchIndex(text, -1), nil)
	}
	var spans []span
	for _, region := range r.regions(text) {
		match := r.re.FindStringSubmatchIndex(text[region.start:region.end])
		if match == nil {
			continue
		}
		for k := range match {
			if match[k] >= 0 {
				match[k] += region.start
			}
		}
		spans = e.matchSpans(r, text, [][]int{match}, spans)
	}
	return spans
}

// rescanBudget bounds the bytes rescanSpans reads again in one text: rescanFactor times its
// size, plus rescanSlack.
const (
	rescanFactor = 4
	rescanSlack  = 64 << 10
)

// rescanSpans returns the accepted matches of a rule with rescan: after each match the search goes
// on from the end of its first group (the label), so that a label inside the rest of the match (a
// qualifier or a value, rejected or not) is matched with its own value. Accepted spans that overlap
// are merged. The values read again share a budget, since a text made of labels would make that
// quadratic; past it, the search goes on after each match.
func (e *Engine) rescanSpans(r *rule, text string) []span {
	var spans []span
	budget := rescanFactor*len(text) + rescanSlack
	for pos := 0; pos < len(text); {
		// The search starts at the character before pos, so that the expression sees the left
		// boundary of a label at pos as it does in the whole text.
		from := pos
		if from > 0 {
			from--
			for from > 0 && !utf8.RuneStart(text[from]) {
				from--
			}
		}
		match := r.re.FindStringSubmatchIndex(text[from:])
		if match == nil {
			break
		}
		for k := range match {
			if match[k] >= 0 {
				match[k] += from
			}
		}
		next := match[1]
		if g := match[3]; g > match[0] && budget >= match[1]-g {
			budget -= match[1] - g
			next = g
		}
		for _, s := range e.matchSpans(r, text, [][]int{match}, nil) {
			if n := len(spans); n > 0 && s.start < spans[n-1].end {
				spans[n-1].end = max(spans[n-1].end, s.end)
				spans[n-1].jsonEscaped = false
				continue
			}
			spans = append(spans, s)
		}
		pos = max(next, pos+1)
	}
	return spans
}

// matchSpans appends to spans the accepted matches of r, whose indexes refer to text.
func (e *Engine) matchSpans(r *rule, text string, matches [][]int, spans []span) []span {
	for _, match := range matches {
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
	// literal is the value of a literal (see WithLiterals) whose occurrence the span covers
	// exactly, or "".
	literal string
}

// value returns the secret as a Replacer sees it: decoded when it was written inside a JSON
// string literal.
func (s span) value(text string) string {
	if s.literal != "" {
		return s.literal
	}
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
// priority number, so that no part of an overlapping candidate stays visible. Spans that only
// touch stay separate. Both inputs are sorted by position and free of overlaps, so one linear
// pass suffices.
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
		end := max(last.end, s.end)
		winner := *last
		if s.priority < last.priority {
			winner = s
		}
		// A value is decoded as a JSON string only when an escaped finding covers the whole
		// merged span; otherwise the span holds text outside the literal and is given raw.
		escaped := (last.jsonEscaped && last.end == end) || (s.jsonEscaped && s.start == last.start && s.end == end)
		// Likewise a literal keeps its value only when its occurrence is the whole merged span.
		literal := ""
		switch {
		case last.literal != "" && last.end == end:
			literal = last.literal
		case s.literal != "" && s.start == last.start && s.end == end:
			literal = s.literal
		}
		last.end, last.kind, last.priority, last.jsonEscaped, last.literal = end, winner.kind, winner.priority, escaped, literal
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
// backslash and a letter, as in JSON, a log or a repr that was not decoded) replaced by two
// control bytes, so it has the same length: NUL for a line break, 0x01 for a tab. Neither is a
// word character, so the rules see a boundary before what follows ("API:\n123:AA…" left none
// between n and the digit), and neither is a line break, quote or backslash, so a quoted value
// that contains one still ends at its quote. An unquoted value stops at NUL, a line break, and
// goes on over 0x01, a tab, which a password can hold; a NUL byte in the text becomes 0x01 too.
// An escaped backslash (\\n) is left alone.
func maskEscapedBreaks(text string) string {
	hasNUL := strings.IndexByte(text, maskedBreak) >= 0
	if !hasNUL && !strings.Contains(text, `\`) {
		return text
	}
	b := []byte(text)
	if hasNUL {
		// A NUL in the text itself is no line break: it reads as maskedTab, so that values go
		// on over it.
		for i := range b {
			if b[i] == maskedBreak {
				b[i] = maskedTab
			}
		}
	}
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' {
			continue
		}
		j := i
		for j < len(b) && b[j] == '\\' {
			j++
		}
		if (j-i)%2 == 1 && j < len(b) {
			switch b[j] {
			case 'n', 'r':
				b[j-1], b[j] = maskedBreak, maskedBreak
			case 't':
				b[j-1], b[j] = maskedTab, maskedTab
			}
		}
		i = j - 1
	}
	return string(b)
}

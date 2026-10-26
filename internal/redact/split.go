package redact

import (
	"strings"
)

// Tokens split across JSON strings: a vendor token whose first part ends one string and whose
// rest starts the next one (["ghp_abc", "def…"], {"ghp_abc": "def…"}). Each string is redacted
// on its own, so neither part matches a rule; the boundary of two adjacent strings is matched
// again over a window that joins them.

// ContinuationMarker replaces the part of a split token that lies in the second string. The
// first part is replaced by the replacement of the whole token (see Finding), so restoring a
// text puts the token's value in place of the first marker and drops this one.
const ContinuationMarker = markerPrefix + "continued]"

// splitWindow bounds how much of each string, back from the end of the first and on from the
// start of the second, the boundary window holds.
const splitWindow = 256

// isSplitByte reports whether c can be part of a token of a split rule; a token split across
// two strings ends the first and starts the second with such bytes.
func isSplitByte(c byte) bool {
	return isTokenByte(c) || c == '.' || c == '/' || c == ':'
}

// splitNeedles maps the first two bytes of each prefilter word of the split rules to the words,
// so that a window is searched for them without lower-casing it.
var splitNeedles = func() map[uint16][]string {
	needles := map[uint16][]string{}
	for _, r := range allRules() {
		for _, word := range r.prefilter {
			if r.split && len(word) >= 2 {
				pair := uint16(word[0])<<8 | uint16(word[1])
				needles[pair] = append(needles[pair], word)
			}
		}
	}
	return needles
}()

// lowerASCII lower-cases an ASCII letter.
func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// maySplit is the cheap check of a window that joins a and b: whether it holds, in any letter
// case, a prefilter word of a split rule, or a digit followed by a colon (a Telegram bot token,
// the split rule with a precheck instead).
func maySplit[B string | []byte](a string, b B) bool {
	at := func(i int) byte {
		if i < len(a) {
			return a[i]
		}
		return b[i-len(a)]
	}
	n := len(a) + len(b)
	for i := 0; i+1 < n; i++ {
		c, d := at(i), at(i+1)
		if d == ':' && c >= '0' && c <= '9' {
			return true
		}
		words := splitNeedles[uint16(lowerASCII(c))<<8|uint16(lowerASCII(d))]
		for _, word := range words {
			if i+len(word) > n {
				continue
			}
			k := 2
			for k < len(word) && lowerASCII(at(i+k)) == word[k] {
				k++
			}
			if k == len(word) {
				return true
			}
		}
	}
	return false
}

// splitCut is a token split across two strings: it starts at tail in the first one and ends at
// head in the second, and value is the whole token.
type splitCut struct {
	tail, head int
	kind       string
	value      string
}

// splitLeft returns where the window of a split token starts in a: at the start of the run of
// splitBytes that ends a, but at most splitWindow bytes back and not before from.
func splitLeft(a string, from int) int {
	left := len(a)
	for left > from && len(a)-left < splitWindow && isSplitByte(a[left-1]) {
		left--
	}
	return left
}

// splitToken looks for a match of a split rule that starts in a, at or after from, and ends in
// b, over a window that joins the run of splitBytes ending a (at most splitWindow bytes of it)
// to the run starting b (as much). A match that reaches the edge of a window cut short goes on
// over the rest of the run, so no part of the token stays visible. The caller has checked the
// window with maySplit.
func (e *Engine) splitToken(a string, from int, b string) (splitCut, bool) {
	if len(a) <= from || b == "" || !isSplitByte(a[len(a)-1]) || !isSplitByte(b[0]) {
		return splitCut{}, false
	}
	left := splitLeft(a, from)
	right := 0
	for right < len(b) && right < splitWindow && isSplitByte(b[right]) {
		right++
	}
	window := a[left:] + b[:right]
	boundary := len(a) - left
	for _, s := range e.splitSpans(window) {
		if s.start >= boundary || s.end <= boundary {
			continue
		}
		// A token that is whole at the end of a ({"<token>": "repo"}) is found there; a rule
		// that runs on into b only took b's start along.
		for _, whole := range e.splitSpans(a[left:]) {
			if whole.end == boundary && whole.start <= s.start {
				return splitCut{}, false
			}
		}
		tail, head := left+s.start, s.end-boundary
		if s.start == 0 {
			for tail > from && isSplitByte(a[tail-1]) {
				tail--
			}
		}
		if s.end == len(window) {
			for head < len(b) && isSplitByte(b[head]) {
				head++
			}
		}
		return splitCut{tail: tail, head: head, kind: s.kind, value: a[tail:] + b[:head]}, true
	}
	return splitCut{}, false
}

// splitSpans returns the findings of the split rules in text.
func (e *Engine) splitSpans(text string) []span {
	lowered := strings.ToLower(text)
	var spans []span
	for _, r := range e.rules {
		if !r.split || (len(r.prefilter) > 0 && !containsAny(lowered, r.prefilter)) || (r.precheck != nil && !r.precheck(text)) {
			continue
		}
		spans = mergeSpans(spans, e.ruleSpans(r, text))
	}
	return spans
}

// cuts are the parts of one string that belong to split tokens: text[:head] ends a token of
// the string before (head 0 for none), and text[tail.tail:] starts one that goes on in the next
// string (tail nil for none).
type cuts struct {
	head int
	tail *splitCut
}

func (c cuts) none() bool { return c.head == 0 && c.tail == nil }

// redactCut redacts text, which holds split tokens as c says: the part that ends a token is
// replaced by ContinuationMarker, the part that starts one by the replacement of the whole token,
// and the rest as usual, with findings that overlap a part cut back to what lies outside it.
// secretKind is set when text is a value under a secret member: the rest is then replaced as a
// whole, and when a token starts in it, together with that token.
func (e *Engine) redactCut(secretKind, text string, c cuts, r Replacer) string {
	end := len(text)
	if c.tail != nil {
		end = c.tail.tail
	}
	var b strings.Builder
	if c.head > 0 {
		b.WriteString(ContinuationMarker)
	}
	if secretKind != "" && !e.disabled[secretKind] {
		switch {
		case c.tail != nil:
			b.WriteString(r.Replace(Finding{Kind: secretKind, Value: text[c.head:end] + c.tail.value}))
		case c.head < len(text):
			b.WriteString(r.Replace(Finding{Kind: secretKind, Value: text[c.head:]}))
		}
		return b.String()
	}
	last := c.head
	for _, s := range e.Find(text) {
		start, stop := max(s.Start, c.head), min(s.End, end)
		if start >= stop {
			continue
		}
		value := s.Finding.Value
		if start != s.Start || stop != s.End {
			value = text[start:stop]
		}
		b.WriteString(text[last:start])
		b.WriteString(r.Replace(Finding{Kind: s.Finding.Kind, Value: value}))
		last = stop
	}
	b.WriteString(text[last:end])
	if c.tail != nil {
		b.WriteString(r.Replace(Finding{Kind: c.tail.kind, Value: c.tail.value}))
	}
	return b.String()
}

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
// so that a window is searched for them without lower-casing it; splitPairs holds the same
// pairs as a bit set, which rules out most positions without a map lookup.
var splitNeedles, splitPairs = func() (map[uint16][]string, *[1 << 16 / 64]uint64) {
	needles := map[uint16][]string{}
	var pairs [1 << 16 / 64]uint64
	for _, r := range allRules() {
		for _, word := range r.prefilter {
			if r.split && len(word) >= 2 {
				pair := uint16(word[0])<<8 | uint16(word[1])
				needles[pair] = append(needles[pair], word)
				pairs[pair/64] |= 1 << (pair % 64)
			}
		}
	}
	return needles, &pairs
}()

// lowerASCII lower-cases an ASCII letter.
func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// telegramTokenRun is the number of token bytes after the colon of a Telegram bot token, as
// hasDigitColonRun checks it.
const telegramTokenRun = 35

// maySplitReach is how far into b a prefilter word of a token that starts in a can begin: after
// the digits of a Telegram bot token (at most 16), or after "sk_" or "https://".
const maySplitReach = 16

// maySplit is the cheap check of a window that joins a and b: whether it holds, in any letter
// case and starting in a or at most maySplitReach bytes into b, a prefilter word of a split rule,
// or a digit, a colon and telegramTokenRun token bytes (a Telegram bot token, the split rule with
// a precheck instead).
func maySplit[B string | []byte](a string, b B) bool {
	at := func(i int) byte {
		if i < len(a) {
			return a[i]
		}
		return b[i-len(a)]
	}
	n := len(a) + len(b)
	end := min(n-1, len(a)+maySplitReach)
	for i := range end {
		c := at(i)
		starts := splitStarts[c]
		if starts == 0 {
			continue
		}
		d := at(i + 1)
		if starts&startsDigit != 0 && d == ':' {
			run := 0
			for j := i + 2; j < n && isTokenByte(at(j)); j++ {
				run++
			}
			if run >= telegramTokenRun {
				return true
			}
		}
		if starts&startsWord == 0 {
			continue
		}
		pair := uint16(lowerASCII(c))<<8 | uint16(lowerASCII(d))
		if splitPairs[pair/64]&(1<<(pair%64)) == 0 {
			continue
		}
		for _, word := range splitNeedles[pair] {
			k := 2
			for k < len(word) && i+k < n && lowerASCII(at(i+k)) == word[k] {
				k++
			}
			if k == len(word) {
				return true
			}
		}
	}
	return false
}

// splitStarts marks, for each byte, whether it is a digit (it may start the digits of a Telegram
// bot token) or starts a prefilter word of a split rule in either letter case.
var splitStarts = func() *[256]uint8 {
	var starts [256]uint8
	for c := '0'; c <= '9'; c++ {
		starts[c] |= startsDigit
	}
	for pair := range splitNeedles {
		c := byte(pair >> 8)
		starts[c] |= startsWord
		if c >= 'a' && c <= 'z' {
			starts[c-'a'+'A'] |= startsWord
		}
	}
	return &starts
}()

const (
	startsDigit uint8 = 1 << iota
	startsWord
)

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
// over the rest of the run, so no part of the token stays visible. The caller has checked the window with maySplit.
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
		// A whole token that ends a ({"<token>": "repo"}, ["<token>", "general"]) is found
		// there, and a rule that runs on into b only took b's start along; it is joined only
		// when that start looks like the random rest of a token, since a part long enough to
		// match on its own may still be only the start of a longer one.
		if !randomTail(b[:min(s.end-boundary, len(b))]) {
			for _, whole := range e.splitSpans(a[left:]) {
				if whole.end == boundary && whole.start <= s.start {
					return splitCut{}, false
				}
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

// minRandomTail is the length from which the start of a string can be the random rest of a
// token that already matches whole before it.
const minRandomTail = 8

// randomTail reports whether s looks like the random rest of a token: at least minRandomTail
// bytes, with upper-case letters, lower-case letters and digits.
func randomTail(s string) bool {
	var upper, lower, digit bool
	for i := range len(s) {
		c := s[i]
		upper = upper || c >= 'A' && c <= 'Z'
		lower = lower || c >= 'a' && c <= 'z'
		digit = digit || c >= '0' && c <= '9'
	}
	return len(s) >= minRandomTail && upper && lower && digit
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

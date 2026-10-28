package toolpins

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// fieldOrder is the order the fields of a definition are shown in; others follow, sorted.
var fieldOrder = []string{"name", "title", "description", "inputSchema", "outputSchema", "annotations", "icons", "_meta"}

// maxDiffLines bounds the lines of one field compared line by line; a longer field is shown as
// removed and added whole.
const maxDiffLines = 4000

// WriteDiff writes what differs between two definitions of a tool, field by field: each field
// that differs is named, then its lines, removed ones marked "-", added ones "+" and the others
// indented. A string field is shown as its text, any other as indented JSON. old is nil for an
// added tool.
func WriteDiff(w io.Writer, old, cur json.RawMessage) error {
	a, err := fields(old)
	if err != nil {
		return err
	}
	b, err := fields(cur)
	if err != nil {
		return err
	}
	names := slices.Collect(maps.Keys(a))
	for k := range b {
		if _, ok := a[k]; !ok {
			names = append(names, k)
		}
	}
	slices.SortFunc(names, func(x, y string) int {
		ix, iy := slices.Index(fieldOrder, x), slices.Index(fieldOrder, y)
		switch {
		case ix >= 0 && iy >= 0:
			return ix - iy
		case ix >= 0:
			return -1
		case iy >= 0:
			return 1
		}
		return strings.Compare(x, y)
	})
	for _, name := range names {
		va, vb := a[name], b[name]
		if bytes.Equal(va, vb) {
			continue
		}
		if _, err := fmt.Fprintf(w, "  %s:\n", name); err != nil {
			return err
		}
		for _, l := range diffLines(show(va), show(vb)) {
			if _, err := fmt.Fprintf(w, "    %c %s\n", l.mark, Visible(l.text)); err != nil {
				return err
			}
		}
	}
	return nil
}

// fields returns the top-level fields of a definition; none for nil.
func fields(def json.RawMessage) (map[string]json.RawMessage, error) {
	out := map[string]json.RawMessage{}
	if def == nil {
		return out, nil
	}
	if err := json.Unmarshal(def, &out); err != nil {
		return nil, fmt.Errorf("a definition is not a JSON object: %w", err)
	}
	return out, nil
}

// show returns the lines of a field's value: a string's text, other JSON indented, nothing for
// an absent field.
func show(v json.RawMessage) []string {
	if v == nil {
		return nil
	}
	var s string
	if json.Unmarshal(v, &s) == nil {
		return strings.Split(s, "\n")
	}
	var buf bytes.Buffer
	if json.Indent(&buf, v, "", "  ") != nil {
		return []string{string(v)}
	}
	return strings.Split(buf.String(), "\n")
}

// Visible returns a line with every character that a terminal does not show as itself written
// as \u{XXXX}: controls such as an escape sequence, format characters such as a bidirectional
// override or an invisible tag character, variation selectors and other default-ignorable code
// points, line and paragraph separators, and the blank letters that render as nothing (U+034F,
// U+115F, U+1160, U+2800, U+3164, U+FFA0). A definition thus cannot hide text from the terminal
// it is shown on.
//
// A backslash that starts "u{" is written as \u{005C} too, so that text that reads like an escape
// cannot be taken for one: every \u{XXXX} in the result is an escape.
func Visible(s string) string {
	var b strings.Builder
	for i, r := range s {
		if r != '\t' && hidden(r) || r == '\\' && strings.HasPrefix(s[i+1:], "u{") {
			fmt.Fprintf(&b, "\\u{%04X}", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// blanks are letters that render as nothing.
var blanks = []rune{0x034F, 0x115F, 0x1160, 0x2800, 0x3164, 0xFFA0}

// hidden reports whether a terminal does not show r as itself.
func hidden(r rune) bool {
	return r == utf8.RuneError || unicode.IsControl(r) ||
		unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Variation_Selector, unicode.Other_Default_Ignorable_Code_Point) ||
		slices.Contains(blanks, r)
}

// line is one line of a diff.
type line struct {
	mark byte // ' ', '-' or '+'
	text string
}

// diffLines returns a line diff of a and b, from their longest common subsequence.
func diffLines(a, b []string) []line {
	var out []line
	if len(a) > maxDiffLines || len(b) > maxDiffLines {
		for _, s := range a {
			out = append(out, line{'-', s})
		}
		for _, s := range b {
			out = append(out, line{'+', s})
		}
		return out
	}
	// lcs[i][j] is the length of the longest common subsequence of a[i:] and b[j:].
	lcs := make([][]int, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			out = append(out, line{' ', a[i]})
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			out = append(out, line{'-', a[i]})
			i++
		default:
			out = append(out, line{'+', b[j]})
			j++
		}
	}
	for ; i < len(a); i++ {
		out = append(out, line{'-', a[i]})
	}
	for ; j < len(b); j++ {
		out = append(out, line{'+', b[j]})
	}
	return out
}

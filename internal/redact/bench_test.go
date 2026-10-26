package redact

import (
	"fmt"
	"strings"
	"testing"
)

// messageList is a large JSON chat history without secrets, the common case.
func messageList(n int) string {
	var sb strings.Builder
	sb.WriteString(`{"messages":[`)
	for i := range n {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `{"id":%d,"sender":"user %d","date":"2026-10-14T10:00:00Z","text":"ordinary message number %d, see https://example.com/x/%d"}`, i, i, i, i)
	}
	sb.WriteString(`]}`)
	return sb.String()
}

func benchmarkRedactString(b *testing.B, opts Options, text string) {
	e := newEngine(b, opts)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	for b.Loop() {
		_ = e.RedactString(text, Marker{})
	}
}

func BenchmarkRedactLargeMessageList(b *testing.B) {
	benchmarkRedactString(b, Options{Russian: true, HighEntropy: true}, messageList(5000))
}

func BenchmarkRedactPlainText(b *testing.B) {
	text := strings.Repeat("An ordinary line of log output, nothing to see here. ", 2000)
	benchmarkRedactString(b, Options{Russian: true, HighEntropy: true}, text)
}

func BenchmarkRedactManySecrets(b *testing.B) {
	text := strings.Repeat("password: hunter2secret\nAKIAABCDEFGHIJKLMNOP\nпароль: Qwerty-123\n", 2000)
	benchmarkRedactString(b, Options{Russian: true, HighEntropy: true}, text)
}

// BenchmarkRedactValuesOnNextLines is YAML with keys whose values are on the next line, so that
// the next-line key-value rule runs over the whole text.
func BenchmarkRedactValuesOnNextLines(b *testing.B) {
	text := strings.Repeat("service:\n  password:\n    hunter2secret\n  user: alice\n  note: ordinary text here\n", 2000)
	benchmarkRedactString(b, Options{Russian: true, HighEntropy: true}, text)
}

// The next-line key-value rule on text that is full of line breaks, key lines or long lines but
// has few values on next lines.
func BenchmarkRedactNextLineEdgeCases(b *testing.B) {
	for name, text := range map[string]string{
		"Newlines":             strings.Repeat("\n", 1<<20) + "token: x",
		"KeyLines":             strings.Repeat("token:\n", 150000),
		"KeyValues":            strings.Repeat("token:\nabcdefgh12\n", 60000),
		"PythonCode":           strings.Repeat("    if not token:\n        return None\n    x = token.split()\n", 20000),
		"LongKeyLine":          strings.Repeat("x", 1<<20) + " token:\n" + strings.Repeat("y", 1<<20),
		"KeyLinesLongNextLine": strings.Repeat("token:\n", 1000) + strings.Repeat("z", 1<<20),
		"RussianKeyLines":      strings.Repeat("пароль:\nQwerty-123\nтокен:\nимя: бот\n", 30000),
	} {
		b.Run(name, func(b *testing.B) { benchmarkRedactString(b, Options{Russian: true, HighEntropy: true}, text) })
	}
}

func BenchmarkRedactCoreRulesOnly(b *testing.B) {
	benchmarkRedactString(b, Options{}, messageList(5000))
}

// BenchmarkRedactJSONStringBoundaries is a JSON document of many short adjacent strings that end
// and start with token characters, so that each boundary is checked for a split token.
func BenchmarkRedactJSONStringBoundaries(b *testing.B) {
	var sb strings.Builder
	sb.WriteString(`{"ids":[`)
	for i := range 20000 {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `"item-%d-abc","user_%d"`, i, i)
	}
	sb.WriteString(`]}`)
	benchmarkRedactString(b, Options{Russian: true, HighEntropy: true}, sb.String())
}

// BenchmarkRedactSecretMemberNames is a list of secret objects whose members are a mix of
// identifiers and names that are values.
func BenchmarkRedactSecretMemberNames(b *testing.B) {
	var sb strings.Builder
	sb.WriteString(`[`)
	for i := range 5000 {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `{"credentials":{"type":"basic","enabled":true,"user%d":true,"expires_in":3600}}`, i)
	}
	sb.WriteString(`]`)
	benchmarkRedactString(b, Options{Russian: true, HighEntropy: true}, sb.String())
}

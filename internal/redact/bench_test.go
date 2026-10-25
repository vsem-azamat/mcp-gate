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

func BenchmarkRedactCoreRulesOnly(b *testing.B) {
	benchmarkRedactString(b, Options{}, messageList(5000))
}

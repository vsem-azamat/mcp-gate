package mcpredact

import (
	"fmt"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/redact"
)

func BenchmarkCallToolResult(b *testing.B) {
	var sb strings.Builder
	sb.WriteString(`{"messages":[`)
	for i := range 2000 {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `{"id":%d,"text":"ordinary message number %d"}`, i, i)
	}
	sb.WriteString(`]}`)
	structured := map[string]any{"items": []any{map[string]any{"id": 1.0, "token": "abc-123-def"}, "plain"}}
	res := &mcp.CallToolResult{
		Content:           []mcp.Content{&mcp.TextContent{Text: sb.String()}},
		StructuredContent: structured,
		Meta:              mcp.Meta{"k": "v"},
	}
	r := newRedactor(b, 0)
	b.SetBytes(int64(sb.Len()))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := r.CallToolResult(res, redact.Marker{}); err != nil {
			b.Fatal(err)
		}
	}
}

package compare

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func tool(name string, schema string) *mcp.Tool {
	return &mcp.Tool{Name: name, InputSchema: json.RawMessage(schema)}
}

func diffStrings(t *testing.T, a, b Catalog) []string {
	t.Helper()
	diffs, err := Diff(a, b)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(diffs))
	for _, d := range diffs {
		out = append(out, d.String())
	}
	return out
}

func TestDiff(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		a, b Catalog
		want []string
	}{
		{
			name: "identical",
			a:    Catalog{Tools: []*mcp.Tool{tool("search", `{"type":"object"}`)}},
			b:    Catalog{Tools: []*mcp.Tool{tool("search", `{"type":"object"}`)}},
		},
		{
			name: "key order and whitespace do not count",
			a:    Catalog{Tools: []*mcp.Tool{tool("search", `{"type":"object","properties":{"q":{"type":"string"}}}`)}},
			b:    Catalog{Tools: []*mcp.Tool{tool("search", `{ "properties": {"q": {"type": "string"}}, "type": "object" }`)}},
		},
		{
			name: "list order does not count",
			a:    Catalog{Tools: []*mcp.Tool{tool("a", `{}`), tool("b", `{}`)}},
			b:    Catalog{Tools: []*mcp.Tool{tool("b", `{}`), tool("a", `{}`)}},
		},
		{
			name: "schema drift",
			a:    Catalog{Tools: []*mcp.Tool{tool("search", `{"type":"object","properties":{"q":{"type":"string"}}}`)}},
			b:    Catalog{Tools: []*mcp.Tool{tool("search", `{"type":"object"}`)}},
			want: []string{`tool "search": inputSchema differs
  a: {"properties":{"q":{"type":"string"}},"type":"object"}
  b: {"type":"object"}`},
		},
		{
			name: "numbers compared as the SDK decodes them",
			a:    Catalog{Tools: []*mcp.Tool{{Name: "t", InputSchema: map[string]any{"maximum": 10.0}}}},
			b:    Catalog{Tools: []*mcp.Tool{{Name: "t", InputSchema: map[string]any{"maximum": 10.5}}}},
			want: []string{"tool \"t\": inputSchema differs\n  a: {\"maximum\":10}\n  b: {\"maximum\":10.5}"},
		},
		{
			name: "absent field",
			a: Catalog{Tools: []*mcp.Tool{{
				Name: "t", InputSchema: json.RawMessage(`{}`),
				Annotations: &mcp.ToolAnnotations{Title: "T"},
			}}},
			b:    Catalog{Tools: []*mcp.Tool{tool("t", `{}`)}},
			want: []string{"tool \"t\": annotations differs\n  a: {\"idempotentHint\":false,\"readOnlyHint\":false,\"title\":\"T\"}\n  b: (absent)"},
		},
		{
			name: "meta is compared",
			a:    Catalog{Prompts: []*mcp.Prompt{{Name: "p", Meta: mcp.Meta{"x": 1}}}},
			b:    Catalog{Prompts: []*mcp.Prompt{{Name: "p"}}},
			want: []string{"prompt \"p\": _meta differs\n  a: {\"x\":1}\n  b: (absent)"},
		},
		{
			name: "only in one source",
			a: Catalog{
				Resources:         []*mcp.Resource{{URI: "file:///a", Name: "a"}},
				ResourceTemplates: []*mcp.ResourceTemplate{{URITemplate: "file:///{x}", Name: "x"}},
			},
			b: Catalog{Resources: []*mcp.Resource{{URI: "file:///b", Name: "b"}}},
			want: []string{
				`resource "file:///a": only in a`,
				`resource "file:///b": only in b`,
				`resource template "file:///{x}": only in a`,
			},
		},
		{
			name: "duplicates",
			a:    Catalog{Tools: []*mcp.Tool{tool("t", `{}`), tool("t", `{}`)}},
			b:    Catalog{Tools: []*mcp.Tool{tool("t", `{}`)}},
			want: []string{`tool "t": listed more than once in a`},
		},
		{
			name: "html characters are not escaped",
			a:    Catalog{Tools: []*mcp.Tool{{Name: "t", Description: "a < b", InputSchema: json.RawMessage(`{}`)}}},
			b:    Catalog{Tools: []*mcp.Tool{{Name: "t", Description: "a > b", InputSchema: json.RawMessage(`{}`)}}},
			want: []string{"tool \"t\": description differs\n  a: \"a < b\"\n  b: \"a > b\""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := diffStrings(t, tt.a, tt.b)
			if strings.Join(got, "\n---\n") != strings.Join(tt.want, "\n---\n") {
				t.Errorf("differences:\n%s\nwant:\n%s", strings.Join(got, "\n---\n"), strings.Join(tt.want, "\n---\n"))
			}
		})
	}
}

func TestCounts(t *testing.T) {
	t.Parallel()
	c := Catalog{Tools: []*mcp.Tool{tool("a", `{}`), tool("b", `{}`)}, Prompts: []*mcp.Prompt{{Name: "p"}}}
	if got, want := c.Counts(), "2 tools, 1 prompt, 0 resources, 0 resource templates"; got != want {
		t.Errorf("Counts() = %q, want %q", got, want)
	}
}

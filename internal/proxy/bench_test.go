package proxy

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/audit"
	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/policy"
	"github.com/vsem-azamat/mcp-gate/internal/redact"
)

// benchDown is served by an in-memory MCP server whose tool "echo" returns its text argument.
func benchDown(b *testing.B) *sessionDown {
	b.Helper()
	server := mcp.NewServer(&mcp.Implementation{Name: "fake", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{Name: "echo", InputSchema: map[string]any{"type": "object"}},
		func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var args struct{ Text string }
			_ = json.Unmarshal(req.Params.Arguments, &args)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: args.Text}}}, nil
		})
	ct, st := mcp.NewInMemoryTransports()
	ss, err := server.Connect(b.Context(), st, nil)
	if err != nil {
		b.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "1"}, nil).Connect(b.Context(), ct, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = cs.Close(); _ = ss.Close() })
	return &sessionDown{cs: cs}
}

// nowhere takes the log lines of a benchmark, which are formatted as for real.
type nowhere struct{}

func (nowhere) Write(p []byte) (int, error) { return len(p), nil }

// benchMirror returns a mirror with redaction on and audit lines written as JSON to nowhere.
func benchMirror(b *testing.B, down sessionRunner, filter *config.Filter) *Mirror {
	b.Helper()
	engine, err := redact.New(redact.Options{})
	if err != nil {
		b.Fatal(err)
	}
	return newMirror(Options{
		Name: "s", Policy: policy.New(&config.Server{Tools: filter}), Redaction: NewRedaction(engine, nil, 1<<20),
		Logger: slog.New(slog.NewJSONHandler(nowhere{}, nil)),
	}, down)
}

// BenchmarkCallTool is the whole call path of a forwarded tool call: the checks, the forward
// over an in-memory session, redaction of the result and the audit line.
func BenchmarkCallTool(b *testing.B) {
	m := benchMirror(b, benchDown(b), nil)
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "echo", Arguments: json.RawMessage(`{"text":"hello, world"}`)}}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := m.callTool(b.Context(), req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCallToolDenied is a call the server's filter refuses: the checks and the audit line.
func BenchmarkCallToolDenied(b *testing.B) {
	m := benchMirror(b, stubDown{}, &config.Filter{Deny: []string{"echo"}})
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "echo"}}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := m.callTool(b.Context(), req); err == nil {
			b.Fatal("not denied")
		}
	}
}

// BenchmarkCallToolPipeline is the pipeline alone: a tool call answered by a fake supervisor
// without any session, with redaction and the audit line.
func BenchmarkCallToolPipeline(b *testing.B) {
	engine, err := redact.New(redact.Options{})
	if err != nil {
		b.Fatal(err)
	}
	down := &fakeDown{tool: textResult("hello, world")}
	m, _ := fakeMirror(Options{Redaction: NewRedaction(engine, nil, 1<<20)}, down)
	m.audit = audit.Log(slog.New(slog.NewJSONHandler(nowhere{}, nil)))
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "echo", Arguments: json.RawMessage(`{"text":"hello, world"}`)}}
	b.ReportAllocs()
	for b.Loop() {
		down.tools = down.tools[:0]
		if _, err := m.callTool(b.Context(), req); err != nil {
			b.Fatal(err)
		}
	}
}

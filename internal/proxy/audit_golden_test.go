package proxy

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/downstream"
	"github.com/vsem-azamat/mcp-gate/internal/policy"
	"github.com/vsem-azamat/mcp-gate/internal/redact"
)

// failingDown answers every call with err.
type failingDown struct {
	stubDown
	err error
}

func (d failingDown) Call(context.Context, func(context.Context, *mcp.ClientSession) error) error {
	return d.err
}

// bigDown is served by an in-memory MCP server whose tool "big" returns a long text.
func bigDown(t *testing.T) *sessionDown {
	t.Helper()
	server := mcp.NewServer(&mcp.Implementation{Name: "fake", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{Name: "big", InputSchema: map[string]any{"type": "object"}},
		func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Repeat("x", 64)}}}, nil
		})
	ct, st := mcp.NewInMemoryTransports()
	ss, err := server.Connect(t.Context(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "1"}, nil).Connect(t.Context(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close(); _ = ss.Close() })
	return &sessionDown{cs: cs}
}

// TestAuditOutcomesGolden pins the exact audit lines of the outcomes the gate's own tests do not
// reach: a server without a session, a failed call, and a result that cannot be redacted.
func TestAuditOutcomesGolden(t *testing.T) {
	var logs strings.Builder
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			switch a.Key {
			case slog.TimeKey:
				return slog.Attr{}
			case "durMs":
				return slog.Int64("durMs", 0)
			}
			return a
		},
	}))
	engine, err := redact.New(redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	mirror := func(down Downstream, r *Redaction) *Mirror {
		return newMirror(Options{Name: "s", Policy: policy.New(&config.Server{}), Logger: logger, Redaction: r}, down)
	}
	call := func(m *Mirror, name string) {
		_, _ = m.callTool(t.Context(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: name}})
	}
	call(mirror(failingDown{err: &downstream.NotReadyError{Name: "s", State: downstream.Backoff}}, nil), "a")
	call(mirror(failingDown{err: errors.New("boom")}, nil), "a")
	call(mirror(bigDown(t), NewRedaction(engine, nil, 8)), "big")
	m := mirror(failingDown{err: errors.New("boom")}, nil)
	_, _ = m.getPrompt(t.Context(), &mcp.GetPromptRequest{Params: &mcp.GetPromptParams{Name: "p"}})
	_, _ = m.readResource(t.Context(), &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{URI: "x://y"}})

	var got []string
	for line := range strings.SplitSeq(logs.String(), "\n") {
		if strings.Contains(line, `"msg":"call"`) {
			got = append(got, line)
		}
	}
	want := []string{
		`{"level":"INFO","msg":"call","server":"s","principal":"","method":"tools/call","tool":"a","durMs":0,"outcome":"unavailable","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"s","principal":"","method":"tools/call","tool":"a","durMs":0,"outcome":"error","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"s","principal":"","method":"tools/call","tool":"big","durMs":0,"outcome":"withheld","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"s","principal":"","method":"prompts/get","prompt":"p","durMs":0,"outcome":"error","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"s","principal":"","method":"resources/read","uri":"x://y","durMs":0,"outcome":"error","tokenPolicy":"none","redactions":0}`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("audit lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !strings.Contains(logs.String(), `"msg":"result withheld`) {
		t.Errorf("no withheld warning: %s", logs.String())
	}
}

// TestCallCounters checks the counters /_status reports: every audited request is a call, and
// every one whose outcome is neither ok nor tool_error a failed one.
func TestCallCounters(t *testing.T) {
	m := newMirror(Options{Name: "s", Policy: policy.New(&config.Server{Tools: &config.Filter{Deny: []string{"env"}}})}, newSessionDown(t))
	for _, name := range []string{"a", "a", "env"} {
		_, _ = m.callTool(t.Context(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: name}})
	}
	refuses := m.receive(func(context.Context, string, mcp.Request) (mcp.Result, error) { return nil, errors.New("unknown tool") })
	_, _ = refuses(t.Context(), "tools/call", &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "missing"}})
	if st := m.Stats(); st.Calls != 4 || st.Failed != 2 {
		t.Errorf("calls %d, failed %d; want 4 and 2", st.Calls, st.Failed)
	}
}

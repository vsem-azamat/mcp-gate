package proxy

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

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
	mirror := func(down sessionRunner, r *Redaction) *Mirror {
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

// fullDown is served by an in-memory MCP server with a tool, a prompt and a resource of each
// shape a result can take: plain, a tool error, asking for input, and too long to redact.
func fullDown(t *testing.T) *sessionDown {
	t.Helper()
	server := mcp.NewServer(&mcp.Implementation{Name: "fake", Version: "1"}, nil)
	long := strings.Repeat("x", 4096)
	for name, res := range map[string]*mcp.CallToolResult{
		"ok":    {Content: []mcp.Content{&mcp.TextContent{Text: "fine"}}},
		"fails": {IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "no"}}},
		"asks":  {RequestState: "waiting"},
	} {
		server.AddTool(&mcp.Tool{Name: name, InputSchema: map[string]any{"type": "object"}},
			func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) { return res, nil })
	}
	for name, res := range map[string]*mcp.GetPromptResult{
		"p":     {Messages: []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: "fine"}}}},
		"pasks": {RequestState: "waiting"},
		"pbig":  {Messages: []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: long}}}},
	} {
		server.AddPrompt(&mcp.Prompt{Name: name}, func(context.Context, *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) { return res, nil })
	}
	read := func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		switch req.Params.URI {
		case "x://asks":
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, Text: "?"}}, RequestState: "waiting"}, nil
		case "x://big":
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, Text: long}}}, nil
		}
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, Text: "fine"}}}, nil
	}
	for _, uri := range []string{"x://ok", "x://asks", "x://big"} {
		server.AddResource(&mcp.Resource{URI: uri, Name: uri}, read)
	}
	server.AddResourceTemplate(&mcp.ResourceTemplate{URITemplate: "t://{id}", Name: "items"}, read)
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

// failingScanner fails every scan.
type failingScanner struct{}

func (failingScanner) Scan(context.Context, string, func() map[string]any, *mcp.CallToolResult, time.Time) (*mcp.CallToolResult, int, error) {
	return nil, 0, errors.New("unreadable")
}

// TestAuditMoreOutcomesGolden pins the exact audit lines of the remaining outcomes of each kind,
// the refusals the mirror and the aggregate make before or instead of a forward, and an
// aggregate line with joined token names.
func TestAuditMoreOutcomesGolden(t *testing.T) {
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
	// A mirror of fullDown, listed, whose filter hides the template "items".
	src := NewSource("s", logger)
	src.Attach(onSession{fullDown(t)})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	src.Start(ctx)
	defer src.Close()
	src.OnSession(nil) // as a new session does: list everything
	m := New(Options{
		Name: "s", Policy: policy.New(&config.Server{Resources: &config.Filter{Deny: []string{"items"}}}), Logger: logger,
		Redaction: NewRedaction(engine, nil, 1024), Source: src,
	})
	for deadline := time.Now().Add(10 * time.Second); !m.Ready() || len(catalogOf(m).Resources) < 3; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the catalog was not listed")
		}
	}
	tool := func(m *Mirror, ctx context.Context, name string) {
		_, _ = m.callTool(ctx, &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: name}})
	}
	prompt := func(m *Mirror, name string) {
		_, _ = m.getPrompt(t.Context(), &mcp.GetPromptRequest{Params: &mcp.GetPromptParams{Name: name}})
	}
	read := func(m *Mirror, uri string) {
		_, _ = m.readResource(t.Context(), &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{URI: uri}})
	}
	tool(m, t.Context(), "fails") // tool_error
	tool(m, t.Context(), "asks")  // input_required
	prompt(m, "pasks")
	read(m, "x://asks")
	prompt(m, "pbig") // withheld
	read(m, "x://big")
	read(m, "t://1") // the server's filter hides the template
	notReady := failingDown{err: &downstream.NotReadyError{Name: "s", State: downstream.Starting}}
	down := newMirror(Options{Name: "s", Policy: policy.New(&config.Server{}), Logger: logger}, notReady)
	prompt(down, "p") // unavailable
	read(down, "x://ok")
	timeout := newMirror(Options{Name: "s", Policy: policy.New(&config.Server{}), Logger: logger}, failingDown{err: context.DeadlineExceeded})
	tool(timeout, t.Context(), "ok") // error: no answer in time
	gone, stop := context.WithCancel(t.Context())
	stop()
	cancelled := newMirror(Options{Name: "s", Policy: policy.New(&config.Server{}), Logger: logger}, failingDown{err: context.Canceled})
	tool(cancelled, gone, "ok") // error: the client has gone
	scans := newMirror(Options{
		Name: "s", Policy: policy.New(&config.Server{}), Logger: logger, Redaction: NewRedaction(engine, nil, 1<<20), Files: failingScanner{},
	}, fullDown(t))
	tool(scans, t.Context(), "ok") // withheld: the scan failed
	// The SDK refuses a call of a tool the mirror holds: an error, not a denial.
	refuses := m.receive(func(context.Context, string, mcp.Request) (mcp.Result, error) {
		return nil, errors.New("invalid params")
	})
	_, _ = refuses(t.Context(), "tools/call", &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "ok"}})

	agg, err := NewAggregate(AggregateOptions{Members: []*Mirror{m}, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	v := agg.View([]string{"s"}, nil)
	access := &mcp.RequestExtra{TokenInfo: AccessInfo("laptop", map[string]string{"s": "laptop"})}
	// A tool the view still lists but the mirror no longer holds: refused as hidden.
	_, _ = v.callTool("s", "gone")(t.Context(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "s__gone"}, Extra: access})
	// A prompt get the request's access does not reach: refused by the aggregate.
	noAccess := &mcp.RequestExtra{TokenInfo: AccessInfo("laptop", map[string]string{})}
	_, _ = v.getPrompt("s", "p")(t.Context(), &mcp.GetPromptRequest{Params: &mcp.GetPromptParams{Name: "s__p"}, Extra: noAccess})
	// A resource read through the view, handled by the member.
	_, _ = v.readResource(t.Context(), &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{URI: "x://ok"}, Extra: access})
	// Token names joined, on a line no member writes.
	joined := &mcp.RequestExtra{TokenInfo: AccessInfo("laptop,phone", map[string]string{})}
	_, _ = v.callTool("s", "ok")(t.Context(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "s__ok"}, Extra: joined})

	var got []string
	for line := range strings.SplitSeq(logs.String(), "\n") {
		if strings.Contains(line, `"msg":"call"`) {
			got = append(got, line)
		}
	}
	want := []string{
		`{"level":"INFO","msg":"call","server":"s","principal":"","method":"tools/call","tool":"fails","durMs":0,"outcome":"tool_error","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"s","principal":"","method":"tools/call","tool":"asks","durMs":0,"outcome":"input_required","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"s","principal":"","method":"prompts/get","prompt":"pasks","durMs":0,"outcome":"input_required","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"s","principal":"","method":"resources/read","uri":"x://asks","durMs":0,"outcome":"input_required","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"s","principal":"","method":"prompts/get","prompt":"pbig","durMs":0,"outcome":"withheld","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"s","principal":"","method":"resources/read","uri":"x://big","durMs":0,"outcome":"withheld","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"s","principal":"","method":"resources/read","uri":"t://1","durMs":0,"outcome":"denied","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"s","principal":"","method":"prompts/get","prompt":"p","durMs":0,"outcome":"unavailable","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"s","principal":"","method":"resources/read","uri":"x://ok","durMs":0,"outcome":"unavailable","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"s","principal":"","method":"tools/call","tool":"ok","durMs":0,"outcome":"error","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"s","principal":"","method":"tools/call","tool":"ok","durMs":0,"outcome":"error","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"s","principal":"","method":"tools/call","tool":"ok","durMs":0,"outcome":"withheld","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"s","principal":"","method":"tools/call","tool":"ok","durMs":0,"outcome":"error","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"s","principal":"laptop","method":"tools/call","tool":"gone","durMs":0,"outcome":"denied","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"","principal":"laptop","method":"prompts/get","prompt":"s__p","durMs":0,"outcome":"denied","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"s","principal":"laptop","method":"resources/read","uri":"x://ok","durMs":0,"outcome":"ok","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"","principal":"laptop,phone","method":"tools/call","tool":"s__ok","durMs":0,"outcome":"denied","tokenPolicy":"none","redactions":0}`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("audit lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

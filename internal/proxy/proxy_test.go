package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/policy"
	"github.com/vsem-azamat/mcp-gate/internal/redact"
)

func TestDownstreamMeta(t *testing.T) {
	in := mcp.Meta{
		"progressToken":                       "up-1",
		"example.com/trace":                   "abc",
		"plain":                               1,
		"io.modelcontextprotocol/clientInfo":  "x",
		"modelcontextprotocol.io/protocol":    "x",
		"dev.mcp/thing":                       "x",
		"mcp/thing":                           "x",
		"tools.mcp.example.com/thing":         "x",
		"mcpish.example.com/thing":            "kept",
		"example.com/modelcontextprotocolish": "kept",
	}
	if got := downstreamMeta(in, nil); got != nil {
		t.Errorf("nothing listed: %v", got)
	}
	forward := []string{"example.com/trace", "plain", "absent", "progressToken", "dev.mcp/thing"}
	got := downstreamMeta(in, forward)
	want := mcp.Meta{"example.com/trace": "abc", "plain": 1}
	if !maps.Equal(map[string]any(got), map[string]any(want)) {
		t.Errorf("downstreamMeta = %v, want %v", got, want)
	}
	if downstreamMeta(nil, forward) != nil {
		t.Error("an empty _meta is not nil")
	}
	if _, ok := in["progressToken"]; !ok {
		t.Error("the input was changed")
	}
}

func TestProgressToken(t *testing.T) {
	for _, c := range []struct {
		meta mcp.Meta
		want any
	}{
		{mcp.Meta{"progressToken": "a"}, "a"},
		{mcp.Meta{"progressToken": float64(3)}, float64(3)},
		{mcp.Meta{"progressToken": int64(3)}, int64(3)},
		{mcp.Meta{"progressToken": true}, nil},
		{mcp.Meta{"progressToken": map[string]any{}}, nil},
		{mcp.Meta{}, nil},
		{nil, nil},
	} {
		if got := progressToken(c.meta); got != c.want {
			t.Errorf("progressToken(%v) = %v, want %v", c.meta, got, c.want)
		}
	}
}

func TestCapabilities(t *testing.T) {
	caps := Capabilities(policy.New(&config.Server{}))
	if caps.Tools == nil || !caps.Tools.ListChanged || caps.Prompts == nil || caps.Resources == nil || caps.Resources.Subscribe {
		t.Errorf("no filter: %+v", caps)
	}
	if caps.Logging != nil || caps.Completions != nil { //nolint:staticcheck // the mirror must not advertise logging
		t.Errorf("no filter: %+v", caps)
	}
	none := &config.Filter{Allow: []string{}}
	caps = Capabilities(policy.New(&config.Server{Tools: none, Prompts: none, Resources: none}))
	if caps.Tools == nil || caps.Prompts != nil || caps.Resources != nil {
		t.Errorf("empty allow lists: %+v", caps)
	}
}

func TestSyncSetKeepsWhatFails(t *testing.T) {
	type entry struct{ V int }
	have := map[string]*entry{"same": {1}, "changed": {1}, "bad": {1}, "gone": {1}}
	want := map[string]*entry{"same": {1}, "changed": {2}, "bad": {2}, "new": {1}, "newbad": {9}}
	var added, removed []string
	add := func(e *entry) error {
		for k, v := range want {
			if v == e {
				if k == "bad" || k == "newbad" {
					return errors.New("rejected")
				}
				added = append(added, k)
			}
		}
		return nil
	}
	got := syncSet(slog.New(slog.DiscardHandler), func(s string) string { return s }, "test", have, want, add, func(keys ...string) { removed = append(removed, keys...) })
	slices.Sort(added)
	if !slices.Equal(added, []string{"changed", "new"}) || !slices.Equal(removed, []string{"gone"}) {
		t.Errorf("added %v, removed %v", added, removed)
	}
	if got["bad"] != have["bad"] || got["same"] != have["same"] || got["changed"] != want["changed"] {
		t.Errorf("result %v", got)
	}
	if _, ok := got["newbad"]; ok {
		t.Error("a rejected new entry is kept")
	}
	if _, ok := got["gone"]; ok {
		t.Error("a removed entry is kept")
	}
}

func TestValidTool(t *testing.T) {
	for _, c := range []struct {
		tool *mcp.Tool
		ok   bool
	}{
		{&mcp.Tool{Name: "a", InputSchema: map[string]any{"type": "object"}}, true},
		{&mcp.Tool{Name: "", InputSchema: map[string]any{"type": "object"}}, false},
		{&mcp.Tool{Name: "a", InputSchema: map[string]any{"type": "string"}}, false},
		{&mcp.Tool{Name: "a"}, false},
	} {
		if err := validTool(c.tool); (err == nil) != c.ok {
			t.Errorf("validTool(%+v) = %v", c.tool, err)
		}
	}
}

func TestQueueIsBounded(t *testing.T) {
	m := New(Options{Name: "s", Policy: policy.New(&config.Server{})})
	for range eventQueue + 5 {
		m.enqueue(event{progress: &mcp.ProgressNotificationParams{}})
	}
	if got := m.Stats().DroppedNotifications; got != 5 {
		t.Errorf("dropped %d, want 5", got)
	}
}

func TestProgressForUnknownTokenIsDropped(t *testing.T) {
	const unknown = "mcp-gate-404"
	pt := newProgressTable()
	pt.deliver(&mcp.ProgressNotificationParams{ProgressToken: unknown})
	pt.deliver(&mcp.ProgressNotificationParams{ProgressToken: 7})
	if len(pt.sinks) != 0 {
		t.Errorf("sinks %v", pt.sinks)
	}
}

func TestInvalidUpdateKeepsPrevious(t *testing.T) {
	m := New(Options{Name: "s", Policy: policy.New(&config.Server{})})
	good := &mcp.Tool{Name: "a", InputSchema: map[string]any{"type": "object"}}
	m.tools = m.applyTools([]*mcp.Tool{good})
	m.tools = m.applyTools([]*mcp.Tool{{Name: "a", InputSchema: map[string]any{"type": "string"}}})
	if m.tools["a"] != good {
		t.Errorf("tool a after an invalid update: %+v", m.tools["a"])
	}
	m.tools = m.applyTools(nil)
	if len(m.tools) != 0 {
		t.Errorf("a tool that is gone is kept: %v", m.tools)
	}
}

func TestReceiveRecoversAndAuditsRefusals(t *testing.T) {
	var logs strings.Builder
	m := New(Options{Name: "s", Policy: policy.New(&config.Server{}), Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
	panics := m.receive(func(context.Context, string, mcp.Request) (mcp.Result, error) { panic("secret-value") })
	res, err := panics(t.Context(), "tools/list", &mcp.ListToolsRequest{})
	var rpc *jsonrpc.Error
	if res != nil || !errors.As(err, &rpc) || rpc.Code != jsonrpc.CodeInternalError {
		t.Errorf("panic: %v %v", res, err)
	}
	m.Attach(stubDown{})
	refuses := m.receive(func(context.Context, string, mcp.Request) (mcp.Result, error) { return nil, errors.New("unknown tool") })
	_, _ = refuses(t.Context(), "tools/call", &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "env"}})
	out := logs.String()
	if strings.Contains(out, "secret-value") || !strings.Contains(out, `"msg":"call"`) ||
		!strings.Contains(out, `"tool":"env"`) || !strings.Contains(out, `"outcome":"denied"`) {
		t.Errorf("logs %s", out)
	}
}

type stubDown struct{}

func (stubDown) Call(context.Context, func(context.Context, *mcp.ClientSession) error) error {
	return errors.New("no session")
}

func (stubDown) ErrorText(err error) string { return err.Error() }

func (stubDown) HideURL(text string) string { return text }

// urlDown is a downstream whose URL is serverURL.
type urlDown struct{ stubDown }

const serverURL = "https://mcp.example.com/k-PATHCRED/mcp"

func (urlDown) HideURL(text string) string {
	return strings.ReplaceAll(text, serverURL, "<servers.s.http.url>")
}

func (d urlDown) ErrorText(err error) string { return d.HideURL(err.Error()) }

func TestDownstreamErrorHidesURL(t *testing.T) {
	const token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	engine, err := redact.New(redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	rejected := fmt.Errorf("calling: %w: Post %q: connection refused", &jsonrpc.Error{Code: -32005, Message: "rejected by transport"}, serverURL)
	reply := &jsonrpc.Error{
		Code: -32000, Message: "failed at " + serverURL + " with " + token,
		Data: json.RawMessage(`{"url":"` + serverURL + `","token":"` + token + `"}`),
	}
	const kept = "[REDACTED:secret #kabcdefghij]"
	escrow := NewRedaction(engine, func(Request) redact.Replacer {
		return redact.ReplacerFunc(func(redact.Finding) string { return kept })
	}, 1<<20)
	for _, c := range []struct {
		name      string
		redaction *Redaction
		err       error
		code      int64
		data      bool
		marker    string // in the message and the data
	}{
		{"transport, plain", nil, rejected, -32005, false, ""},
		{"transport, redacted", NewRedaction(engine, nil, 1<<20), rejected, -32005, false, ""},
		{"reply, plain", nil, reply, -32000, false, ""},
		{"reply, redacted", NewRedaction(engine, nil, 1<<20), reply, -32000, true, "[REDACTED:"},
		{"reply, escrow", escrow, reply, -32000, true, kept},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := New(Options{Name: "s", Policy: policy.New(&config.Server{}), Redaction: c.redaction})
			m.Attach(urlDown{})
			call := m.begin(t.Context(), "tools/call", nil)
			out := call.downstreamError(t.Context(), c.err)
			var rpc *jsonrpc.Error
			if !errors.As(out, &rpc) || rpc.Code != c.code {
				t.Fatalf("error %v, want code %d", out, c.code)
			}
			if strings.Contains(out.Error(), "PATHCRED") || strings.Contains(string(rpc.Data), "PATHCRED") {
				t.Errorf("the error quotes the URL: %q %s", out.Error(), rpc.Data)
			}
			if strings.Contains(string(rpc.Data), token) {
				t.Errorf("the data holds the token: %s", rpc.Data)
			}
			if got := len(rpc.Data) > 0; got != c.data {
				t.Errorf("data %s, want data: %v", rpc.Data, c.data)
			}
			if c.marker != "" && (!strings.Contains(rpc.Message, c.marker) || !strings.Contains(string(rpc.Data), c.marker) || strings.Contains(rpc.Message, token)) {
				t.Errorf("want %q in message and data: %q %s", c.marker, rpc.Message, rpc.Data)
			}
		})
	}
}

func TestRejectedEntryLogIsRedacted(t *testing.T) {
	const token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	engine, err := redact.New(redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var logs strings.Builder
	m := New(Options{
		Name: "s", Policy: policy.New(&config.Server{}), Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
		Redaction: NewRedaction(engine, nil, 1<<20),
	})
	m.templates = m.applyTemplates([]*mcp.ResourceTemplate{{Name: "t", URITemplate: "https://example.com/{x?token=" + token}})
	if len(m.templates) != 0 {
		t.Fatalf("the SDK took an invalid template: %v", m.templates)
	}
	if out := logs.String(); !strings.Contains(out, "skipping a catalog entry") || strings.Contains(out, token) {
		t.Errorf("logs %s", out)
	}
}

func TestServerLogMessageIsRedacted(t *testing.T) {
	const token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	engine, err := redact.New(redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var logs strings.Builder
	m := New(Options{
		Name: "s", Policy: policy.New(&config.Server{}),
		Logger:    slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Redaction: NewRedaction(engine, nil, 1<<20),
	})
	m.logMessage(t.Context(), &mcp.LoggingMessageParams{Level: "info", Logger: "auth " + token, Data: "token " + token}) //nolint:staticcheck // servers of older protocol versions still send log messages
	if out := logs.String(); !strings.Contains(out, "server log message") || strings.Contains(out, token) {
		t.Errorf("logs %s", out)
	}
}

func TestLogTextKeepsCharacters(t *testing.T) {
	m := New(Options{Name: "s", Policy: policy.New(&config.Server{})})
	m.Attach(stubDown{})
	got := m.logText(strings.Repeat("a", 255) + "é")
	if !utf8.ValidString(got) || got != strings.Repeat("a", 255)+"…" {
		t.Errorf("logText = %q", got)
	}
}

package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/audit"
	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/downstream"
	"github.com/vsem-azamat/mcp-gate/internal/policy"
	"github.com/vsem-azamat/mcp-gate/internal/redact"
)

// fakeDown is a downstream that answers the typed calls with what its fields say, without any
// session, and keeps the requests it got.
type fakeDown struct {
	stubDown
	tool   *mcp.CallToolResult
	prompt *mcp.GetPromptResult
	read   *mcp.ReadResourceResult
	err    error

	tools   []*mcp.CallToolParams
	prompts []*mcp.GetPromptParams
	reads   []*mcp.ReadResourceParams
}

func (d *fakeDown) CallTool(_ context.Context, p *mcp.CallToolParams) (*mcp.CallToolResult, error) {
	d.tools = append(d.tools, p)
	return d.tool, d.err
}

func (d *fakeDown) GetPrompt(_ context.Context, p *mcp.GetPromptParams) (*mcp.GetPromptResult, error) {
	d.prompts = append(d.prompts, p)
	return d.prompt, d.err
}

func (d *fakeDown) ReadResource(_ context.Context, p *mcp.ReadResourceParams) (*mcp.ReadResourceResult, error) {
	d.reads = append(d.reads, p)
	return d.read, d.err
}

// fakeMirror returns a mirror of a source attached to down, recording its audit records.
func fakeMirror(opts Options, down *fakeDown) (*Mirror, *recorder) {
	rec := &recorder{}
	if opts.Name == "" {
		opts.Name = "s"
	}
	if opts.Policy == nil {
		opts.Policy = policy.New(&config.Server{})
	}
	opts.Audit = rec
	src := NewSource(opts.Name, nil)
	src.Attach(down)
	opts.Source = src
	return New(opts), rec
}

func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

func firstText(res *mcp.CallToolResult) string {
	if res == nil || len(res.Content) == 0 {
		return ""
	}
	if tc, ok := res.Content[0].(*mcp.TextContent); ok {
		return tc.Text
	}
	return ""
}

// jsonIs reports whether v is the raw JSON want.
func jsonIs(v any, want string) bool {
	raw, ok := v.(json.RawMessage)
	return ok && string(raw) == want
}

const ghToken = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"

// TestToolPipeline runs a tool call through every outcome the server's answer can give it.
func TestToolPipeline(t *testing.T) {
	engine, err := redact.New(redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	notReady := &downstream.NotReadyError{Name: "s", State: downstream.Backoff}
	for _, c := range []struct {
		name       string
		res        *mcp.CallToolResult
		err        error
		redaction  *Redaction
		wantText   string // of the result the client gets
		wantErr    string // of the error the client gets
		outcome    audit.Outcome
		redactions int64
	}{
		{name: "ok", res: textResult("hello"), wantText: "hello", outcome: audit.OK},
		{name: "tool error", res: &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "no"}}}, wantText: "no", outcome: audit.ToolError},
		{name: "unavailable", err: notReady, wantText: "server s is not available (backoff); try again later", outcome: audit.Unavailable},
		{name: "failed", err: errors.New("boom"), wantErr: "boom", outcome: audit.Error},
		{name: "no result", wantErr: "server s returned no result", outcome: audit.Error},
		{name: "input", res: &mcp.CallToolResult{RequestState: "x"}, wantText: errNeedsInput.Error(), outcome: audit.InputRequired},
		{name: "redacted", res: textResult("token " + ghToken), redaction: NewRedaction(engine, nil, 1<<20), wantText: "token [REDACTED:github_token]", outcome: audit.OK, redactions: 1},
		{name: "withheld", res: textResult(strings.Repeat("x", 64)), redaction: NewRedaction(engine, nil, 8), wantErr: "server s:", outcome: audit.Withheld},
		{name: "unavailable is not redacted", err: notReady, redaction: NewRedaction(engine, nil, 8), wantText: "server s is not available (backoff); try again later", outcome: audit.Unavailable},
	} {
		t.Run(c.name, func(t *testing.T) {
			down := &fakeDown{tool: c.res, err: c.err}
			m, rec := fakeMirror(Options{Redaction: c.redaction}, down)
			res, err := m.callTool(t.Context(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "echo", Arguments: json.RawMessage(`{"a":1}`)}})
			switch {
			case c.wantErr != "":
				if err == nil || !strings.HasPrefix(err.Error(), c.wantErr) || res != nil {
					t.Errorf("got %v %v, want the error %q", res, err, c.wantErr)
				}
			case err != nil || firstText(res) != c.wantText:
				t.Errorf("got %q %v, want %q", firstText(res), err, c.wantText)
			}
			want := audit.Record{Server: "s", Kind: audit.Tool, Name: "echo", Outcome: c.outcome, TokenPolicy: policy.NoPolicy, Redactions: c.redactions}
			if got := rec.all(); !slices.Equal(got, []audit.Record{want}) {
				t.Errorf("records %+v, want %+v", got, want)
			}
			if len(down.tools) != 1 || down.tools[0].Name != "echo" || !jsonIs(down.tools[0].Arguments, `{"a":1}`) {
				t.Errorf("forwarded %+v", down.tools)
			}
			if failed := m.Stats().Failed; failed != map[bool]int64{true: 1, false: 0}[c.outcome.Failed()] {
				t.Errorf("failed calls %d", failed)
			}
		})
	}
}

// TestPromptAndResourcePipelines checks that a prompt get and a resource read, which have no
// tool-error form, fail with an error where a tool call reports one in its result.
func TestPromptAndResourcePipelines(t *testing.T) {
	notReady := &downstream.NotReadyError{Name: "s", State: downstream.Starting}
	for _, c := range []struct {
		name    string
		down    *fakeDown
		wantErr string
		outcome audit.Outcome
	}{
		{"ok", &fakeDown{prompt: &mcp.GetPromptResult{}, read: &mcp.ReadResourceResult{}}, "", audit.OK},
		{"unavailable", &fakeDown{err: notReady}, "server s is not available (starting); try again later", audit.Unavailable},
		{"input", &fakeDown{prompt: &mcp.GetPromptResult{RequestState: "x"}, read: &mcp.ReadResourceResult{RequestState: "x"}}, errNeedsInput.Error(), audit.InputRequired},
		{"no result", &fakeDown{}, "server s returned no result", audit.Error},
	} {
		t.Run(c.name, func(t *testing.T) {
			m, rec := fakeMirror(Options{}, c.down)
			_, perr := m.getPrompt(t.Context(), &mcp.GetPromptRequest{Params: &mcp.GetPromptParams{Name: "greet", Arguments: map[string]string{"who": "x"}}})
			_, rerr := m.readResource(t.Context(), &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{URI: "x://y"}})
			for _, err := range []error{perr, rerr} {
				if (c.wantErr == "") != (err == nil) || (err != nil && err.Error() != c.wantErr) {
					t.Errorf("error %v, want %q", err, c.wantErr)
				}
			}
			want := []audit.Record{
				{Server: "s", Kind: audit.Prompt, Name: "greet", Outcome: c.outcome, TokenPolicy: policy.NoPolicy},
				{Server: "s", Kind: audit.Resource, Name: "x://y", Outcome: c.outcome, TokenPolicy: policy.NoPolicy},
			}
			if got := rec.all(); !slices.Equal(got, want) {
				t.Errorf("records %+v", got)
			}
			if len(c.down.prompts) != 1 || c.down.prompts[0].Arguments["who"] != "x" || len(c.down.reads) != 1 || c.down.reads[0].URI != "x://y" {
				t.Errorf("forwarded %+v %+v", c.down.prompts, c.down.reads)
			}
		})
	}
}

// TestPromptAndResourceRedaction checks that prompt and resource results are redacted, and that
// the findings are counted in the audit record.
func TestPromptAndResourceRedaction(t *testing.T) {
	engine, err := redact.New(redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	down := &fakeDown{
		prompt: &mcp.GetPromptResult{Messages: []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: "token " + ghToken}}}},
		read:   &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: "x://y", Text: "token " + ghToken}}},
	}
	m, rec := fakeMirror(Options{Redaction: NewRedaction(engine, nil, 1<<20)}, down)
	pres, err := m.getPrompt(t.Context(), &mcp.GetPromptRequest{Params: &mcp.GetPromptParams{Name: "greet"}})
	if err != nil {
		t.Fatal(err)
	}
	rres, err := m.readResource(t.Context(), &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{URI: "x://y"}})
	if err != nil {
		t.Fatal(err)
	}
	const want = "token [REDACTED:github_token]"
	if tc, ok := pres.Messages[0].Content.(*mcp.TextContent); !ok || tc.Text != want {
		t.Errorf("prompt %+v", pres.Messages[0].Content)
	}
	if got := rres.Contents[0].Text; got != want {
		t.Errorf("resource %q", got)
	}
	records := []audit.Record{
		{Server: "s", Kind: audit.Prompt, Name: "greet", Outcome: audit.OK, TokenPolicy: policy.NoPolicy, Redactions: 1},
		{Server: "s", Kind: audit.Resource, Name: "x://y", Outcome: audit.OK, TokenPolicy: policy.NoPolicy, Redactions: 1},
	}
	if got := rec.all(); !slices.Equal(got, records) {
		t.Errorf("records %+v", got)
	}
}

// TestPipelineRefusesBeforeForward checks that the server's filter and the token's policy
// refuse a hidden entry with the error of an unknown one, under the name the caller gave, and
// that nothing reaches the server.
func TestPipelineRefusesBeforeForward(t *testing.T) {
	cfg := &config.Config{Policies: map[string]*config.TokenPolicy{"phone": {Servers: map[string]*config.ServerPolicy{
		"s": {
			Tools:     &config.PolicyFilter{Deny: []string{"mail"}},
			Prompts:   &config.PolicyFilter{Deny: []string{"draft"}},
			Resources: &config.PolicyFilter{Deny: []string{"x://private"}},
		},
	}}}}
	down := &fakeDown{tool: textResult("x"), prompt: &mcp.GetPromptResult{}, read: &mcp.ReadResourceResult{}}
	m, rec := fakeMirror(Options{
		Policy: policy.New(&config.Server{
			Tools:     &config.Filter{Deny: []string{"env"}},
			Prompts:   &config.Filter{Deny: []string{"secret"}},
			Resources: &config.Filter{Deny: []string{"x://hidden"}},
		}),
		Tokens: policy.NewTokens(cfg, "s"),
	}, down)
	phone := &mcp.RequestExtra{TokenInfo: &auth.TokenInfo{UserID: "phone"}}
	for _, c := range []struct {
		name, shown string
		extra       *mcp.RequestExtra
	}{
		{"env", "s__env", nil},     // the server's filter
		{"mail", "s__mail", phone}, // the token's policy
	} {
		_, err := m.callToolAs(t.Context(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: c.name}, Extra: c.extra}, c.shown)
		if err == nil || err.Error() != errUnknownTool(c.shown).Error() {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	for _, c := range []struct {
		name, shown string
		extra       *mcp.RequestExtra
	}{
		{"secret", "s__secret", nil}, // the server's filter
		{"draft", "s__draft", phone}, // the token's policy
	} {
		_, err := m.getPromptAs(t.Context(), &mcp.GetPromptRequest{Params: &mcp.GetPromptParams{Name: c.name}, Extra: c.extra}, c.shown)
		if err == nil || err.Error() != errUnknownPrompt(c.shown).Error() {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	for _, c := range []struct {
		uri   string
		extra *mcp.RequestExtra
	}{
		{"x://hidden", nil},    // the server's filter
		{"x://private", phone}, // the token's policy
	} {
		_, err := m.readResource(t.Context(), &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{URI: c.uri}, Extra: c.extra})
		if err == nil || err.Error() != errUnknownResource(c.uri).Error() {
			t.Errorf("%s: %v", c.uri, err)
		}
	}
	if len(down.tools)+len(down.prompts)+len(down.reads) != 0 {
		t.Errorf("forwarded %+v %+v %+v", down.tools, down.prompts, down.reads)
	}
	// What each filter passes still goes through.
	if _, err := m.getPromptAs(t.Context(), &mcp.GetPromptRequest{Params: &mcp.GetPromptParams{Name: "greet"}, Extra: phone}, "greet"); err != nil {
		t.Errorf("greet: %v", err)
	}
	if _, err := m.readResource(t.Context(), &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{URI: "x://open"}, Extra: phone}); err != nil {
		t.Errorf("x://open: %v", err)
	}
	denied := func(principal string, kind audit.Kind, name string) audit.Record {
		return audit.Record{Server: "s", Principal: principal, Kind: kind, Name: name, Outcome: audit.Denied, TokenPolicy: policy.NoPolicy}
	}
	want := []audit.Record{
		denied("", audit.Tool, "env"), denied("phone", audit.Tool, "mail"),
		denied("", audit.Prompt, "secret"), denied("phone", audit.Prompt, "draft"),
		denied("", audit.Resource, "x://hidden"), denied("phone", audit.Resource, "x://private"),
		{Server: "s", Principal: "phone", Kind: audit.Prompt, Name: "greet", Outcome: audit.OK, TokenPolicy: policy.NoPolicy},
		{Server: "s", Principal: "phone", Kind: audit.Resource, Name: "x://open", Outcome: audit.OK, TokenPolicy: policy.NoPolicy},
	}
	if got := rec.all(); !slices.Equal(got, want) {
		t.Errorf("records %+v", got)
	}
}

// TestPipelineForwardsMeta checks that only the configured _meta keys are forwarded.
func TestPipelineForwardsMeta(t *testing.T) {
	down := &fakeDown{tool: textResult("x")}
	m, _ := fakeMirror(Options{ForwardMeta: []string{"example.com/trace"}}, down)
	meta := mcp.Meta{"example.com/trace": "t1", "example.com/other": "o", "progressToken": "p"}
	if _, err := m.callTool(t.Context(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "echo", Meta: meta}}); err != nil {
		t.Fatal(err)
	}
	// Without an upstream session there is no stream for progress, so no token goes down.
	if got := down.tools[0].Meta; len(got) != 1 || got["example.com/trace"] != "t1" {
		t.Errorf("downstream _meta %v", got)
	}
}

// scanner is a FileScanner that withholds n files, or fails with err.
type scanner struct {
	n    int
	err  error
	tool string
	at   time.Time
	args map[string]any
}

func (s *scanner) Scan(_ context.Context, tool string, args func() map[string]any, res *mcp.CallToolResult, start time.Time) (*mcp.CallToolResult, int, error) {
	s.tool, s.at, s.args = tool, start, args()
	return res, s.n, s.err
}

// TestPipelineScansFiles checks that the files a tool call wrote are scanned after redaction,
// that withheld files count as redactions, and that a file that cannot be scanned withholds the
// result.
func TestPipelineScansFiles(t *testing.T) {
	engine, err := redact.New(redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		sc   *scanner
		want audit.Outcome
		n    int64
	}{
		{"withheld files", &scanner{n: 2}, audit.OK, 3},
		{"cannot scan", &scanner{err: errors.New("unreadable")}, audit.Withheld, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			down := &fakeDown{tool: textResult("token " + ghToken)}
			m, rec := fakeMirror(Options{Redaction: NewRedaction(engine, nil, 1<<20), Files: c.sc}, down)
			before := time.Now()
			_, _ = m.callTool(t.Context(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "dl", Arguments: json.RawMessage(`{"path":"/x"}`)}})
			if c.sc.tool != "dl" || c.sc.args["path"] != "/x" || c.sc.at.Before(before) {
				t.Errorf("scanned %q %v at %v", c.sc.tool, c.sc.args, c.sc.at)
			}
			if last := rec.last(t); last.Outcome != c.want || last.Redactions != c.n {
				t.Errorf("record %+v", last)
			}
		})
	}
	// Without redaction the files are not scanned.
	sc := &scanner{n: 1}
	m, _ := fakeMirror(Options{Files: sc}, &fakeDown{tool: textResult("x")})
	_, _ = m.callTool(t.Context(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "dl"}})
	if sc.tool != "" {
		t.Error("scanned without redaction")
	}
}

package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/audit"
	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/limit"
	"github.com/vsem-azamat/mcp-gate/internal/policy"
)

// TestLimitsStage checks the limits stage: a call over a limit fails with the limit's error and
// outcome limited without being forwarded, a hidden entry fails as an unknown one whatever the
// limits, and the places in flight are given back when a call ends.
func TestLimitsStage(t *testing.T) {
	cfg := &config.Config{Policies: map[string]*config.TokenPolicy{"phone": {Servers: map[string]*config.ServerPolicy{
		"s": {Tools: &config.PolicyFilter{Deny: []string{"env"}}},
	}}}}
	limits := limit.New(nil)
	limits.Set([]limit.Rule{
		{Token: "phone", Rate: 1, Per: time.Hour, Burst: 1},
		{Server: "s", Concurrency: 1},
	})
	down := &fakeDown{tool: textResult("x"), prompt: &mcp.GetPromptResult{}}
	m, rec := fakeMirror(Options{Tokens: policy.NewTokens(cfg, "s"), Limits: limits}, down)
	phone := &mcp.RequestExtra{TokenInfo: &auth.TokenInfo{UserID: "phone"}}
	call := func(name string, extra *mcp.RequestExtra) error {
		_, err := m.callTool(t.Context(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: name}, Extra: extra})
		return err
	}
	if err := call("echo", phone); err != nil {
		t.Fatal(err)
	}
	err := call("echo", phone)
	var rpc *jsonrpc.Error
	if !errors.As(err, &rpc) || rpc.Code != CodeLimited || rpc.Message != "mcp-gate: rate limit reached: at most 1 call per 1h; retry in 3600s" {
		t.Fatalf("over the limit: %v", err)
	}
	var data struct {
		RetryAfterMs int64 `json:"retryAfterMs"`
	}
	if json.Unmarshal(rpc.Data, &data) != nil || data.RetryAfterMs < 3599_000 || data.RetryAfterMs > 3600_000 {
		t.Errorf("data %s", rpc.Data)
	}
	if err := call("env", phone); err == nil || err.Error() != errUnknownTool("env").Error() {
		t.Errorf("hidden tool: %v", err)
	}
	if _, err := m.getPrompt(t.Context(), &mcp.GetPromptRequest{Params: &mcp.GetPromptParams{Name: "greet"}, Extra: phone}); err == nil {
		t.Error("a prompt get passed the token's used-up limit")
	}
	if len(down.tools) != 1 || len(down.prompts) != 0 {
		t.Errorf("forwarded %d tool calls and %d prompt gets, want 1 and 0", len(down.tools), len(down.prompts))
	}
	// The concurrency place of the first call was given back when it ended.
	if err := call("echo", nil); err != nil {
		t.Errorf("a call after the first ended: %v", err)
	}
	want := []audit.Record{
		{Server: "s", Principal: "phone", Kind: audit.Tool, Name: "echo", Outcome: audit.OK, TokenPolicy: policy.NoPolicy},
		{Server: "s", Principal: "phone", Kind: audit.Tool, Name: "echo", Outcome: audit.Limited, TokenPolicy: policy.NoPolicy},
		{Server: "s", Principal: "phone", Kind: audit.Tool, Name: "env", Outcome: audit.Denied, TokenPolicy: policy.NoPolicy},
		{Server: "s", Principal: "phone", Kind: audit.Prompt, Name: "greet", Outcome: audit.Limited, TokenPolicy: policy.NoPolicy},
		{Server: "s", Kind: audit.Tool, Name: "echo", Outcome: audit.OK, TokenPolicy: policy.NoPolicy},
	}
	if got := rec.all(); !slices.Equal(got, want) {
		t.Errorf("records %+v", got)
	}
}

// TestLimitsToolEntryNotPrompt checks that an entry of a tool does not count a prompt of the
// same name.
func TestLimitsToolEntryNotPrompt(t *testing.T) {
	limits := limit.New(nil)
	limits.Set([]limit.Rule{{Server: "s", Tool: "greet", Rate: 1, Per: time.Hour, Burst: 1}})
	m, _ := fakeMirror(Options{Limits: limits}, &fakeDown{prompt: &mcp.GetPromptResult{}})
	for i := range 3 {
		if _, err := m.getPrompt(t.Context(), &mcp.GetPromptRequest{Params: &mcp.GetPromptParams{Name: "greet"}}); err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
	}
}

// blockingDown answers a tool call once release is closed.
type blockingDown struct {
	fakeDown
	started chan struct{}
	release chan struct{}
}

func (d *blockingDown) CallTool(ctx context.Context, _ *mcp.CallToolParams) (*mcp.CallToolResult, error) {
	d.started <- struct{}{}
	<-d.release
	return textResult("x"), nil
}

// TestLimitsConcurrency checks that a call in flight holds its place until it ends, and that a
// concurrency refusal carries no retry time.
func TestLimitsConcurrency(t *testing.T) {
	limits := limit.New(nil)
	limits.Set([]limit.Rule{{Server: "s", Tool: "slow", Concurrency: 1}})
	down := &blockingDown{started: make(chan struct{}), release: make(chan struct{})}
	src := NewSource("s", nil)
	src.Attach(down)
	m := New(Options{Name: "s", Policy: policy.New(&config.Server{}), Source: src, Limits: limits, Audit: &recorder{}})
	done := make(chan error)
	go func() {
		_, err := m.callTool(context.Background(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "slow"}})
		done <- err
	}()
	<-down.started
	_, err := m.callTool(t.Context(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "slow"}})
	var rpc *jsonrpc.Error
	if !errors.As(err, &rpc) || rpc.Message != "mcp-gate: concurrency limit reached: at most 1 call in flight; retry when one ends" || rpc.Data != nil {
		t.Fatalf("second call: %v", err)
	}
	close(down.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	go func() { <-down.started }()
	if _, err := m.callTool(t.Context(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "slow"}}); err != nil {
		t.Errorf("a call after the first ended: %v", err)
	}
}

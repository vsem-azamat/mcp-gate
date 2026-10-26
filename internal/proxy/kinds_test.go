package proxy

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/policy"
)

// TestUnknownErrors checks that the errors the gate gives for an entry the caller may not see
// are, on the wire, the SDK's own for an entry the server does not have.
func TestUnknownErrors(t *testing.T) {
	// The SDK's errors: a server with nothing.
	sdk := connectTo(t, mcp.NewServer(&mcp.Implementation{Name: "sdk", Version: "1"}, nil))
	// The gate's: a server whose entries refuse with them.
	gate := mcp.NewServer(&mcp.Implementation{Name: "gate", Version: "1"}, nil)
	const tool, prompt, uri = "s__hidden", "s__secret", "fake://hidden"
	gate.AddTool(&mcp.Tool{Name: tool, InputSchema: map[string]any{"type": "object"}},
		func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return nil, errUnknownTool(tool)
		})
	gate.AddPrompt(&mcp.Prompt{Name: prompt},
		func(context.Context, *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			return nil, errUnknownPrompt(prompt)
		})
	gate.AddResource(&mcp.Resource{Name: "hidden", URI: uri},
		func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return nil, errUnknownResource(uri)
		})
	cs := connectTo(t, gate)

	for _, c := range []struct {
		what string
		call func(*mcp.ClientSession) error
	}{
		{"tool", func(s *mcp.ClientSession) error {
			_, err := s.CallTool(t.Context(), &mcp.CallToolParams{Name: tool})
			return err
		}},
		{"prompt", func(s *mcp.ClientSession) error {
			_, err := s.GetPrompt(t.Context(), &mcp.GetPromptParams{Name: prompt})
			return err
		}},
		{"resource", func(s *mcp.ClientSession) error {
			_, err := s.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: uri})
			return err
		}},
	} {
		want, got := c.call(sdk), c.call(cs)
		if want == nil || got == nil || got.Error() != want.Error() {
			t.Errorf("%s: the gate's error %v, the SDK's %v", c.what, got, want)
		}
	}
}

func connectTo(t *testing.T, s *mcp.Server) *mcp.ClientSession {
	t.Helper()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := s.Connect(t.Context(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(t.Context(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// countingDown counts the calls that reach the downstream.
type countingDown struct {
	stubDown
	calls *int
}

func (d countingDown) Call(ctx context.Context, fn func(context.Context, *mcp.ClientSession) error) error {
	*d.calls++
	return d.stubDown.Call(ctx, fn)
}

// The handlers check access with the token's policy itself: a name the mirror does not hold is
// refused when the policy hides it, and labelled none in the audit line.
func TestHandlersCheckThePolicy(t *testing.T) {
	var logs strings.Builder
	cfg := &config.Config{Policies: map[string]*config.TokenPolicy{"phone": {Servers: map[string]*config.ServerPolicy{
		"s": {Tools: &config.PolicyFilter{Allow: []string{"echo"}}, Resources: &config.PolicyFilter{None: true}},
	}}}}
	calls := 0
	m := newMirror(Options{
		Name: "s", Policy: policy.New(&config.Server{}), Tokens: policy.NewTokens(cfg, "s"),
		Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
	}, countingDown{calls: &calls})
	extra := &mcp.RequestExtra{TokenInfo: &auth.TokenInfo{UserID: "phone"}}
	_, err := m.callTool(t.Context(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "ghost"}, Extra: extra})
	if err == nil || err.Error() != errUnknownTool("ghost").Error() {
		t.Errorf("ghost: %v", err)
	}
	_, err = m.readResource(t.Context(), &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{URI: "x://y"}, Extra: extra})
	if err == nil || err.Error() != errUnknownResource("x://y").Error() {
		t.Errorf("x://y: %v", err)
	}
	if calls != 0 {
		t.Errorf("%d calls reached the downstream", calls)
	}
	if n := strings.Count(logs.String(), `"outcome":"denied","tokenPolicy":"none"`); n != 2 {
		t.Errorf("audit lines: %s", logs.String())
	}
}

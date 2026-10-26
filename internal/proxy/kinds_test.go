package proxy

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
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

package proxy

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/policy"
)

// sessionDown is a downstream served by an in-memory MCP server with a tool and a prompt. Before
// each call it runs during, if set.
type sessionDown struct {
	stubDown
	cs     *mcp.ClientSession
	during func()
}

func newSessionDown(t *testing.T) *sessionDown {
	t.Helper()
	server := mcp.NewServer(&mcp.Implementation{Name: "fake", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{Name: "a", InputSchema: map[string]any{"type": "object"}},
		func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{}, nil
		})
	server.AddPrompt(&mcp.Prompt{Name: "p"}, func(context.Context, *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return &mcp.GetPromptResult{}, nil
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

func (d *sessionDown) Call(ctx context.Context, fn func(context.Context, *mcp.ClientSession) error) error {
	if d.during != nil {
		d.during()
	}
	return fn(ctx, d.cs)
}

// TestReadyAfterMirrorsHaveTheTools checks that a source reports ready only once its mirrors have
// registered the first listing, so that a route that waits for ready never serves an empty catalog.
func TestReadyAfterMirrorsHaveTheTools(t *testing.T) {
	src := NewSource("s", nil)
	src.Attach(newSessionDown(t))
	m := New(Options{Name: "s", Policy: policy.New(&config.Server{}), Source: src})
	var readyAtApply []bool
	m.Watch(func() { readyAtApply = append(readyAtApply, m.Ready()) })
	if failed, _ := src.sync(t.Context(), kindAll); failed != 0 {
		t.Fatalf("failed kinds %b", failed)
	}
	if len(readyAtApply) != 1 || readyAtApply[0] {
		t.Errorf("ready when the mirror applied the first listing: %v", readyAtApply)
	}
	if !m.Ready() || catalogOf(m).Tools["a"] == nil {
		t.Error("not ready, or without the tool, after the listing")
	}
}

// TestMirrorAttachedDuringListing checks that a mirror that shows prompts, attached while a listing
// made for mirrors that hide them runs, gets the prompts listed.
func TestMirrorAttachedDuringListing(t *testing.T) {
	down := newSessionDown(t)
	src := NewSource("s", nil)
	src.Attach(down)
	none := &config.Filter{Allow: []string{}}
	_ = New(Options{Name: "s", Policy: policy.New(&config.Server{Prompts: none}), Source: src})
	var shows *Mirror
	down.during = func() {
		down.during = nil
		shows = New(Options{Name: "s", Policy: policy.New(&config.Server{}), Source: src})
	}
	if failed, _ := src.sync(t.Context(), kindAll); failed != 0 {
		t.Fatalf("failed kinds %b", failed)
	}
	src.mu.Lock()
	dirty := src.dirty
	src.mu.Unlock()
	if dirty&kindPrompts == 0 {
		t.Fatalf("prompts not marked for listing (dirty %b)", dirty)
	}
	if failed, _ := src.sync(t.Context(), dirty); failed != 0 {
		t.Fatalf("failed kinds %b", failed)
	}
	if catalogOf(shows).Prompts["p"] == nil {
		t.Errorf("the prompt is missing: %v", catalogOf(shows).Prompts)
	}
}

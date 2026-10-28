package proxy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/audit"
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
	src.Attach(onSession{newSessionDown(t)})
	m := New(Options{Name: "s", Policy: policy.New(&config.Server{}), Source: src})
	var readyAtApply []bool
	m.Watch(func() { readyAtApply = append(readyAtApply, m.Ready()) })
	if failed, _ := src.sync(t.Context(), allKinds); failed != 0 {
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
	src.Attach(onSession{down})
	none := &config.Filter{Allow: []string{}}
	_ = New(Options{Name: "s", Policy: policy.New(&config.Server{Prompts: none}), Source: src})
	var shows *Mirror
	down.during = func() {
		down.during = nil
		shows = New(Options{Name: "s", Policy: policy.New(&config.Server{}), Source: src})
	}
	if failed, _ := src.sync(t.Context(), allKinds); failed != 0 {
		t.Fatalf("failed kinds %b", failed)
	}
	src.mu.Lock()
	dirty := src.dirty
	src.mu.Unlock()
	if !dirty.has(audit.Prompt) {
		t.Fatalf("prompts not marked for listing (dirty %b)", dirty)
	}
	if failed, _ := src.sync(t.Context(), dirty); failed != 0 {
		t.Fatalf("failed kinds %b", failed)
	}
	if catalogOf(shows).Prompts["p"] == nil {
		t.Errorf("the prompt is missing: %v", catalogOf(shows).Prompts)
	}
}

// TestCollectBounds checks that a listing whose cursor never ends, or that has too many
// entries, fails instead of growing.
func TestCollectBounds(t *testing.T) {
	t.Parallel()
	type entry struct{}
	pages := 0
	endless := func(context.Context, string) ([]*entry, string, error) {
		pages++
		return nil, "again", nil
	}
	if _, err := collect(t.Context(), endless); !errors.Is(err, errListTooLong) || pages != maxListPages {
		t.Errorf("endless cursor: %v after %d pages", err, pages)
	}
	big := func(_ context.Context, c string) ([]*entry, string, error) {
		next := "more"
		if c == "more" {
			next = ""
		}
		return make([]*entry, maxListEntries/2+1), next, nil
	}
	if _, err := collect(t.Context(), big); !errors.Is(err, errListTooLong) {
		t.Errorf("too many entries: %v", err)
	}
	type text struct{ T string }
	pageOf := strings.Repeat("x", 1<<20)
	heavyPages := 0
	heavy := func(context.Context, string) ([]*text, string, error) { // 30 pages of 1 MiB
		heavyPages++
		if heavyPages == 30 {
			return []*text{{T: pageOf}}, "", nil
		}
		return []*text{{T: pageOf}}, "more", nil
	}
	if _, err := collect(t.Context(), heavy); !errors.Is(err, errListTooLong) {
		t.Errorf("too many bytes: %v", err)
	}
	two := func(_ context.Context, c string) ([]*entry, string, error) {
		if c == "" {
			return []*entry{{}}, "p2", nil
		}
		return []*entry{{}, {}}, "", nil
	}
	if got, err := collect(t.Context(), two); err != nil || len(got) != 3 {
		t.Errorf("two pages = %d entries, %v", len(got), err)
	}
}

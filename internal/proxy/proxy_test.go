package proxy

import (
	"errors"
	"log/slog"
	"maps"
	"slices"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/policy"
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
	got := downstreamMeta(in)
	want := mcp.Meta{"example.com/trace": "abc", "plain": 1, "mcpish.example.com/thing": "kept", "example.com/modelcontextprotocolish": "kept"}
	if !maps.Equal(map[string]any(got), map[string]any(want)) {
		t.Errorf("downstreamMeta = %v, want %v", got, want)
	}
	if downstreamMeta(mcp.Meta{"progressToken": 1}) != nil || downstreamMeta(nil) != nil {
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
	got := syncSet(slog.New(slog.DiscardHandler), "test", have, want, add, func(keys ...string) { removed = append(removed, keys...) })
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

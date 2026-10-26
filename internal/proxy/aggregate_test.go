package proxy

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/policy"
)

// member returns a mirror named name serving the given tools and resources.
func member(t *testing.T, name string, logger *slog.Logger, tools []string, resources []string, templates []string) *Mirror {
	t.Helper()
	m := New(Options{Name: name, Policy: policy.New(&config.Server{}), Logger: logger})
	m.Attach(stubDown{})
	var list []*mcp.Tool
	for _, n := range tools {
		list = append(list, &mcp.Tool{Name: n, InputSchema: map[string]any{"type": "object"}})
	}
	m.tools = m.applyTools(list)
	var rs []*mcp.Resource
	for _, u := range resources {
		rs = append(rs, &mcp.Resource{URI: u, Name: u})
	}
	m.resources = m.applyResources(rs)
	var ts []*mcp.ResourceTemplate
	for _, u := range templates {
		ts = append(ts, &mcp.ResourceTemplate{URITemplate: u, Name: u})
	}
	m.templates = m.applyTemplates(ts)
	m.served = newServed(m.resources, m.templates)
	return m
}

func registered(v *View) []string {
	v.a.mu.Lock()
	defer v.a.mu.Unlock()
	var out []string
	for k := range v.tools {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestAggregateNames(t *testing.T) {
	long := strings.Repeat("x", 62) // one over the limit once prefixed
	m := member(t, "s", nil, []string{"a", "b__c", "bad name", long, long[1:]}, nil, nil)
	a, err := NewAggregate(AggregateOptions{Name: "gate", Members: []*Mirror{m}})
	if err != nil {
		t.Fatal(err)
	}
	v := a.View([]string{"s"}, nil)
	want := []string{"s__" + long[1:], "s__a", "s__b__c"}
	sort.Strings(want)
	if got := registered(v); !slices.Equal(got, want) {
		t.Errorf("registered %v, want %v", got, want)
	}
	for _, c := range []struct{ in, server, rest string }{
		{"s__a", "s", "a"}, {"s__b__c", "s", "b__c"}, {"s_a", "", ""},
	} {
		server, rest, _ := splitName(c.in)
		if c.server != "" && (server != c.server || rest != c.rest) {
			t.Errorf("splitName(%q) = %q %q", c.in, server, rest)
		}
		if _, _, ok := splitName(c.in); ok != (c.server != "") {
			t.Errorf("splitName(%q) ok = %v", c.in, ok)
		}
	}
}

func TestAggregateFollowsChanges(t *testing.T) {
	m := member(t, "s", nil, []string{"a"}, nil, nil)
	a, err := NewAggregate(AggregateOptions{Members: []*Mirror{m}})
	if err != nil {
		t.Fatal(err)
	}
	v := a.View([]string{"s"}, nil)
	m.tools = m.applyTools([]*mcp.Tool{{Name: "b", InputSchema: map[string]any{"type": "object"}}})
	m.ready.Store(true)
	if a.Listed("s") {
		t.Error("listed before the views hold the catalog")
	}
	for _, w := range m.watchers {
		w()
	}
	if !a.Listed("s") {
		t.Error("not listed after the change reached the views")
	}
	if got := registered(v); !slices.Equal(got, []string{"s__b"}) {
		t.Errorf("after the change: %v", got)
	}
}

// TestViewRechecksAccess calls a view's handler with an access that does not name the server:
// the view serves both servers, but the request may reach only one.
func TestViewRechecksAccess(t *testing.T) {
	var logs strings.Builder
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	ma := member(t, "a", logger, []string{"echo"}, nil, nil)
	mb := member(t, "b", logger, []string{"echo"}, nil, nil)
	agg, err := NewAggregate(AggregateOptions{Members: []*Mirror{ma, mb}, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	v := agg.View([]string{"a", "b"}, nil)
	call := v.callTool("b", "echo")
	req := func(access map[string]string) *mcp.CallToolRequest {
		return &mcp.CallToolRequest{
			Params: &mcp.CallToolParamsRaw{Name: "b__echo"},
			Extra:  &mcp.RequestExtra{TokenInfo: AccessInfo("laptop", access)},
		}
	}
	for _, extra := range []*mcp.RequestExtra{nil, {}, {TokenInfo: AccessInfo("laptop", map[string]string{"a": "laptop"})}} {
		r := req(nil)
		r.Extra = extra
		if res, err := call(t.Context(), r); err == nil {
			t.Errorf("called with %+v: %v", extra, res)
		}
	}
	lines := callLines(t, logs.String())
	if len(lines) != 3 || lines[2]["server"] != "" || lines[2]["outcome"] != "denied" || lines[2]["tool"] != "b__echo" {
		t.Fatalf("audit lines %v", lines)
	}
	// With access to b the call reaches b's mirror, under the token name b knows.
	_, _ = call(t.Context(), req(map[string]string{"b": "phone"}))
	lines = callLines(t, logs.String())
	last := lines[len(lines)-1]
	if last["server"] != "b" || last["principal"] != "phone" || last["tool"] != "echo" {
		t.Errorf("audit line %v", last)
	}
	// A tool gone from the mirror before the view has caught up is refused as on b's route.
	mb.tools = mb.applyTools(nil)
	if res, err := call(t.Context(), req(map[string]string{"b": "phone"})); err == nil {
		t.Errorf("a removed tool was called: %v", res)
	}
	lines = callLines(t, logs.String())
	last = lines[len(lines)-1]
	if last["server"] != "b" || last["outcome"] != "denied" || last["tool"] != "echo" {
		t.Errorf("audit line of the removed tool %v", last)
	}
}

func callLines(t *testing.T, out string) []map[string]any {
	t.Helper()
	var lines []map[string]any
	for line := range strings.SplitSeq(out, "\n") {
		var l map[string]any
		if json.Unmarshal([]byte(line), &l) == nil && l["msg"] == "call" {
			lines = append(lines, l)
		}
	}
	return lines
}

func TestViewRoutesResources(t *testing.T) {
	ma := member(t, "a", nil, nil, []string{"x://shared", "x://a", "y://listed"}, []string{"x://a/{id}", "y://{id}", "z://{id}"})
	mb := member(t, "b", nil, nil, []string{"x://shared", "x://b"}, []string{"x://b/{id}", "y://{id}", "z://{+id}"})
	agg, err := NewAggregate(AggregateOptions{Members: []*Mirror{ma, mb}})
	if err != nil {
		t.Fatal(err)
	}
	both := agg.View([]string{"a", "b"}, nil)
	for uri, want := range map[string]string{
		"x://a": "a", "x://b": "b", "x://a/1": "a", "x://b/1": "b",
		"y://listed": "a", // listed by a, matched by both templates: the listing wins
		"x://shared": "",  // listed by both
		"y://1":      "",  // the same template on both
		"z://1":      "",  // different templates on both match
		"q://1":      "",
	} {
		got, ok := both.route(uri)
		if ok != (want != "") || got != want {
			t.Errorf("route(%s) = %q %v, want %q", uri, got, ok, want)
		}
	}
	both.a.mu.Lock()
	_, shared := both.resources["x://shared"]
	_, sameTemplate := both.templates["y://{id}"]
	both.a.mu.Unlock()
	if shared || sameTemplate {
		t.Error("an entry both servers list is registered")
	}
	onlyA := agg.View([]string{"a"}, nil)
	if got, ok := onlyA.route("x://shared"); !ok || got != "a" {
		t.Errorf("a alone: route(x://shared) = %q %v", got, ok)
	}
	if _, ok := onlyA.route("x://b"); ok {
		t.Error("a's view routes to b")
	}
}

// TestViewReadRechecksMirror reads a resource the mirror stopped listing before the view caught up.
func TestViewReadRechecksMirror(t *testing.T) {
	var logs strings.Builder
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	ma := member(t, "a", logger, nil, []string{"x://a"}, nil)
	agg, err := NewAggregate(AggregateOptions{Members: []*Mirror{ma}, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	v := agg.View([]string{"a"}, nil)
	ma.resources = ma.applyResources(nil)
	ma.served = newServed(ma.resources, ma.templates)
	req := &mcp.ReadResourceRequest{
		Params: &mcp.ReadResourceParams{URI: "x://a"},
		Extra:  &mcp.RequestExtra{TokenInfo: AccessInfo("laptop", map[string]string{"a": "laptop"})},
	}
	if res, err := v.readResource(t.Context(), req); err == nil {
		t.Errorf("read a resource the mirror no longer lists: %v", res)
	}
	lines := callLines(t, logs.String())
	if len(lines) != 1 || lines[0]["outcome"] != "denied" || lines[0]["server"] != "a" {
		t.Errorf("audit lines %v", lines)
	}
}

func TestAggregateLogTextUsesEveryRule(t *testing.T) {
	a, err := NewAggregate(AggregateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// A random-looking value made at run time, so that no secret-shaped literal is committed.
	sum := sha256.Sum256([]byte("aggregate"))
	secret := base64.RawURLEncoding.EncodeToString(sum[:])
	if got := a.logText("x__" + secret); strings.Contains(got, secret) {
		t.Errorf("a high-entropy name is logged: %q", got)
	}
}

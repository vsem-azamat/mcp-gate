package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/audit"
	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/policy"
)

// member returns a mirror named name serving the given tools and resources.
func member(t *testing.T, name string, rec *recorder, tools []string, resources []string, templates []string) *Mirror {
	t.Helper()
	opts := Options{Name: name, Policy: policy.New(&config.Server{})}
	if rec != nil {
		opts.Audit = rec
	}
	m := newMirror(opts, stubDown{})
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
	m.src.ready.Store(true)
	if a.Listed("s") {
		t.Error("listed before the views hold the catalog")
	}
	m.notifyWatchers()
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
	rec := &recorder{}
	ma := member(t, "a", rec, []string{"echo"}, nil, nil)
	mb := member(t, "b", rec, []string{"echo"}, nil, nil)
	agg, err := NewAggregate(AggregateOptions{Members: []*Mirror{ma, mb}, Audit: rec})
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
	denied := audit.Record{Principal: "laptop", Kind: audit.Tool, Name: "b__echo", Outcome: audit.Denied, TokenPolicy: policy.NoPolicy}
	if got := rec.all(); len(got) != 3 || got[2] != denied {
		t.Fatalf("records %+v", got)
	}
	// With access to b the call reaches b's mirror, under the token name b knows.
	_, _ = call(t.Context(), req(map[string]string{"b": "phone"}))
	if last := rec.last(t); last.Server != "b" || last.Principal != "phone" || last.Kind != audit.Tool || last.Name != "echo" {
		t.Errorf("record %+v", last)
	}
	// A tool gone from the mirror before the view has caught up is refused as on b's route.
	mb.tools = mb.applyTools(nil)
	if res, err := call(t.Context(), req(map[string]string{"b": "phone"})); err == nil {
		t.Errorf("a removed tool was called: %v", res)
	}
	removed := audit.Record{Server: "b", Principal: "phone", Kind: audit.Tool, Name: "echo", Outcome: audit.Denied, TokenPolicy: policy.NoPolicy}
	if last := rec.last(t); last != removed {
		t.Errorf("record of the removed tool %+v", last)
	}
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
	rec := &recorder{}
	ma := member(t, "a", rec, nil, []string{"x://a"}, nil)
	agg, err := NewAggregate(AggregateOptions{Members: []*Mirror{ma}, Audit: rec})
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
	want := []audit.Record{{Server: "a", Principal: "laptop", Kind: audit.Resource, Name: "x://a", Outcome: audit.Denied, TokenPolicy: policy.NoPolicy}}
	if got := rec.all(); !slices.Equal(got, want) {
		t.Errorf("records %+v", got)
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

// TestViewAuditsHiddenReadsOnly checks which reads the SDK refuses before a handler a view
// audits: one whose URI the caller's token policy hides, by the member's mirror, and not one of
// a URI the member serves and the policy passes, nor one no member serves.
func TestViewAuditsHiddenReadsOnly(t *testing.T) {
	rec := &recorder{}
	cfg := &config.Config{Policies: map[string]*config.TokenPolicy{"phone": {Servers: map[string]*config.ServerPolicy{
		"a": {Resources: &config.PolicyFilter{Allow: []string{"x://open"}}},
	}}}}
	m := newMirror(Options{Name: "a", Policy: policy.New(&config.Server{}), Tokens: policy.NewTokens(cfg, "a"), Audit: rec}, stubDown{})
	m.apply(kindSet(audit.Resource), &listing{resources: []*mcp.Resource{{URI: "x://open", Name: "open"}, {URI: "x://secret", Name: "secret"}}}, time.Now())
	agg, err := NewAggregate(AggregateOptions{Members: []*Mirror{m}, Audit: rec})
	if err != nil {
		t.Fatal(err)
	}
	v := agg.View([]string{"a"}, map[string]string{"a": "phone"})
	refuses := v.receive(func(context.Context, string, mcp.Request) (mcp.Result, error) { return nil, errors.New("not found") })
	for _, uri := range []string{"x://open", "x://secret", "y://nowhere"} {
		req := &mcp.ReadResourceRequest{
			Params: &mcp.ReadResourceParams{URI: uri},
			Extra:  &mcp.RequestExtra{TokenInfo: AccessInfo("phone", map[string]string{"a": "phone"})},
		}
		_, _ = refuses(t.Context(), "resources/read", req)
	}
	want := []audit.Record{{Server: "a", Principal: "phone", Kind: audit.Resource, Name: "x://secret", Outcome: audit.Denied, TokenPolicy: policy.Denied}}
	if got := rec.all(); !slices.Equal(got, want) {
		t.Errorf("records %+v", got)
	}
}

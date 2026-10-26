package gate_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

// aggregateGate serves alpha (global tokens, with a catalog), beta (only its own token phone)
// and pub (public, echo only) together on the aggregate endpoint.
func aggregateGate(t *testing.T) *running {
	t.Helper()
	r := startGate(t, configDoc("aggregate: {}\n", map[string]string{
		"alpha": stdioServer(t, testkit.Fake{Catalog: true}, ""),
		"beta":  stdioServer(t, testkit.Fake{Catalog: true}, "auth:\n  inherit: false\n  tokens: {phone: \"${PHONE}\"}\n"),
		"pub":   stdioServer(t, testkit.Fake{}, "auth: {public: true}\ntools: {allow: [echo]}\n"),
	}), gateOpts{})
	for _, s := range []string{"alpha", "beta", "pub"} {
		r.waitReady(t, s)
	}
	return r
}

// serversOf returns the server prefixes of the listed tools.
func serversOf(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	var out []string
	for _, name := range toolNames(t, cs) {
		server, _, ok := strings.Cut(name, "__")
		if !ok {
			t.Errorf("tool %q has no server prefix", name)
		}
		if !slices.Contains(out, server) {
			out = append(out, server)
		}
	}
	slices.Sort(out)
	return out
}

// lastCall returns the last audit line whose attribute key is value.
func (r *running) lastCall(key, value string) map[string]any {
	var out map[string]any
	for _, l := range r.logs.lines("call") {
		if l[key] == value {
			out = l
		}
	}
	return out
}

func TestAggregateAccess(t *testing.T) {
	r := aggregateGate(t)
	laptop := r.connect(t, "", clientOpts{aggregate: true})
	phone := r.connect(t, "", clientOpts{aggregate: true, header: "Bearer " + phoneToken})
	anon := r.connect(t, "", clientOpts{aggregate: true, noHeader: true})

	for _, c := range []struct {
		name string
		cs   *mcp.ClientSession
		want []string
	}{
		{"laptop", laptop, []string{"alpha", "pub"}},
		{"phone", phone, []string{"beta", "pub"}},
		{"no token", anon, []string{"pub"}},
	} {
		if got := serversOf(t, c.cs); !slices.Equal(got, c.want) {
			t.Errorf("%s lists the tools of %v, want %v", c.name, got, c.want)
		}
	}
	if got := toolNames(t, anon); !slices.Equal(got, []string{"pub__echo"}) {
		t.Errorf("pub's filter is not applied: %v", got)
	}

	call := func(cs *mcp.ClientSession, name string) (*mcp.CallToolResult, error) {
		return cs.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: map[string]any{"text": "hi"}})
	}
	if res, err := call(laptop, "alpha__echo"); err != nil || textOf(t, res) != "hi" {
		t.Fatalf("alpha__echo: %v %v", res, err)
	}
	if l := r.lastCall("tool", "echo"); l["server"] != "alpha" || l["principal"] != "laptop" || l["outcome"] != "ok" {
		t.Errorf("audit line of alpha__echo: %v", l)
	}
	if res, err := call(phone, "beta__echo"); err != nil || textOf(t, res) != "hi" {
		t.Fatalf("beta__echo: %v %v", res, err)
	}
	if l := r.lastCall("tool", "echo"); l["server"] != "beta" || l["principal"] != "phone" {
		t.Errorf("audit line of beta__echo: %v", l)
	}
	if res, err := call(anon, "pub__echo"); err != nil || textOf(t, res) != "hi" {
		t.Fatalf("pub__echo: %v %v", res, err)
	}

	// No way into a server the token cannot reach directly.
	for _, c := range []struct {
		cs   *mcp.ClientSession
		tool string
	}{
		{laptop, "beta__echo"},
		{phone, "alpha__echo"},
		{anon, "alpha__echo"},
		{anon, "beta__echo"},
		{laptop, "echo"},
		{laptop, "nobody__echo"},
	} {
		if res, err := call(c.cs, c.tool); err == nil {
			t.Errorf("%s was called: %v", c.tool, res)
		}
		if l := r.lastCall("tool", c.tool); l["server"] != "" || l["outcome"] != "denied" {
			t.Errorf("audit line of the refused %s: %v", c.tool, l)
		}
	}
	// A tool the server's filter hides is refused by that server, as on its own route.
	if _, err := call(anon, "pub__sleep"); err == nil {
		t.Error("pub__sleep was called")
	}
	if l := r.lastCall("tool", "sleep"); l["server"] != "pub" || l["outcome"] != "denied" {
		t.Errorf("audit line of pub__sleep: %v", l)
	}

	// Prompts and resources.
	if _, err := laptop.GetPrompt(t.Context(), &mcp.GetPromptParams{Name: "alpha__greet"}); err != nil {
		t.Errorf("alpha__greet: %v", err)
	}
	if _, err := laptop.GetPrompt(t.Context(), &mcp.GetPromptParams{Name: "beta__greet"}); err == nil {
		t.Error("laptop got beta__greet")
	}
	res, err := laptop.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "fake://items/7"})
	if err != nil || len(res.Contents) == 0 || res.Contents[0].Text != "contents of fake://items/7" {
		t.Fatalf("laptop reads fake://items/7: %v %v", res, err)
	}
	if l := r.lastCall("uri", "fake://items/7"); l["server"] != "alpha" || l["principal"] != "laptop" {
		t.Errorf("audit line of the read: %v", l)
	}
	if _, err := anon.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "fake://items/7"}); err == nil {
		t.Error("no token reads alpha's resource")
	}
	if rs, err := anon.ListResources(t.Context(), nil); err != nil || len(rs.Resources) != 0 {
		t.Errorf("no token lists resources: %v %v", rs, err)
	}

	// The header forms a server's route takes.
	for _, header := range []string{laptopToken, "bearer " + laptopToken} {
		cs := r.connect(t, "", clientOpts{aggregate: true, header: header})
		if got := serversOf(t, cs); !slices.Equal(got, []string{"alpha", "pub"}) {
			t.Errorf("%q lists %v", header, got)
		}
	}
	// Without access to any server, or with a wrong token, the route is closed.
	for _, header := range []string{"Bearer wrong", "Bearer " + adminToken} {
		if _, err := r.dial(t, "", clientOpts{aggregate: true, header: header}); err == nil {
			t.Errorf("%q connects", header)
		}
	}
	code, _, body := r.get(t, "POST", "/mcp", "Bearer wrong")
	if code != 401 || body != "Unauthorized\n" {
		t.Errorf("wrong token: %d %q", code, body)
	}
}

func TestAggregateParity(t *testing.T) {
	const secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	r := aggregateGate(t)
	var progress atomic.Int32
	var changed atomic.Int32
	watcher := r.connect(t, "", clientOpts{aggregate: true, version: "2026-07-28", changed: func() { changed.Add(1) }})
	cs := r.connect(t, "", clientOpts{aggregate: true, version: "2026-07-28", progress: func(req *mcp.ProgressNotificationClientRequest) {
		if req.Params.ProgressToken == "tok" {
			progress.Add(1)
		}
	}})

	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "alpha__echo", Arguments: map[string]any{"text": "token " + secret}})
	if err != nil {
		t.Fatal(err)
	}
	if got := textOf(t, res); strings.Contains(got, secret) || !strings.Contains(got, "[REDACTED:github_token]") {
		t.Errorf("not redacted: %q", got)
	}
	if l := r.lastCall("tool", "echo"); l["server"] != "alpha" || l["redactions"] != float64(1) {
		t.Errorf("audit line: %v", l)
	}
	if strings.Contains(r.logs.String(), secret) {
		t.Error("the secret reached the log")
	}
	if _, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "alpha__badblob"}); err == nil || !strings.Contains(err.Error(), "withheld") {
		t.Errorf("badblob: %v", err)
	}

	params := &mcp.CallToolParams{Name: "alpha__progress", Arguments: map[string]any{"steps": 3, "ms": 20}}
	params.SetProgressToken("tok")
	if _, err := cs.CallTool(t.Context(), params); err != nil {
		t.Fatal(err)
	}
	if progress.Load() == 0 {
		t.Error("no progress through the aggregate")
	}

	// A change in a member's catalog reaches the aggregate and its listening clients. A tool whose
	// prefixed name is over 64 characters is served only on the server's own route.
	long := strings.Repeat("x", 60)
	for _, name := range []string{"fresh", long} {
		if _, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "alpha__addtool", Arguments: map[string]any{"name": name}}); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for !slices.Contains(toolNames(t, cs), "alpha__fresh") || changed.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("alpha__fresh not listed or no list_changed (%d)", changed.Load())
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = watcher
	if res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "alpha__fresh"}); err != nil || textOf(t, res) != "fresh" {
		t.Errorf("alpha__fresh: %v %v", res, err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for !slices.Contains(toolNames(t, r.connect(t, "alpha", clientOpts{})), long) {
		if time.Now().After(deadline) {
			t.Fatal("the long tool is not listed on alpha's route")
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, name := range toolNames(t, cs) {
		if len(name) > 64 {
			t.Errorf("the aggregate lists %q", name)
		}
	}
	if _, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "alpha__" + long}); err == nil {
		t.Error("the long tool was called through the aggregate")
	}
	if l := r.lastCall("tool", long); l["server"] != "alpha" || l["outcome"] != "denied" {
		t.Errorf("audit line of the long tool: %v", l)
	}
}

// TestAggregateTimeoutsAndCancellation checks that a member's callTimeout and a client giving up
// end the downstream call through the aggregate as on the member's route, and that the Host check
// applies to /mcp.
func TestAggregateTimeoutsAndCancellation(t *testing.T) {
	r := startGate(t, configDoc("listen: {allowedHosts: [127.0.0.1]}\naggregate: {}\n", map[string]string{
		"slow": stdioServer(t, testkit.Fake{}, "callTimeout: 300ms\n"),
		"s":    stdioServer(t, testkit.Fake{}, "callTimeout: 5s\n"),
	}), gateOpts{})
	r.waitReady(t, "slow")
	r.waitReady(t, "s")
	cs := r.connect(t, "", clientOpts{aggregate: true, version: "2026-07-28"})
	start := time.Now()
	if _, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "slow__hang"}); err == nil || !strings.Contains(err.Error(), "did not answer in time") {
		t.Errorf("slow__hang: %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("callTimeout took %s", d)
	}
	cancelled := func() int {
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "s__stats"})
		if err != nil {
			t.Fatal(err)
		}
		var st struct{ Cancelled int }
		_ = json.Unmarshal([]byte(textOf(t, res)), &st)
		return st.Cancelled
	}
	start = time.Now()
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	_, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "s__hang"})
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("s__hang: %v", err)
	}
	for cancelled() == 0 {
		if time.Since(start) > 4*time.Second {
			t.Fatal("the downstream call was not cancelled with the client")
		}
		time.Sleep(50 * time.Millisecond)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, r.base+"/mcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "other.example.com"
	req.Header.Set("Authorization", "Bearer "+laptopToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("another Host: %d", res.StatusCode)
	}
}

func TestAggregateResourceCollision(t *testing.T) {
	r := startGate(t, configDoc("aggregate: {servers: [one, two]}\n", map[string]string{
		"one":   stdioServer(t, testkit.Fake{Catalog: true}, ""),
		"two":   stdioServer(t, testkit.Fake{Catalog: true}, ""),
		"three": stdioServer(t, testkit.Fake{}, ""),
	}), gateOpts{})
	for _, s := range []string{"one", "two", "three"} {
		r.waitReady(t, s)
	}
	cs := r.connect(t, "", clientOpts{aggregate: true})
	if got := serversOf(t, cs); !slices.Equal(got, []string{"one", "two"}) {
		t.Errorf("servers %v; three is not in aggregate.servers", got)
	}
	// Both servers list fake://info and fake://items/{id}: a read could not tell which is meant.
	rs, err := cs.ListResources(t.Context(), nil)
	if err != nil || len(rs.Resources) != 0 {
		t.Errorf("resources listed by both are served: %v %v", rs, err)
	}
	for _, uri := range []string{"fake://info", "fake://items/7"} {
		if _, err := cs.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: uri}); err == nil {
			t.Errorf("%s was read", uri)
		}
	}
	if _, err := cs.GetPrompt(t.Context(), &mcp.GetPromptParams{Name: "two__greet"}); err != nil {
		t.Errorf("two__greet: %v", err)
	}
}

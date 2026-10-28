package gate_test

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/metrics"
	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

// metricsDoc is a config with admin tokens and the aggregate endpoint, where the token phone
// may not see the tool big of server-a; head adds keys and tools filters server-a.
func metricsDoc(t *testing.T, head, tools string) string {
	t.Helper()
	return configDoc("admin:\n  tokens: {owner: \"${ADMIN}\"}\naggregate: {}\n"+
		"policies:\n  phone:\n    servers:\n      server-a: {tools: {deny: [big]}}\n"+head, map[string]string{
		"server-a": stdioServer(t, testkit.Fake{Catalog: true}, "auth: {tokens: {phone: \"${PHONE}\"}}\n"+tools),
	})
}

// scrapeHost reads /_metrics on base without a token, with the Host header host.
func scrapeHost(t *testing.T, base, host string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/_metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	return res.StatusCode
}

// scrape reads path on base with an Authorization header, which may be empty.
func scrape(t *testing.T, base, path, header string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if header != "" {
		req.Header.Set("Authorization", header)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, string(body)
}

// metricsOf scrapes /_metrics on the listener with the admin token.
func (r *running) metricsOf(t *testing.T) string {
	t.Helper()
	code, _, body := scrape(t, r.base, "/_metrics", "Bearer "+adminToken)
	if code != http.StatusOK {
		t.Fatalf("/_metrics: %d", code)
	}
	return body
}

func hasLine(body, line string) bool {
	return strings.Contains("\n"+body, "\n"+line+"\n")
}

func TestMetrics(t *testing.T) {
	doc := metricsDoc(t, "metrics: {enabled: true, addr: '127.0.0.1:0'}\n", "")
	r := startGate(t, doc, gateOpts{escrowKey: "metrics-escrow-key-0123456789"})
	r.waitReady(t, "server-a")

	for _, h := range []string{"", "Bearer " + laptopToken} {
		if code, hdr, _ := scrape(t, r.base, "/_metrics", h); code != http.StatusUnauthorized || hdr.Get("Cache-Control") != "no-store" {
			t.Errorf("/_metrics with %q: %d %v", h, code, hdr)
		}
	}
	code, hdr, _ := scrape(t, r.base, "/_metrics", "Bearer "+adminToken)
	if code != http.StatusOK || hdr.Get("Content-Type") != metrics.ContentType || hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("/_metrics: %d %v", code, hdr)
	}

	cs := r.connect(t, "server-a", clientOpts{})
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "pass" + "word: Summer-Blue-77!"}})
	if err != nil || strings.Contains(textOf(t, res), "Summer") {
		t.Fatalf("echo = %v, %v", res, err)
	}
	if _, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "ghost-tool-xyz"}); err == nil {
		t.Error("an unknown tool was called")
	}
	if _, err := cs.GetPrompt(t.Context(), &mcp.GetPromptParams{Name: "greet", Arguments: map[string]string{"who": "x"}}); err != nil {
		t.Errorf("greet: %v", err)
	}
	// A tool the token's policy hides is counted as one the server does not have.
	phone := r.connect(t, "server-a", clientOpts{header: "Bearer " + phoneToken})
	if _, err := phone.CallTool(t.Context(), &mcp.CallToolParams{Name: "big"}); err == nil {
		t.Error("a hidden tool was called")
	}
	if code, _, _ := r.get(t, http.MethodGet, "/_status", "Bearer wrong"); code != http.StatusUnauthorized {
		t.Errorf("wrong admin token: %d", code)
	}
	if code, _, _ := r.get(t, http.MethodPost, "/server-a/mcp", "Bearer wrong"); code != http.StatusUnauthorized {
		t.Errorf("wrong token: %d", code)
	}
	if code, _, _ := r.get(t, http.MethodPost, config.AggregatePath, "Bearer wrong"); code != http.StatusUnauthorized {
		t.Errorf("wrong token on the aggregate: %d", code)
	}
	if code, _, _ := r.escrowGet(t, http.MethodGet, "/_escrow/kaaaaaaaaaa/meta", "Authorization", "Bearer wrong"); code != http.StatusUnauthorized {
		t.Errorf("wrong escrow key: %d", code)
	}
	if _, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "crash"}); err == nil {
		t.Error("the crashing call succeeded")
	}
	waitFor(t, "a counted restart", func() bool {
		return hasLine(r.metricsOf(t), `mcp_gate_downstream_restarts_total{server="server-a"} 1`)
	})
	r.waitReady(t, "server-a")
	waitFor(t, "ready again", func() bool {
		return hasLine(r.metricsOf(t), `mcp_gate_downstream_state{server="server-a",state="ready"} 1`)
	})

	counted := []string{
		`mcp_gate_build_info{version="test"} 1`,
		`mcp_gate_requests_total{server="server-a",kind="tool",name="echo",token="laptop",outcome="ok"} 1`,
		`mcp_gate_requests_total{server="server-a",kind="tool",name="(other)",token="laptop",outcome="denied"} 1`,
		`mcp_gate_requests_total{server="server-a",kind="tool",name="(other)",token="phone",outcome="denied"} 1`,
		`mcp_gate_requests_total{server="server-a",kind="prompt",name="greet",token="laptop",outcome="ok"} 1`,
		`mcp_gate_auth_failures_total{route="/_status"} 1`,
		`mcp_gate_request_duration_seconds_count{server="server-a",kind="tool",name="echo"} 1`,
		`mcp_gate_redactions_total{server="server-a"} 1`,
		`mcp_gate_escrow_stored_total 1`,
		`mcp_gate_escrow_entries 1`,
		`mcp_gate_auth_failures_total{route="/_escrow/"} 1`,
		`mcp_gate_auth_failures_total{route="/_metrics"} 2`,
		`mcp_gate_auth_failures_total{route="/mcp"} 1`,
		`mcp_gate_auth_failures_total{route="/server-a/mcp"} 1`,
		`mcp_gate_downstream_restarts_total{server="server-a"} 1`,
	}
	body := r.metricsOf(t)
	for _, line := range counted {
		if !hasLine(body, line) {
			t.Errorf("missing %s", line)
		}
	}
	if n := strings.Count(body, `mcp_gate_downstream_state{server="server-a",state=`); n != 7 || strings.Count(body, `mcp_gate_downstream_state{server="server-a",state="ready"} 1`) != 1 {
		t.Errorf("states:\n%s", body)
	}
	for _, leaked := range []string{"ghost-tool-xyz", `name="big"`, "Summer", adminToken, laptopToken} {
		if strings.Contains(body, leaked) {
			t.Errorf("/_metrics holds %q", leaked)
		}
	}

	// A reload that replaces the server's mirror keeps the counts; one that fails is counted.
	r.reload(t, metricsDoc(t, "metrics: {enabled: true, addr: '127.0.0.1:0'}\n", "tools: {deny: [sleep]}\n"))
	if err := r.g.Reload(t.Context(), func() (*config.Config, error) { return nil, errors.New("bad config") }); err == nil {
		t.Error("a failing load was applied")
	}
	body = r.metricsOf(t)
	for _, line := range append(counted,
		`mcp_gate_reloads_total{result="failure"} 1`,
		`mcp_gate_reloads_total{result="success"} 1`,
	) {
		if !hasLine(body, line) {
			t.Errorf("after the reloads, missing %s", line)
		}
	}

	// The loopback listener serves /_metrics without a token, and nothing else.
	lines := r.logs.lines("metrics listening")
	if len(lines) != 1 {
		t.Fatalf("metrics listening lines: %v", lines)
	}
	addr, _ := lines[0]["addr"].(string)
	own := "http://" + addr
	if code, _, body := scrape(t, own, "/_metrics", ""); code != http.StatusOK || !hasLine(body, counted[1]) {
		t.Errorf("loopback /_metrics: %d", code)
	}
	if code, _, _ := scrape(t, own, "/_status", "Bearer "+adminToken); code != http.StatusNotFound {
		t.Errorf("loopback /_status: %d", code)
	}
	// Only loopback Host names: a page that rebinds its own name to 127.0.0.1 gets 403.
	_, port, _ := strings.Cut(addr, ":")
	for host, want := range map[string]int{
		"evil.example.com:" + port: http.StatusForbidden, "evil.example.com": http.StatusForbidden,
		"localhost:" + port: http.StatusOK, "127.0.0.1": http.StatusOK, "[::1]:" + port: http.StatusOK, "[::1]": http.StatusOK,
	} {
		if code := scrapeHost(t, own, host); code != want {
			t.Errorf("loopback /_metrics with Host %q: %d, want %d", host, code, want)
		}
	}

	// Turning the endpoint off on the listener leaves the loopback listener as it is.
	r.reload(t, metricsDoc(t, "metrics: {addr: '127.0.0.1:0'}\n", ""))
	if code, _, _ := scrape(t, r.base, "/_metrics", "Bearer "+adminToken); code != http.StatusNotFound {
		t.Errorf("/_metrics off: %d", code)
	}
	if code, _, _ := scrape(t, own, "/_metrics", ""); code != http.StatusOK {
		t.Errorf("loopback /_metrics after the reload: %d", code)
	}
}

func TestMetricsOffByDefault(t *testing.T) {
	r := startGate(t, metricsDoc(t, "", ""), gateOpts{})
	r.waitReady(t, "server-a")
	if code, _, _ := scrape(t, r.base, "/_metrics", "Bearer "+adminToken); code != http.StatusNotFound {
		t.Errorf("/_metrics: %d", code)
	}
	if len(r.logs.lines("metrics listening")) != 0 {
		t.Error("a metrics listener was opened")
	}
}

package gate_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/compare"
	"github.com/vsem-azamat/mcp-gate/internal/downstream"
	"github.com/vsem-azamat/mcp-gate/internal/gate"
	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

const initializeBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25",` +
	`"capabilities":{},"clientInfo":{"name":"raw","version":"1"}}}`

// post sends an initialize request with the given Host and returns the status.
func (r *running) post(t *testing.T, path, host string) int {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, r.base+path, bytes.NewReader([]byte(initializeBody)))
	req.Host = host
	req.Header.Set("Authorization", "Bearer "+laptopToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	return res.StatusCode
}

func TestHostChecks(t *testing.T) {
	servers := func() map[string]string { return map[string]string{"s": stdioServer(t, testkit.Fake{}, "")} }
	direct := startGate(t, configDoc("", servers()), gateOpts{})
	proxied := startGate(t, configDoc("listen: {behindProxy: true}\n", servers()), gateOpts{})
	pinned := startGate(t, configDoc("listen: {behindProxy: true, allowedHosts: [mcp.example.com]}\n", servers()), gateOpts{})
	for _, r := range []*running{direct, proxied, pinned} {
		r.waitReady(t, "s")
	}
	for _, c := range []struct {
		r    *running
		host string
		want int
	}{
		{direct, "127.0.0.1", 200},
		{direct, "mcp.example.com", 403}, // the SDK's DNS-rebinding check
		{proxied, "mcp.example.com", 200},
		{pinned, "mcp.example.com", 200},
		{pinned, "MCP.example.com:443", 200},
		{pinned, "other.example.com", 403},
	} {
		if got := c.r.post(t, "/s/mcp", c.host); got != c.want {
			t.Errorf("Host %s: %d, want %d", c.host, got, c.want)
		}
	}
	// The health endpoints answer any Host.
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, pinned.base+"/_healthz", nil)
	req.Host = "other.example.com"
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Errorf("healthz with another Host: %d", res.StatusCode)
	}
}

func TestLearnedPinIsKept(t *testing.T) {
	dir := t.TempDir()
	doc := configDoc("", map[string]string{"legacy": stdioServer(t, testkit.Fake{SilentDiscover: true}, "")})
	tune := func(o *downstream.Options) { o.DiscoverTimeout = 500 * time.Millisecond }
	first := startGate(t, doc, gateOpts{stateDir: dir, tune: tune})
	first.waitReady(t, "legacy")
	if st := first.g.Status().Servers["legacy"]; st.LearnedPin != "2025-11-25" || !st.AutoPinned {
		t.Fatalf("status %+v", st)
	}
	first.stop()
	data, err := os.ReadFile(filepath.Join(dir, gate.PinsFile))
	if err != nil {
		t.Fatal(err)
	}
	var doc2 struct {
		Version int
		Pins    map[string]string
	}
	if err := json.Unmarshal(data, &doc2); err != nil || doc2.Pins["legacy"] != "2025-11-25" {
		t.Fatalf("pins file %s: %v", data, err)
	}
	r := startGate(t, doc, gateOpts{stateDir: dir, tune: func(o *downstream.Options) { o.DiscoverTimeout = time.Hour }})
	r.waitReady(t, "legacy")
	if st := r.g.Status().Servers["legacy"]; st.ProtocolVersion != "2025-11-25" || !st.AutoPinned {
		t.Errorf("after a restart: %+v", st)
	}
}

// TestCompareWithHub puts the gate in front of a fake hub, the way it replaces an mcp-proxy, and
// checks with compare that both serve the same catalog.
func TestCompareWithHub(t *testing.T) {
	cat := testkit.Catalog{
		Tools: []*mcp.Tool{
			{Name: "search", Description: "Search", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"q": map[string]any{"type": "string"}}}},
			{Name: "read", Title: "Read", InputSchema: map[string]any{"type": "object"}, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		},
		Prompts:           []*mcp.Prompt{{Name: "summary", Description: "Summarize"}},
		Resources:         []*mcp.Resource{{Name: "index", URI: "notes://index", MIMEType: "text/plain"}},
		ResourceTemplates: []*mcp.ResourceTemplate{{Name: "note", URITemplate: "notes://{id}"}},
	}
	hub := testkit.NewHub(t, testkit.HubOptions{Servers: map[string]testkit.Catalog{"notes": cat}, Token: "hub-token", PageSize: 1})
	url := strings.ReplaceAll(hub.URLTemplate(), "{server}", "notes")
	r := startGate(t, configDoc("", map[string]string{
		"notes": httpServer(url, "  headers: {Authorization: \"Bearer hub-token\"}\n"),
	}), gateOpts{})
	r.waitReady(t, "notes")
	a, err := compare.NewEndpoint(hub.URLTemplate(), "hub-token")
	if err != nil {
		t.Fatal(err)
	}
	b, err := compare.NewEndpoint(r.base+"/{server}/mcp", laptopToken)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := a.Catalog(t.Context(), "notes")
	if err != nil {
		t.Fatal(err)
	}
	cb, err := b.Catalog(t.Context(), "notes")
	if err != nil {
		t.Fatal(err)
	}
	diffs, err := compare.Diff(ca, cb)
	if err != nil || len(diffs) != 0 {
		t.Errorf("diffs %v %v", diffs, err)
	}
	if ca.Counts() != "2 tools, 1 prompt, 1 resource, 1 resource template" {
		t.Errorf("counts %s", ca.Counts())
	}
}

// TestShutdown checks that a listening client does not hold the shutdown, and that a call in
// flight finishes within the grace period with its progress.
func TestShutdown(t *testing.T) {
	r := startGate(t, configDoc("", map[string]string{"s": stdioServer(t, testkit.Fake{}, "")}), gateOpts{})
	r.waitReady(t, "s")
	_ = r.connect(t, "s", clientOpts{version: "2026-07-28", changed: func() {}})
	var progress atomic.Int32
	cs := r.connect(t, "s", clientOpts{version: "2026-07-28", progress: func(*mcp.ProgressNotificationClientRequest) { progress.Add(1) }})
	done := make(chan error, 1)
	go func() {
		params := &mcp.CallToolParams{Name: "progress", Arguments: map[string]any{"steps": 10, "ms": 100}}
		params.SetProgressToken("p")
		_, err := cs.CallTool(context.Background(), params)
		done <- err
	}()
	waitFor(t, "the call's first progress", func() bool { return progress.Load() > 0 })
	start := time.Now()
	r.stop()
	// The call has under a second left. A listen stream would hold the shutdown for its whole
	// 10 second grace, and an unused spare connection for 5 seconds.
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("shutdown took %s", d)
	}
	if err := <-done; err != nil {
		t.Errorf("the call in flight failed: %v", err)
	}
	if progress.Load() < 8 {
		t.Errorf("progress during the shutdown: %d", progress.Load())
	}
	if lines := r.logs.lines("calls still running at shutdown are cut off"); len(lines) != 0 {
		t.Errorf("cut off: %v", lines)
	}
}

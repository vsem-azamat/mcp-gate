package compare

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

func sampleCatalog() testkit.Catalog {
	return testkit.Catalog{
		Tools: []*mcp.Tool{
			{
				Name:        "search",
				Description: "Search the notes",
				InputSchema: map[string]any{
					"type":       "object",
					"properties": map[string]any{"q": map[string]any{"type": "string"}, "limit": map[string]any{"type": "integer", "maximum": 50}},
					"required":   []any{"q"},
				},
				Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
			},
			{Name: "read", InputSchema: map[string]any{"type": "object"}},
			{Name: "write", InputSchema: map[string]any{"type": "object"}},
		},
		Prompts:           []*mcp.Prompt{{Name: "summarise", Arguments: []*mcp.PromptArgument{{Name: "topic", Required: true}}}},
		Resources:         []*mcp.Resource{{URI: "notes://index", Name: "index", MIMEType: "text/plain"}},
		ResourceTemplates: []*mcp.ResourceTemplate{{URITemplate: "notes://{id}", Name: "note"}},
	}
}

func mustEndpoint(t *testing.T, template, token string) *Endpoint {
	t.Helper()
	e, err := NewEndpoint(template, token)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func mustCatalog(t *testing.T, src Source, server string) Catalog {
	t.Helper()
	cat, err := src.Catalog(t.Context(), server)
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

func assertNoDiff(t *testing.T, a, b Catalog) {
	t.Helper()
	if d := diffStrings(t, a, b); len(d) != 0 {
		t.Errorf("unexpected differences:\n%s", strings.Join(d, "\n"))
	}
}

func TestEndpointReadsEveryPage(t *testing.T) {
	t.Parallel()
	hub := testkit.NewHub(t, testkit.HubOptions{PageSize: 1, Servers: map[string]testkit.Catalog{"notes": sampleCatalog()}})
	cat := mustCatalog(t, mustEndpoint(t, hub.URLTemplate(), ""), "notes")
	if got, want := cat.Counts(), "3 tools, 1 prompt, 1 resource, 1 resource template"; got != want {
		t.Errorf("Counts() = %q, want %q", got, want)
	}
	var names []string
	for _, tool := range cat.Tools {
		names = append(names, tool.Name)
	}
	if got := strings.Join(names, ","); got != "read,search,write" {
		t.Errorf("tools = %s, want them sorted: read,search,write", got)
	}
}

func TestEndpointProtocolVersions(t *testing.T) {
	t.Parallel()
	ref := testkit.NewHub(t, testkit.HubOptions{Servers: map[string]testkit.Catalog{"notes": sampleCatalog()}})
	want := mustCatalog(t, mustEndpoint(t, ref.URLTemplate(), ""), "notes")
	for _, v := range []string{"2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"} {
		for _, jsonResponse := range []bool{false, true} {
			hub := testkit.NewHub(t, testkit.HubOptions{
				ProtocolVersions: []string{v},
				JSONResponse:     jsonResponse,
				Servers:          map[string]testkit.Catalog{"notes": sampleCatalog()},
			})
			got := mustCatalog(t, mustEndpoint(t, hub.URLTemplate(), ""), "notes")
			t.Run(fmt.Sprintf("%s json=%t", v, jsonResponse), func(t *testing.T) { assertNoDiff(t, want, got) })
		}
	}
}

func TestEndpointCapabilityNotAdvertised(t *testing.T) {
	t.Parallel()
	// The first hub serves prompts and resources but does not advertise them, so they are not
	// listed; the second advertises both with empty lists.
	hidden := testkit.NewHub(t, testkit.HubOptions{
		Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}},
		Servers:      map[string]testkit.Catalog{"notes": sampleCatalog()},
	})
	empty := testkit.NewHub(t, testkit.HubOptions{
		Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}, Prompts: &mcp.PromptCapabilities{}, Resources: &mcp.ResourceCapabilities{}},
		Servers:      map[string]testkit.Catalog{"notes": {Tools: sampleCatalog().Tools}},
	})
	assertNoDiff(t,
		mustCatalog(t, mustEndpoint(t, hidden.URLTemplate(), ""), "notes"),
		mustCatalog(t, mustEndpoint(t, empty.URLTemplate(), ""), "notes"))
}

func TestEndpointNumbersAsDecoded(t *testing.T) {
	t.Parallel()
	serve := func(schema string) Catalog {
		hub := testkit.NewHub(t, testkit.HubOptions{Servers: map[string]testkit.Catalog{
			"notes": {Tools: []*mcp.Tool{{Name: "t", InputSchema: json.RawMessage(schema)}}},
		}})
		return mustCatalog(t, mustEndpoint(t, hub.URLTemplate(), ""), "notes")
	}
	assertNoDiff(t, serve(`{"type":"object","maximum":10}`), serve(`{"type":"object","maximum":10.0}`))
}

func TestEndpointAdvertisesNoCapabilities(t *testing.T) {
	t.Parallel()
	// The server rejects every request and records the client capabilities of the discover and
	// initialize requests the SDK sends in turn.
	var mu sync.Mutex
	got := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			Params struct {
				Meta         map[string]json.RawMessage `json:"_meta"`
				Capabilities json.RawMessage            `json:"capabilities"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			mu.Lock()
			switch req.Method {
			case "server/discover":
				got[req.Method] = string(req.Params.Meta["io.modelcontextprotocol/clientCapabilities"])
			case "initialize":
				got[req.Method] = string(req.Params.Capabilities)
			}
			mu.Unlock()
		}
		http.Error(w, "no", http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)
	_, _ = mustEndpoint(t, srv.URL+"/{server}/mcp", "").Catalog(t.Context(), "notes")
	mu.Lock()
	defer mu.Unlock()
	for _, m := range []string{"server/discover", "initialize"} {
		if got[m] != "{}" {
			t.Errorf("%s client capabilities = %q, want {}", m, got[m])
		}
	}
}

func TestEndpointToken(t *testing.T) {
	t.Parallel()
	const token = "token-value-1234"
	hub := testkit.NewHub(t, testkit.HubOptions{Token: token, Servers: map[string]testkit.Catalog{"notes": sampleCatalog()}})

	mustCatalog(t, mustEndpoint(t, hub.URLTemplate(), token), "notes")
	if n := hub.Unauthorized(); n != 0 {
		t.Errorf("%d requests were rejected with the right token", n)
	}

	_, err := mustEndpoint(t, hub.URLTemplate(), "wrong-token-5678").Catalog(t.Context(), "notes")
	if err == nil {
		t.Fatal("Catalog with a wrong token succeeded")
	}
	if strings.Contains(err.Error(), "wrong-token-5678") {
		t.Errorf("error contains the token: %v", err)
	}
}

func TestEndpointTokenInErrorIsRedacted(t *testing.T) {
	t.Parallel()
	const token = "echoed-token-9999"
	// A server that echoes the Authorization header in a JSON-RPC error, which the SDK puts into
	// its error message.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID json.RawMessage `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"error":   map[string]any{"code": -32603, "message": "bad credentials: " + r.Header.Get("Authorization")},
		})
	}))
	t.Cleanup(srv.Close)
	_, err := mustEndpoint(t, srv.URL+"/{server}/mcp", token).Catalog(t.Context(), "notes")
	if err == nil {
		t.Fatal("Catalog succeeded")
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("error contains the token: %v", err)
	}
	if !strings.Contains(err.Error(), "bad credentials: Bearer "+redacted) {
		t.Errorf("error = %v, want the server's message with the token redacted", err)
	}
}

func TestEndpointDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	var leaked atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Add(1)
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(other.Close)
	redirect := httptest.NewServer(http.RedirectHandler(other.URL+"/mcp", http.StatusTemporaryRedirect))
	t.Cleanup(redirect.Close)

	if _, err := mustEndpoint(t, redirect.URL+"/{server}/mcp", "secret").Catalog(t.Context(), "notes"); err == nil {
		t.Fatal("Catalog through a redirect succeeded")
	}
	if leaked.Load() != 0 {
		t.Error("the token was sent to the redirect target")
	}
}

func TestEndpointCancelled(t *testing.T) {
	t.Parallel()
	hub := testkit.NewHub(t, testkit.HubOptions{Servers: map[string]testkit.Catalog{"notes": sampleCatalog()}})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := mustEndpoint(t, hub.URLTemplate(), "").Catalog(ctx, "notes"); err == nil {
		t.Error("Catalog with a cancelled context succeeded")
	}
}

func TestNewEndpoint(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		template string
		ok       bool
	}{
		{"https://mcp.example.com/{server}/mcp", true},
		{"http://127.0.0.1:9090/{server}/mcp", true},
		{"https://mcp.example.com/mcp", false},
		{"https://user:pass@mcp.example.com/{server}/mcp", false},
		{"https://mcp.example.com/{server}/mcp?key=x", false},
		{"https://mcp.example.com/{server}/mcp?", false},
		{"https://mcp.example.com/{server}/mcp#x", false},
		{"ftp://mcp.example.com/{server}", false},
		{"https:///{server}/mcp", false},
		{"https://{server}/mcp", false},
		{"https://{server}.example.com/mcp", false},
		{"https://mcp.example.com:{server}/mcp", false},
	} {
		_, err := NewEndpoint(tt.template, "")
		if (err == nil) != tt.ok {
			t.Errorf("NewEndpoint(%q) error = %v, want ok = %v", tt.template, err, tt.ok)
		}
	}
}

func TestEndpointURL(t *testing.T) {
	t.Parallel()
	e := mustEndpoint(t, "https://mcp.example.com/{server}/mcp", "")
	if got, want := e.URL("a b"), "https://mcp.example.com/a%20b/mcp"; got != want {
		t.Errorf("URL = %q, want %q", got, want)
	}
	if _, err := e.Catalog(t.Context(), "a/b"); err == nil {
		t.Error("Catalog accepted a server name with a slash")
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	t.Parallel()
	hub := testkit.NewHub(t, testkit.HubOptions{Servers: map[string]testkit.Catalog{"notes": sampleCatalog(), "empty": {}}})
	e := mustEndpoint(t, hub.URLTemplate(), "")
	live := map[string]Catalog{"notes": mustCatalog(t, e, "notes"), "empty": mustCatalog(t, e, "empty")}

	path := t.TempDir() + "/snap.json"
	if err := WriteSnapshot(path, live); err != nil {
		t.Fatal(err)
	}
	s, err := ReadSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(s.ServerNames(), ","); got != "empty,notes" {
		t.Errorf("ServerNames() = %s", got)
	}
	for name, cat := range live {
		assertNoDiff(t, cat, mustCatalog(t, s, name))
	}
	if _, err := s.Catalog(t.Context(), "missing"); err == nil {
		t.Error("Catalog of a server not in the snapshot succeeded")
	}
}

func TestReadSnapshotRejects(t *testing.T) {
	t.Parallel()
	for name, content := range map[string]string{
		"other version": `{"version":2,"servers":{}}`,
		"unknown field": `{"version":1,"servers":{},"extra":true}`,
		"trailing data": `{"version":1,"servers":{}} {}`,
		"not json":      `version: 1`,
		"unknown field in an entry": `{"version":1,"servers":{"s":{"tools":[{"name":"t","inputSchema":{},"extra":1}],` +
			`"prompts":[],"resources":[],"resourceTemplates":[]}}}`,
	} {
		path := t.TempDir() + "/snap.json"
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadSnapshot(path); err == nil {
			t.Errorf("%s: ReadSnapshot succeeded", name)
		}
	}
}

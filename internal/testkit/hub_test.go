package testkit

import (
	"net/http"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

func TestHub(t *testing.T) {
	t.Parallel()
	hub := NewHub(t, HubOptions{
		Token:    "secret",
		PageSize: 1,
		Servers: map[string]Catalog{
			"server-a": {Tools: []*mcp.Tool{
				{Name: "one", InputSchema: map[string]any{"type": "object"}},
				{Name: "two", InputSchema: map[string]any{"type": "object"}},
			}},
		},
	})
	endpoint := strings.ReplaceAll(hub.URLTemplate(), "{server}", "server-a")

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint:             endpoint,
		HTTPClient:           &http.Client{Transport: bearer{"secret"}},
		DisableStandaloneSSE: true,
	}
	cs, err := client.Connect(t.Context(), transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	var names []string
	for tool, err := range cs.Tools(t.Context(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, tool.Name)
	}
	if got := strings.Join(names, ","); got != "one,two" {
		t.Errorf("tools = %s, want one,two", got)
	}
	if _, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "one"}); err == nil {
		t.Error("CallTool succeeded, want an error")
	}

	noToken := &mcp.StreamableClientTransport{Endpoint: endpoint, DisableStandaloneSSE: true, MaxRetries: -1}
	if _, err := client.Connect(t.Context(), noToken, nil); err == nil {
		t.Error("Connect without a token succeeded")
	}
	if hub.Unauthorized() == 0 {
		t.Error("no request was rejected")
	}
	for _, v := range []string{"2025-11-25", "2025-06-18"} {
		narrowed := NewHub(t, HubOptions{ProtocolVersions: []string{v}, Servers: map[string]Catalog{"server-a": {}}})
		cs, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{
			Endpoint:             strings.ReplaceAll(narrowed.URLTemplate(), "{server}", "server-a"),
			DisableStandaloneSSE: true,
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := cs.InitializeResult().ProtocolVersion; got != v {
			t.Errorf("negotiated %s, want %s", got, v)
		}
		_ = cs.Close()
	}
	http.DefaultTransport.(*http.Transport).CloseIdleConnections() //nolint:forcetypeassert // the standard library's default transport
}

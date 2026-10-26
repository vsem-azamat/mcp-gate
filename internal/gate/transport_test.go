package gate_test

import (
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

// TestTransportFailureHidesURL checks that a call whose HTTP request cannot reach the server
// does not quote the server's URL to the client, with or without redaction.
func TestTransportFailureHidesURL(t *testing.T) {
	const pathMarker = "PATHMARK-zz9"
	for _, c := range []struct{ name, extra string }{
		{"redacted", ""},
		{"plain", "redact: {enabled: false}\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			fake := testkit.NewFakeHTTP(t, testkit.Fake{}, testkit.FakeHTTPOptions{})
			url := strings.TrimSuffix(fake.URL(), "/mcp") + "/" + pathMarker + "/mcp"
			r := startGate(t, configDoc("", map[string]string{"s": httpServer(url, c.extra)}), gateOpts{})
			r.waitReady(t, "s")
			cs := r.connect(t, "s", clientOpts{})
			fake.Close()
			res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "x"}})
			var got string
			switch {
			case err != nil:
				got = err.Error()
			case res != nil && len(res.Content) > 0:
				got = textOf(t, res)
			}
			if got == "" {
				t.Fatalf("the call did not fail: %v", res)
			}
			if strings.Contains(got, pathMarker) || !strings.Contains(got, "<servers.s.http.url>") {
				t.Errorf("the client got the server's URL: %q", got)
			}
			if strings.Contains(r.logs.String(), pathMarker) {
				t.Error("the server's URL reached the log")
			}
		})
	}
}

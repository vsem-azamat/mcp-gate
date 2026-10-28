package downstream

import (
	"fmt"
	"io"
	"net/url"
	"strings"
	"testing"
)

// FuzzSSEHideEndpoint checks that the session id of any message endpoint the origin check lets
// through is hidden in the error of a failed POST to it, as Go's HTTP client renders it.
func FuzzSSEHideEndpoint(f *testing.F) {
	for _, seed := range []string{
		"?sessionid=x", "/messages?sessionid=x", "https://MCP.example.com:443/m", "//mcp.example.com./m",
		"/a'b", "/x,https://other.example/y", "//user:pw@mcp.example.com/m", "/%41%2F?q=1#frag",
	} {
		f.Add(seed)
	}
	const configured = "https://mcp.example.com/sse"
	const marker = "SESSIONMARKER"
	s, err := New(Options{Name: "remote", HTTP: &HTTP{URL: configured, SSE: true}})
	if err != nil {
		f.Fatal(err)
	}
	base, err := url.Parse(configured)
	if err != nil {
		f.Fatal(err)
	}
	origin := originOf(base)
	f.Fuzz(func(t *testing.T, endpoint string) {
		u, err := base.Parse(endpoint) // as the SDK resolves the endpoint event
		if err != nil || originOf(u) != origin {
			return // the origin check refuses it
		}
		u.RawQuery = "sessionid=" + marker
		for _, rendered := range []string{u.String(), u.Redacted()} {
			text := fmt.Errorf("calling \"tools/call\": rejected by transport: %w", &url.Error{Op: "Post", URL: rendered, Err: io.EOF}).Error()
			if got := s.HideURL(text); strings.Contains(got, marker) {
				t.Errorf("HideURL(%q) = %q", text, got)
			}
		}
	})
}

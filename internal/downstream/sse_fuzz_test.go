package downstream

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// FuzzSSEHideEndpoint checks that the session id of any message endpoint a server can name,
// added to the endpoint's own query, is hidden in the error of a POST to it, as the SDK builds the
// request and the gate's HTTP client renders the error, whether the guard sends it or not.
func FuzzSSEHideEndpoint(f *testing.F) {
	for _, seed := range []string{
		"?sessionid=x", "/messages?sessionid=x", "https://MCP.example.com:443/m", "//mcp.example.com./m",
		"/a'b", "/x,https://other.example/y", "//user:pw@mcp.example.com/m", "/%41%2F?q=1#frag",
		"/m?a=|{}^`", "/m?a=x y", "https://other.example/m?a=1",
		"//user:pw@mcp.example.com/m?a=|b", "//user@mcp.example.com/m?a=<x>", "//u:p@other.example/m?a=|b",
	} {
		f.Add(seed)
	}
	const configured = "https://mcp.example.com/sse"
	const marker = "SESSIONMARKER"
	s, err := New(Options{Name: "remote", HTTP: &HTTP{URL: configured, SSE: true}})
	if err != nil {
		f.Fatal(err)
	}
	lt, ok := s.http.Transport.(*legacyTransport)
	if !ok {
		f.Fatalf("transport %T", s.http.Transport)
	}
	lt.next = roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, io.EOF })
	base, err := url.Parse(configured)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, endpoint string) {
		u, err := base.Parse(endpoint) // as the SDK resolves the endpoint event
		if err != nil {
			return
		}
		if u.RawQuery != "" {
			u.RawQuery += "&"
		}
		u.RawQuery += "sessionid=" + marker
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, u.String(), nil) // as the SDK posts
		if err != nil || len(req.URL.String()) > maxEndpointBytes {
			return // an overlong endpoint is refused, and never requested
		}
		resp, err := s.http.Do(req) // the gate's own client renders the error
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err == nil {
			t.Fatal("the request did not fail")
		}
		text := fmt.Errorf("calling \"tools/call\": rejected by transport: %w", err).Error()
		if got := s.HideURL(text); strings.Contains(got, marker) {
			t.Errorf("HideURL(%q) = %q", text, got)
		}
	})
}

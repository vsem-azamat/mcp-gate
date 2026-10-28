package downstream

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/oauth"
	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

func sseOptions(t *testing.T, f testkit.Fake) (Options, *testkit.FakeHTTP) {
	t.Helper()
	h := testkit.NewFakeHTTP(t, f, testkit.FakeHTTPOptions{SSE: true})
	return fast(Options{Name: "fake", HTTP: &HTTP{URL: h.URL(), SSE: true}}), h
}

// legacyVersions are the protocol versions the HTTP+SSE transport carries.
func legacyVersions() []string {
	var out []string
	for _, v := range mcp.SupportedProtocolVersions() {
		if v < StatelessVersion {
			out = append(out, v)
		}
	}
	return out
}

// TestSSEVersions connects to legacy servers of every version the transport carries. The
// servers leave server/discover unanswered and the discover sub-deadline is an hour, so a
// discover attempt would never connect.
func TestSSEVersions(t *testing.T) {
	t.Parallel()
	for _, v := range legacyVersions() {
		t.Run(v, func(t *testing.T) {
			t.Parallel()
			o, _ := sseOptions(t, testkit.Fake{ProtocolVersions: []string{v}, SilentDiscover: true})
			o.DiscoverTimeout = time.Hour
			o.OnPinLearned = func(string) { t.Error("a pin was learned") }
			s := start(t, o)
			st := waitReady(t, s)
			if st.ProtocolVersion != v || st.AutoPinned {
				t.Errorf("negotiated %s (auto-pinned %v), want %s", st.ProtocolVersion, st.AutoPinned, v)
			}
			mustEcho(t, s)
		})
	}
}

func TestSSEManualPin(t *testing.T) {
	t.Parallel()
	o, _ := sseOptions(t, testkit.Fake{})
	o.ProtocolVersion = "2025-06-18"
	s := start(t, o)
	if st := waitReady(t, s); st.ProtocolVersion != "2025-06-18" || st.AutoPinned {
		t.Errorf("status = %+v, want the pinned 2025-06-18", st)
	}
	mustEcho(t, s)
}

func TestSSEOversizedResponseFailsOnlyItsCall(t *testing.T) {
	t.Parallel()
	o, _ := sseOptions(t, testkit.Fake{ProtocolVersions: []string{"2024-11-05"}})
	o.MaxMessageBytes = 64 << 10
	s := start(t, o)
	waitReady(t, s)
	_, err := callTool(t, s, "big", map[string]any{"bytes": 1 << 20})
	if err == nil || !strings.Contains(err.Error(), "maxMessageBytes") {
		t.Errorf("big call: err = %v, want the size error", err)
	}
	mustEcho(t, s)
	if got, err := callTool(t, s, "big", map[string]any{"bytes": 32 << 10}); err != nil || len(got) != 32<<10 {
		t.Errorf("a response under the limit: %d bytes, %v", len(got), err)
	}
	if st := s.Status(); st.Restarts != 0 || st.Sessions != 1 || st.State != Ready {
		t.Errorf("the session did not survive: %+v", st)
	}
}

func TestSSEDownAndUp(t *testing.T) {
	t.Parallel()
	o, h := sseOptions(t, testkit.Fake{})
	o.ProbeInterval = 30 * time.Millisecond
	s := start(t, o)
	waitReady(t, s)
	h.SetDown(true)
	waitFor(t, s, "backoff", func(st Status) bool { return st.State == Backoff })
	h.SetDown(false)
	st := waitFor(t, s, "ready again", func(st Status) bool { return st.State == Ready && st.Restarts >= 1 })
	if st.Sessions < 2 {
		t.Errorf("sessions = %d, want a new stream", st.Sessions)
	}
	mustEcho(t, s)
}

func TestSSEFrozenServerIsRestarted(t *testing.T) {
	t.Parallel()
	o, _ := sseOptions(t, testkit.Fake{FreezeAfter: 300 * time.Millisecond})
	o.ProbeInterval = 50 * time.Millisecond
	o.ProbeTimeout = 40 * time.Millisecond
	s := start(t, o)
	waitFor(t, s, "a session", func(st Status) bool { return st.Sessions >= 1 })
	if st := waitFor(t, s, "a restart", func(st Status) bool { return st.Restarts >= 1 }); !strings.Contains(st.LastError, "probe") {
		t.Errorf("last error = %q", st.LastError)
	}
}

// TestSSEHeadersOnEveryRequest checks that the configured headers go on the stream's GET and on
// every POST of a message.
func TestSSEHeadersOnEveryRequest(t *testing.T) {
	t.Parallel()
	srv := mcp.NewServer(&mcp.Implementation{Name: "plain", Version: "test"}, nil)
	var mu sync.Mutex
	seen := map[string]int{}
	var missing atomic.Int32
	handler := mcp.NewSSEHandler(func(*http.Request) *mcp.Server { return srv }, nil)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "key-123" {
			missing.Add(1)
		}
		mu.Lock()
		seen[r.Method]++
		mu.Unlock()
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	o := fast(Options{Name: "fake", HTTP: &HTTP{URL: ts.URL + "/sse", SSE: true, Headers: map[string]string{"X-Api-Key": "key-123"}}})
	s := start(t, o)
	waitReady(t, s)
	mu.Lock()
	defer mu.Unlock()
	if seen[http.MethodGet] == 0 || seen[http.MethodPost] == 0 || missing.Load() != 0 {
		t.Errorf("requests %v, %d without the header", seen, missing.Load())
	}
}

// TestSSEForeignEndpoint has a server name a message endpoint on another host: nothing is sent
// there, with the headers or otherwise.
func TestSSEForeignEndpoint(t *testing.T) {
	t.Parallel()
	var reached atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(other.Close)
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "no", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "event: endpoint\ndata: %s/messages?sessionid=abc\n\n", other.URL)
		_ = http.NewResponseController(w).Flush()
		<-r.Context().Done()
	}))
	t.Cleanup(evil.Close)
	t.Cleanup(evil.CloseClientConnections) // runs first: ends the hanging stream
	o := fast(Options{Name: "evil", HTTP: &HTTP{URL: evil.URL + "/sse", SSE: true, Headers: map[string]string{"X-Api-Key": "key-123"}}})
	s := start(t, o)
	st := waitFor(t, s, "a failed connect", func(st Status) bool { return st.State == Backoff && st.LastError != "" })
	if !strings.Contains(st.LastError, "another origin") {
		t.Errorf("last error = %q", st.LastError)
	}
	if n := reached.Load(); n != 0 {
		t.Errorf("%d requests reached the other host", n)
	}
}

func TestSSEOAuth(t *testing.T) {
	t.Parallel()
	srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{SSE: true})
	store := oauth.NewStore(t.TempDir())
	o := oauthOptions(t, srv, store)
	o.HTTP.SSE = true
	o.ProbeInterval = 30 * time.Millisecond
	s := start(t, o)
	waitFor(t, s, "needs-login", func(st Status) bool { return st.State == NeedsLogin })
	if srv.Rejected() != 0 {
		t.Errorf("%d requests were sent without a grant", srv.Rejected())
	}
	g := srv.Login(t, store, "fake")
	waitReady(t, s)
	mustEcho(t, s)
	srv.RevokeAll()
	st := waitFor(t, s, "needs-login", func(st Status) bool { return st.State == NeedsLogin })
	if !strings.Contains(st.LastError, "invalid_grant") {
		t.Errorf("last error = %q", st.LastError)
	}
	for _, secret := range []string{g.AccessToken, g.RefreshToken} {
		if strings.Contains(st.LastError, secret) {
			t.Error("a token appears in the last error")
		}
	}
}

func TestSSEHideURL(t *testing.T) {
	t.Parallel()
	const u = "https://mcp.example.com:8443/k-secret/sse"
	s, err := New(Options{Name: "remote", HTTP: &HTTP{URL: u, SSE: true}})
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{
		`Post "https://mcp.example.com:8443/messages?sessionid=sess-secret": EOF`,
		`failed https://mcp.example.com:8443/k-secret/sse and https://mcp.example.com:8443/x?sessionid=sess-secret`,
		`{"url":"https:\/\/mcp.example.com:8443\/messages?sessionid=sess-secret"}`,
	} {
		got := s.HideURL(text)
		if strings.Contains(got, "secret") || !strings.Contains(got, "<servers.remote.http.url>") {
			t.Errorf("HideURL(%q) = %q", text, got)
		}
	}
	for _, text := range []string{"https://mcp.example.com.evil.example/other", "see https://other.example/x?sessionid=theirs"} {
		if got := s.HideURL(text); got != text {
			t.Errorf("a URL of another host was changed: %q", got)
		}
	}
}

// TestSSEHideURLSpellings hides the URLs of the server's host however they are spelled and
// wherever they stand: in other letter case, with any port, glued onto other URLs.
func TestSSEHideURLSpellings(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ configured, text string }{
		{"https://mcp.example.com/sse", `Post "https://mcp.example.com:443/messages?sessionid=sess-secret": EOF`},
		{"https://mcp.example.com/sse", `Post "https://MCP.example.com/messages?sessionid=sess-secret": EOF`},
		{"https://mcp.example.com/sse", `Post "HTTPS://mcp.example.com/messages?sessionid=sess-secret": EOF`},
		{"https://mcp.example.com/sse", `Post "https://mcp.example.com./messages?sessionid=sess-secret": EOF`},
		{"https://mcp.example.com:443/sse", `Post "https://mcp.example.com/messages?sessionid=sess-secret": EOF`},
		{"http://[::1]/sse", `Post "http://[::1]:80/messages?sessionid=sess-secret": EOF`},
		// The SDK's own endpoint: the stream's URL with the session id in its query.
		{"https://mcp.example.com/sse", `Post "https://mcp.example.com/sse?sessionid=sess-secret": EOF`},
		{"https://mcp.example.com/k-secret/sse", `Post "https://mcp.example.com/k-secret/sse?sessionid=sess-secret": EOF`},
		{"https://mcp.example.com", `Post "https://mcp.example.com/?sessionid=sess-secret": EOF`},
		{"https://mcp.example.com", `Post "https://mcp.example.com?sessionid=sess-secret": EOF`},
		// Glued onto another URL.
		{"https://mcp.example.com/sse", `https://other.example/x,https://mcp.example.com/messages?sessionid=sess-secret`},
		{"https://mcp.example.com/sse", `https://other.example/x|https://mcp.example.com/messages?sessionid=sess-secret`},
		{"https://mcp.example.com/sse", `[a](https://mcp.example.com/messages?sessionid=sess-secret)`},
		{"https://mcp.example.com/sse", `https://other.example/x?next=https://mcp.example.com/m?sessionid=sess-secret`},
		{"https://mcp.example.com/sse", `https://mcp.example.com/m?next=https://other.example/y&sessionid=sess-secret`},
		// Spellings of the host that the origin check refuses.
		{"https://mcp.example.com/sse", `Post "https://mcp.example.com:0443/messages?sessionid=sess-secret": refused`},
		{"https://mcp.example.com/sse", `Post "https://mcp.example.com../messages?sessionid=sess-secret": refused`},
		{"https://mcp.example.com/sse", `Post "https://user@mcp.example.com/messages?sessionid=sess-secret": refused`},
		{"https://mcp.example.com/sse", `Post "https://mcp.example.com/a'b?sessionid=sess-secret": EOF`},
	} {
		s, err := New(Options{Name: "remote", HTTP: &HTTP{URL: c.configured, SSE: true}})
		if err != nil {
			t.Fatal(err)
		}
		if got := s.HideURL(c.text); strings.Contains(got, "secret") || !strings.Contains(got, "<servers.remote.http.url>") {
			t.Errorf("url %s: HideURL(%q) = %q", c.configured, c.text, got)
		}
	}
}

func TestOriginOf(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"https://mcp.example.com/sse", "https://mcp.example.com:443/messages", true},
		{"https://mcp.example.com/sse", "HTTPS://MCP.Example.COM/messages", true},
		{"http://[::1]/sse", "http://[::1]:80/messages", true},
		{"https://mcp.example.com/sse", "https://mcp.example.com./messages", true},
		{"http://mcp.example.com/sse", "https://mcp.example.com/messages", false},
		{"https://mcp.example.com/sse", "https://mcp.example.com:8443/messages", false},
		{"https://mcp.example.com/sse", "https://mcp.example.com.evil.example/messages", false},
		{"http://[::1]/sse", "http://[::2]/messages", false},
	} {
		ua, err := url.Parse(c.a)
		if err != nil {
			t.Fatal(err)
		}
		ub, err := url.Parse(c.b)
		if err != nil {
			t.Fatal(err)
		}
		if got := originOf(ua) == originOf(ub); got != c.same {
			t.Errorf("%s and %s: same origin %v, want %v (%s, %s)", c.a, c.b, got, c.same, originOf(ua), originOf(ub))
		}
	}
}

// TestSSEOAuthRefreshAndResend has the server reject an expired access token mid-session: the
// request is sent again with a refreshed token, and the session goes on.
func TestSSEOAuthRefreshAndResend(t *testing.T) {
	t.Parallel()
	srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{SSE: true})
	store := oauth.NewStore(t.TempDir())
	srv.Login(t, store, "fake")
	o := oauthOptions(t, srv, store)
	o.HTTP.SSE = true
	s := start(t, o)
	waitReady(t, s)
	mustEcho(t, s)
	srv.ExpireAccess()
	mustEcho(t, s)
	if n := srv.Refreshes(); n != 1 {
		t.Errorf("%d refreshes, want 1", n)
	}
	if st := s.Status(); st.Restarts != 0 || st.Sessions != 1 || st.State != Ready {
		t.Errorf("the session did not survive: %+v", st)
	}
}

// TestSSEOAuthForbidden has the server refuse the token with 403: the call fails naming the
// scopes, and the server, whose probes fail too, is restarted and waits in backoff.
func TestSSEOAuthForbidden(t *testing.T) {
	t.Parallel()
	srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{SSE: true})
	store := oauth.NewStore(t.TempDir())
	srv.Login(t, store, "fake")
	o := oauthOptions(t, srv, store)
	o.HTTP.SSE = true
	o.ProbeInterval = 30 * time.Millisecond
	s := start(t, o)
	waitReady(t, s)
	srv.Refuse(http.StatusForbidden)
	if _, err := callTool(t, s, "echo", map[string]any{"text": "x"}); err == nil || !strings.Contains(err.Error(), "scopes may not cover it") {
		t.Errorf("call refused with 403: err = %v", err)
	}
	waitFor(t, s, "backoff", func(st Status) bool { return st.State == Backoff && st.Restarts >= 1 })
}

// TestSSEFailedPostFailsOnlyItsCall has the server answer one tools/call POST with 500: that
// call fails as rejected by the transport, and the same session serves the next call.
func TestSSEFailedPostFailsOnlyItsCall(t *testing.T) {
	t.Parallel()
	srv := mcp.NewServer(&mcp.Implementation{Name: "plain", Version: "test"}, nil)
	type echoArgs struct {
		Text string `json:"text"`
	}
	mcp.AddTool(srv, &mcp.Tool{Name: "echo"}, func(_ context.Context, _ *mcp.CallToolRequest, in echoArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: in.Text}}}, nil, nil
	})
	handler := mcp.NewSSEHandler(func(*http.Request) *mcp.Server { return srv }, nil)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read", http.StatusBadRequest)
				return
			}
			if bytes.Contains(body, []byte("fail-this-post")) {
				http.Error(w, "boom", http.StatusInternalServerError)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	t.Cleanup(ts.CloseClientConnections) // runs first: ends the hanging stream
	s := start(t, fast(Options{Name: "fake", HTTP: &HTTP{URL: ts.URL + "/sse", SSE: true}}))
	waitReady(t, s)
	_, err := callTool(t, s, "echo", map[string]any{"text": "fail-this-post"})
	var werr *jsonrpc.Error
	if !errors.As(err, &werr) || werr.Code != rejectedByTransport {
		t.Errorf("failed POST: err = %v, want code %d", err, rejectedByTransport)
	}
	mustEcho(t, s)
	if st := s.Status(); st.Restarts != 0 || st.Sessions != 1 || st.State != Ready {
		t.Errorf("the session did not survive: %+v", st)
	}
}

// TestSSEPostConnectionClosed has the server close the connection on one tools/call POST: the
// failure, an EOF inside the POST's error, fails only that call, and the session goes on.
func TestSSEPostConnectionClosed(t *testing.T) {
	t.Parallel()
	srv := mcp.NewServer(&mcp.Implementation{Name: "plain", Version: "test"}, nil)
	type echoArgs struct {
		Text string `json:"text"`
	}
	mcp.AddTool(srv, &mcp.Tool{Name: "echo"}, func(_ context.Context, _ *mcp.CallToolRequest, in echoArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: in.Text}}}, nil, nil
	})
	handler := mcp.NewSSEHandler(func(*http.Request) *mcp.Server { return srv }, nil)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read", http.StatusBadRequest)
				return
			}
			if bytes.Contains(body, []byte("drop-this-post")) {
				conn, _, err := http.NewResponseController(w).Hijack()
				if err == nil {
					_ = conn.Close()
				}
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	t.Cleanup(ts.CloseClientConnections) // runs first: ends the hanging stream
	s := start(t, fast(Options{Name: "fake", HTTP: &HTTP{URL: ts.URL + "/sse", SSE: true}}))
	waitReady(t, s)
	_, err := callTool(t, s, "echo", map[string]any{"text": "drop-this-post"})
	var werr *jsonrpc.Error
	if !errors.As(err, &werr) || werr.Code != rejectedByTransport {
		t.Errorf("dropped POST: err = %v, want code %d", err, rejectedByTransport)
	}
	mustEcho(t, s)
	if st := s.Status(); st.Restarts != 0 || st.Sessions != 1 || st.State != Ready {
		t.Errorf("the session did not survive: %+v", st)
	}
}

// failingConn is an mcp.Connection whose writes fail with err.
type failingConn struct {
	mcp.Connection
	err error
}

func (c failingConn) Write(context.Context, jsonrpc.Message) error { return c.err }

// TestSSEFailedWriteForgetsTheRequest checks that a call whose POST fails leaves no pending id,
// whatever the failure.
func TestSSEFailedWriteForgetsTheRequest(t *testing.T) {
	t.Parallel()
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, c := range []struct {
		name string
		ctx  context.Context
		err  error
	}{
		{"closed", t.Context(), io.EOF},
		{"post failed", t.Context(), &url.Error{Op: "Post", URL: "http://mcp.example.com/m", Err: io.EOF}},
		{"cancelled", cancelled, context.Canceled},
	} {
		p := newPendingCalls()
		conn := &sseConn{Connection: failingConn{err: c.err}, pending: p, cancel: func() {}}
		id, err := jsonrpc.MakeID(float64(7))
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.Write(c.ctx, &jsonrpc.Request{ID: id, Method: "tools/call"}); err == nil {
			t.Fatalf("%s: the write succeeded", c.name)
		}
		if p.has(id) {
			t.Errorf("%s: the request is still pending", c.name)
		}
	}
}

// TestSSEHideHostIsLinear hides URLs in a 1 MiB text of URLs glued together, as a server could
// put in an error, in time linear in its length.
func TestSSEHideHostIsLinear(t *testing.T) {
	t.Parallel()
	s, err := New(Options{Name: "remote", HTTP: &HTTP{URL: "https://mcp.example.com/sse", SSE: true}})
	if err != nil {
		t.Fatal(err)
	}
	for _, unit := range []string{"https://a", "https://mcp.example.comx", "http:\\/\\/a", "https://mcp.example.com/"} {
		text := strings.Repeat(unit, (1<<20)/len(unit))
		began := time.Now()
		got := s.HideURL(text)
		if d := time.Since(began); d > 5*time.Second {
			t.Errorf("%q repeated: HideURL took %s", unit, d)
		}
		if strings.HasSuffix(unit, "/") && strings.Contains(got, "mcp.example.com") {
			t.Errorf("%q repeated: a URL of the host is left", unit)
		}
	}
}

// TestSSEHideRequestedEndpoint hides the session id of a message endpoint whose query holds
// characters a URL does not, which Go sends as they are: the URL as requested is replaced whole.
func TestSSEHideRequestedEndpoint(t *testing.T) {
	t.Parallel()
	for _, query := range []string{"a=|{}^`", "a=<b>", "a=x y", `a="q"`, "a=é"} {
		s, err := New(Options{Name: "remote", HTTP: &HTTP{URL: "https://mcp.example.com/sse", SSE: true}})
		if err != nil {
			t.Fatal(err)
		}
		lt, ok := s.http.Transport.(*legacyTransport)
		if !ok {
			t.Fatalf("transport %T", s.http.Transport)
		}
		lt.next = roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, io.EOF })
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://mcp.example.com/messages?"+query+"&sessionid=sess-secret", nil)
		if err != nil {
			t.Fatalf("%q: %v", query, err)
		}
		resp, rtErr := lt.RoundTrip(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		text := (&url.Error{Op: "Post", URL: req.URL.Redacted(), Err: rtErr}).Error()
		if got := s.HideURL(text); strings.Contains(got, "secret") || !strings.Contains(got, "<servers.remote.http.url>") {
			t.Errorf("HideURL(%q) = %q", text, got)
		}
	}
}

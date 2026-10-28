package upstream

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

func TestTokens(t *testing.T) {
	tokens := NewTokens(map[string]string{"laptop": "secret-a", "phone": "secret-b"})
	for secret, want := range map[string]string{"secret-a": "laptop", "secret-b": "phone", "secret-c": "", "": "", "secret-": ""} {
		name, ok := tokens.lookup(secret)
		if name != want || ok != (want != "") {
			t.Errorf("lookup(%q) = %q %v, want %q", secret, name, ok, want)
		}
	}
	var none *Tokens
	if _, ok := none.lookup("x"); ok {
		t.Error("a nil token set matched")
	}
}

func TestCredential(t *testing.T) {
	for header, want := range map[string]string{
		"Bearer abc":   "abc",
		"bearer abc":   "abc",
		"BEARER  abc ": "abc",
		"abc":          "abc",
		" abc ":        "abc",
		"Bearer":       "Bearer",
		"":             "",
		"Basic abc":    "Basic abc",
	} {
		if got := credential(header); got != want {
			t.Errorf("credential(%q) = %q, want %q", header, got, want)
		}
	}
}

func TestRequireToken(t *testing.T) {
	var principal string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal = Principal(auth.TokenInfoFromContext(r.Context()))
		w.WriteHeader(http.StatusNoContent)
	})
	rejected := 0
	h := RequireToken(NewTokens(map[string]string{"laptop": "secret-a"}), func() { rejected++ }, next)
	for _, c := range []struct {
		header string
		code   int
	}{
		{"Bearer secret-a", http.StatusNoContent},
		{"secret-a", http.StatusNoContent},
		{"bearer secret-a", http.StatusNoContent},
		{"Bearer secret-b", http.StatusUnauthorized},
		{"Bearer secret-a extra", http.StatusUnauthorized},
		{"", http.StatusUnauthorized},
	} {
		principal = ""
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/s/mcp", nil)
		if c.header != "" {
			req.Header.Set("Authorization", c.header)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.code {
			t.Errorf("%q: status %d, want %d", c.header, rec.Code, c.code)
		}
		if c.code == http.StatusUnauthorized && rec.Body.String() != "Unauthorized\n" {
			t.Errorf("%q: body %q", c.header, rec.Body.String())
		}
		if c.code == http.StatusNoContent && principal != "laptop" {
			t.Errorf("%q: principal %q", c.header, principal)
		}
	}
	if rejected != 3 {
		t.Errorf("rejected called %d times, want 3", rejected)
	}
	if Principal(nil) != "" {
		t.Error("Principal(nil) is not empty")
	}
}

func TestAllowHosts(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h := AllowHosts([]string{"mcp.example.com", "other.example.com:8443", "[::1]"}, next)
	for host, want := range map[string]int{
		"mcp.example.com":        http.StatusNoContent,
		"MCP.example.com:443":    http.StatusNoContent,
		"other.example.com:8443": http.StatusNoContent,
		"other.example.com":      http.StatusForbidden,
		"evil.example.com":       http.StatusForbidden,
		"[::1]:9090":             http.StatusNoContent,
	} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/s/mcp", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("Host %s: %d, want %d", host, rec.Code, want)
		}
	}
	if got := AllowHosts(nil, next); got == nil {
		t.Error("AllowHosts(nil) returned nil")
	}
}

func TestRemote(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("10.0.0.0/8")}
	cases := []struct {
		behind bool
		peer   string
		xff    []string
		want   string
	}{
		{false, "127.0.0.1:5000", []string{"192.0.2.1"}, "127.0.0.1"},
		{true, "127.0.0.1:5000", nil, "127.0.0.1"},
		{true, "127.0.0.1:5000", []string{"192.0.2.1"}, "192.0.2.1"},
		{true, "127.0.0.1:5000", []string{"198.51.100.7, 192.0.2.1, 10.1.1.1"}, "192.0.2.1"},
		{true, "127.0.0.1:5000", []string{"198.51.100.7", "192.0.2.1"}, "192.0.2.1"},
		{true, "127.0.0.1:5000", []string{"10.1.1.1"}, "127.0.0.1"},
		{true, "127.0.0.1:5000", []string{"192.0.2.1, junk"}, "127.0.0.1"},
		{true, "192.0.2.9:5000", []string{"198.51.100.7"}, "192.0.2.9"}, // an untrusted peer
		{true, "[::ffff:127.0.0.1]:5000", []string{"192.0.2.1"}, "192.0.2.1"},
	}
	for _, c := range cases {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		req.RemoteAddr = c.peer
		for _, v := range c.xff {
			req.Header.Add("X-Forwarded-For", v)
		}
		if got := NewRemote(c.behind, trusted)(req); got != c.want {
			t.Errorf("behind %v, peer %s, XFF %v: %s, want %s", c.behind, c.peer, c.xff, got, c.want)
		}
	}
}

func TestReadBody(t *testing.T) {
	var got, peeked []byte
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peeked, _ = BodyBytes(r)
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	})
	h := ReadBody(8, time.Second, next)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader("12345678")))
	if rec.Code != http.StatusNoContent || string(got) != "12345678" || string(peeked) != "12345678" {
		t.Errorf("a body at the limit: %d %q %q", rec.Code, got, peeked)
	}
	if _, ok := BodyBytes(httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader("x"))); ok {
		t.Error("BodyBytes of a body ReadBody did not read")
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader("123456789")))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("a body over the limit: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	if rec.Code != http.StatusNoContent {
		t.Errorf("no body: %d", rec.Code)
	}
}

func TestRecover(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	h := Recover(logger, "s", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("secret-value") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status %d", rec.Code)
	}
	if strings.Contains(logs.String(), "secret-value") || !strings.Contains(logs.String(), "handler panicked") {
		t.Errorf("log %q", logs.String())
	}
}

func TestHealthHandler(t *testing.T) {
	info := HealthInfo{Name: "gate", Version: "v1", ServerCount: 2}
	const prefix = `{"name":"gate","serverCount":2,"status":`
	cases := []struct {
		name string
		rep  *Readiness
		code int
		body string
	}{
		{"liveness", nil, http.StatusOK, prefix + `"ok","version":"v1"}`},
		{"initializing", &Readiness{}, http.StatusServiceUnavailable, prefix + `"initializing","version":"v1"}`},
		{"ok", &Readiness{Started: true, Mounted: 2}, http.StatusOK, prefix + `"ok","version":"v1"}`},
		{"one mounted", &Readiness{Started: true, Mounted: 1}, http.StatusOK, prefix + `"ok","version":"v1"}`},
		{"degraded", &Readiness{Started: true, Mounted: 2, Unhealthy: []string{"a"}}, http.StatusServiceUnavailable, prefix + `"degraded","unhealthy":["a"],"version":"v1"}`},
		{"unavailable", &Readiness{Started: true}, http.StatusServiceUnavailable, prefix + `"unavailable","version":"v1"}`},
		{"needs login", &Readiness{Started: true, Mounted: 1, NeedsLogin: []string{"b"}}, http.StatusServiceUnavailable, prefix + `"degraded","needsLogin":["b"],"version":"v1"}`},
		{"only needs login", &Readiness{Started: true, NeedsLogin: []string{"b"}}, http.StatusServiceUnavailable, prefix + `"unavailable","needsLogin":["b"],"version":"v1"}`},
	}
	for _, c := range cases {
		var readiness func() Readiness
		if c.rep != nil {
			rep := *c.rep
			readiness = func() Readiness { return rep }
		}
		h := HealthHandler(info, readiness)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/_readyz", nil))
		if rec.Code != c.code || strings.TrimSpace(rec.Body.String()) != c.body || rec.Header().Get("Content-Type") != "application/json" {
			t.Errorf("%s: %d %q", c.name, rec.Code, rec.Body.String())
		}
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodHead, "/_readyz", nil))
		if rec.Code != c.code || rec.Body.Len() != 0 {
			t.Errorf("%s: HEAD %d %q", c.name, rec.Code, rec.Body.String())
		}
	}
}

func TestStatusHandler(t *testing.T) {
	rejected := 0
	h := StatusHandler(NewTokens(map[string]string{"owner": "admin-secret"}), func() { rejected++ }, func() any { return map[string]int{"servers": 1} })
	for header, want := range map[string]int{"Bearer admin-secret": http.StatusOK, "admin-secret": http.StatusOK, "Bearer nope": http.StatusUnauthorized, "": http.StatusUnauthorized} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/_status", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want || rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%q: %d %v", header, rec.Code, rec.Header())
		}
		if want == http.StatusOK && !strings.Contains(rec.Body.String(), `"servers": 1`) {
			t.Errorf("%q: body %q", header, rec.Body.String())
		}
	}
	if rejected != 2 {
		t.Errorf("rejected called %d times, want 2", rejected)
	}
}

func TestLogRequests(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	h := LogRequests(logger, "s", func(*http.Request) string { return "192.0.2.1" },
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/s/mcp?key=secret-value", nil)
	req.Header.Set("Authorization", "Bearer secret-value")
	h.ServeHTTP(httptest.NewRecorder(), req)
	line := logs.String()
	if !strings.Contains(line, "status=418") || !strings.Contains(line, "remote=192.0.2.1") || strings.Contains(line, "secret-value") {
		t.Errorf("log %q", line)
	}
}

func TestSDKLogger(t *testing.T) {
	var logs bytes.Buffer
	logger := SDKLogger(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo})).With("server", "s"))
	logger.Info("session connected")
	logger.Warn("something odd")
	out := logs.String()
	if strings.Contains(out, "session connected") || !strings.Contains(out, `"level":"WARN"`) || !strings.Contains(out, `"server":"s"`) {
		t.Errorf("at info level: %q", out)
	}
	logs.Reset()
	logger = SDKLogger(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	logger.Info("session connected")
	if !strings.Contains(logs.String(), `"level":"DEBUG","msg":"session connected"`) {
		t.Errorf("at debug level: %q", logs.String())
	}
}

// acceptSignal reports each connection its listener accepts.
type acceptSignal struct {
	net.Listener
	accepted chan struct{}
}

func (l acceptSignal) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepted <- struct{}{}
	}
	return c, err
}

// TestShutdownClosesUnusedConns checks that a connection that has not sent a request does not
// hold the shutdown: http.Server.Shutdown alone waits 5 seconds for one, and HTTP clients open
// spare connections.
func TestShutdownClosesUnusedConns(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer("", http.NotFoundHandler(), slog.New(slog.DiscardHandler))
	served := make(chan error, 1)
	accepted := make(chan struct{}, 1)
	go func() { served <- srv.Serve(acceptSignal{ln, accepted}) }()
	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	<-accepted
	// Well under the 5 seconds net/http gives a new connection, well over a loaded runner's delays.
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("shutdown with an unused connection: %v", err)
	}
	if err := <-served; !errors.Is(err, http.ErrServerClosed) {
		t.Errorf("serve: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("the unused connection was not closed: %v", err)
	}
}

func TestAuthenticate(t *testing.T) {
	// The last three hold whitespace, which config validation refuses: the header check must
	// refuse them on its own.
	tokens := NewTokens(map[string]string{
		"laptop": "secret-a", "phone": "secret-b",
		"spaced": "secret-a extra", "tabbed": "secret-a\tb", "schemed": "Bearer\tsecret-a",
	})
	for header, want := range map[string]string{
		"Bearer secret-a":       "laptop",
		"bearer secret-b":       "phone",
		"BEARER  secret-a ":     "laptop",
		"secret-b":              "phone",
		"Bearer secret-c":       "",
		"Bearer secret-a extra": "",
		"Bearer secret-a\tb":    "",
		"Bearer\tsecret-a":      "",
		"Bearer":                "",
		"Bearer ":               "",
		"":                      "",
		"Basic secret-a":        "",
	} {
		got, ok := tokens.Authenticate(header)
		if got != want || ok != (want != "") {
			t.Errorf("Authenticate(%q) = %q %v, want %q", header, got, ok, want)
		}
	}
	var none *Tokens
	if _, ok := none.Authenticate("Bearer secret-a"); ok {
		t.Error("no tokens accept a header")
	}
}

func TestAuthorizeHidesTheSecret(t *testing.T) {
	var seen []string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Values("Authorization")
		w.WriteHeader(http.StatusNoContent)
	})
	h := RequireToken(NewTokens(map[string]string{"laptop": "secret-a"}), nil, next)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/s/mcp", nil)
	req.Header.Set("Authorization", "Bearer secret-a")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if len(seen) != 1 || strings.Contains(seen[0], "secret-a") {
		t.Errorf("the handler sees the header %q", seen)
	}
}

func TestAllowLoopbackHosts(t *testing.T) {
	h := AllowLoopbackHosts(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for host, want := range map[string]int{
		"localhost": http.StatusNoContent, "LOCALHOST:9464": http.StatusNoContent, "127.0.0.1:9464": http.StatusNoContent,
		"127.0.0.2": http.StatusNoContent, "[::1]": http.StatusNoContent, "[::1]:9464": http.StatusNoContent,
		"evil.example.com": http.StatusForbidden, "evil.example.com:9464": http.StatusForbidden, "192.0.2.1:9464": http.StatusForbidden, "": http.StatusForbidden,
	} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/_metrics", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("Host %q: %d, want %d", host, rec.Code, want)
		}
	}
}

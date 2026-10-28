package gate_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.uber.org/goleak"

	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/downstream"
	"github.com/vsem-azamat/mcp-gate/internal/escrow"
	"github.com/vsem-azamat/mcp-gate/internal/gate"
	"github.com/vsem-azamat/mcp-gate/internal/proxy"
	"github.com/vsem-azamat/mcp-gate/internal/redact"
	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

func TestMain(m *testing.M) {
	testkit.RunFake()
	goleak.VerifyTestMain(m)
}

// Tokens used by the tests.
const (
	laptopToken = "laptop-secret-0123456789"
	phoneToken  = "phone-secret-0123456789"
	adminToken  = "admin-secret-0123456789"
)

// logBuffer collects log lines safely.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// lines returns the decoded log lines whose msg is msg.
func (b *logBuffer) lines(msg string) []map[string]any {
	var out []map[string]any
	for line := range strings.SplitSeq(b.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

// running is a gate serving on a loopback port.
type running struct {
	g    *gate.Gate
	base string
	logs *logBuffer
	stop func() // shuts the gate down; the test's cleanup calls it too
}

// gateOpts adjusts a test gate.
type gateOpts struct {
	stateDir string
	replacer func(string, proxy.Request) redact.Replacer
	// escrowKey, if set, turns the escrow on with the SHA-256 of this key.
	escrowKey string
	tune      func(*downstream.Options)
	notify    func(string)
}

// startGate parses doc, a config with its listen address left out, and serves it until the test
// ends.
func startGate(t *testing.T, doc string, o gateOpts) *running {
	t.Helper()
	cfg := parseConfig(t, doc)
	logs := &logBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	tune := func(opts *downstream.Options) {
		opts.InitialBackoff = 50 * time.Millisecond
		opts.MaxBackoff = 200 * time.Millisecond
		opts.StopGrace = time.Second
		if o.tune != nil {
			o.tune(opts)
		}
	}
	var key *escrow.Key
	if o.escrowKey != "" {
		key = &escrow.Key{Hash: sha256.Sum256([]byte(o.escrowKey)), Source: escrow.KeyHashEnv}
	}
	g, err := gate.New(gate.Options{
		Config: cfg, Environ: []string{"PATH=/usr/bin:/bin"}, StateDir: o.stateDir, Version: "test", Logger: logger,
		Replacer: o.replacer, Tune: tune, EscrowKey: key, Notify: o.notify,
	})
	if err != nil {
		t.Fatal(err)
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Run(ctx, ln) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			// Idle connections would hold the shutdown's drain for its whole linger.
			http.DefaultClient.CloseIdleConnections()
			cancel()
			if err := <-done; err != nil {
				t.Errorf("gate: %v", err)
			}
		})
	}
	t.Cleanup(stop)
	return &running{g: g, base: "http://" + ln.Addr().String(), logs: logs, stop: stop}
}

// parseConfig parses doc, with the test tokens in its environment.
func parseConfig(t *testing.T, doc string) *config.Config {
	t.Helper()
	env := map[string]string{"LAPTOP": laptopToken, "PHONE": phoneToken, "ADMIN": adminToken}
	cfg, err := config.Parse([]byte(doc), func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

// waitReady waits until server answers something other than 503 on its route.
func (r *running) waitReady(t *testing.T, server string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if r.g.Status().Servers[server].Mounted {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server %s did not connect: %+v", server, r.g.Status().Servers[server])
}

// tokenTransport sets the Authorization header, or none when header is empty.
type tokenTransport struct {
	header string
	next   http.RoundTripper
}

func (tt tokenTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if tt.header != "" {
		r.Header.Set("Authorization", tt.header)
	}
	return tt.next.RoundTrip(r)
}

// clientOpts adjusts a test client.
type clientOpts struct {
	version  string // protocol version to offer; "" for the latest
	header   string // Authorization header; "" sends "Bearer <laptopToken>"
	noHeader bool
	// aggregate connects to the aggregate endpoint; the server name is then ignored.
	aggregate bool
	progress  func(*mcp.ProgressNotificationClientRequest)
	changed   func()
}

// connect opens a client session to server on the gate.
func (r *running) connect(t *testing.T, server string, o clientOpts) *mcp.ClientSession {
	t.Helper()
	cs, err := r.dial(t, server, o)
	if err != nil {
		t.Fatalf("connect %s: %v", server, err)
	}
	return cs
}

func (r *running) dial(t *testing.T, server string, o clientOpts) (*mcp.ClientSession, error) {
	t.Helper()
	header := o.header
	if header == "" && !o.noHeader {
		header = "Bearer " + laptopToken
	}
	base := &http.Transport{}
	t.Cleanup(base.CloseIdleConnections)
	copts := &mcp.ClientOptions{Capabilities: &mcp.ClientCapabilities{}}
	if o.progress != nil {
		f := o.progress
		copts.ProgressNotificationHandler = func(_ context.Context, req *mcp.ProgressNotificationClientRequest) { f(req) }
	}
	if o.changed != nil {
		f := o.changed
		copts.ToolListChangedHandler = func(context.Context, *mcp.ToolListChangedRequest) { f() }
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, copts)
	endpoint := r.base + "/" + server + "/mcp"
	if o.aggregate {
		endpoint = r.base + config.AggregatePath
	}
	var sopts *mcp.ClientSessionOptions
	if o.version != "" {
		sopts = &mcp.ClientSessionOptions{ProtocolVersion: o.version}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             endpoint,
		HTTPClient:           &http.Client{Transport: tokenTransport{header: header, next: base}},
		MaxRetries:           -1,
		DisableStandaloneSSE: true,
	}, sopts)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs, nil
}

// get performs a request with an optional Authorization header and returns status and body.
func (r *running) get(t *testing.T, method, path, header string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, r.base+path, nil)
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

// textOf returns the text of a tool result's first block.
func textOf(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatalf("empty result")
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("first block is %T", res.Content[0])
	}
	return tc.Text
}

// stdioServer returns the YAML of a stdio server running fake f.
func stdioServer(t *testing.T, f testkit.Fake, extra string) string {
	t.Helper()
	cmd, args := testkit.StdioCommand(t, f)
	a, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("    stdio:\n      command: %q\n      args: %s\n%s", cmd, a, indent(extra))
}

// httpServer returns the YAML of an HTTP server at url.
func httpServer(url, extra string) string {
	return fmt.Sprintf("    http:\n      url: %q\n%s", url, indent(extra))
}

// sseServer returns the YAML of a server at url on the legacy HTTP+SSE transport.
func sseServer(url, extra string) string {
	return fmt.Sprintf("    http:\n      url: %q\n      transport: sse\n%s", url, indent(extra))
}

func indent(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	for line := range strings.SplitSeq(strings.TrimRight(s, "\n"), "\n") {
		b.WriteString("    " + line + "\n")
	}
	return b.String()
}

// configDoc assembles a config with the global laptop token.
func configDoc(head string, servers map[string]string) string {
	var b strings.Builder
	b.WriteString("version: 1\nauth:\n  tokens: {laptop: \"${LAPTOP}\"}\n")
	b.WriteString(head)
	b.WriteString("servers:\n")
	for name, body := range servers {
		b.WriteString("  " + name + ":\n" + body)
	}
	return b.String()
}

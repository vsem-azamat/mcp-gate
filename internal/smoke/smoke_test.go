//go:build unix

package smoke_test

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.uber.org/goleak"

	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

// binaryFlag names the binary under test: the GoReleaser build hook passes the artifact it just
// built. Without it the test builds one from this checkout.
var binaryFlag = flag.String("binary", "", "mcp-gate binary to test; empty builds one from this checkout")

func TestMain(m *testing.M) {
	testkit.RunFake()
	goleak.VerifyTestMain(m)
}

const (
	clientToken = "smoke-client-0123456789"
	adminToken  = "smoke-admin-0123456789"
	escrowKey   = "smoke-escrow-key-0123456789abcdef"
	secret      = "Summer-Blue-77!"
	otherSecret = "Autumn-Red-42?" //nolint:gosec // a made-up password for the redaction check
	// stopWithin bounds a clean shutdown with nothing in flight; the unit's TimeoutStopSec
	// covers the worst case.
	stopWithin = 20 * time.Second
)

var markerRE = regexp.MustCompile(`\[REDACTED:password #(k[a-z2-7]{10})\]`)

// gateBinary returns the binary under test.
func gateBinary(t *testing.T) string {
	t.Helper()
	if *binaryFlag != "" {
		// go test runs in the package directory; a relative path is read from the module root,
		// where dist/ is.
		p := *binaryFlag
		if !filepath.IsAbs(p) {
			p = filepath.Join("..", "..", p)
		}
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("-binary: %v", err)
		}
		return p
	}
	out := filepath.Join(t.TempDir(), "mcp-gate")
	build := exec.CommandContext(t.Context(), "go", "build", "-trimpath", "-o", out, "github.com/vsem-azamat/mcp-gate/cmd/mcp-gate")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	return out
}

// logLines collects the gate's stderr and reports the address it listens on.
type logLines struct {
	mu    sync.Mutex
	lines []string
	addr  chan string
}

func (l *logLines) read(r io.Reader, done chan<- struct{}) {
	defer close(done)
	sent := false
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		l.mu.Lock()
		l.lines = append(l.lines, line)
		l.mu.Unlock()
		var m map[string]any
		if !sent && json.Unmarshal([]byte(line), &m) == nil && m["msg"] == "listening" {
			if a, ok := m["addr"].(string); ok {
				l.addr <- a
				sent = true
			}
		}
	}
}

func (l *logLines) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// messages returns the decoded lines whose msg is msg.
func (l *logLines) messages(msg string) []map[string]any {
	var out []map[string]any
	for line := range strings.SplitSeq(l.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

// TestBinary runs the binary as systemd does (state directory from $STATE_DIRECTORY, secrets in
// the environment) with a stdio fake that has a grandchild and an HTTP fake behind it, then
// checks health and readiness, listing and calls on both routes, redaction and an escrow round
// trip, /_status, and that SIGTERM stops the gate with status 0 and leaves no child behind.
func TestBinary(t *testing.T) {
	bin := gateBinary(t)
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}

	web := testkit.NewFakeHTTP(t, testkit.Fake{Name: "web"}, testkit.FakeHTTPOptions{})
	cmd, args := testkit.StdioCommand(t, testkit.Fake{Name: "local", Grandchild: true})
	argsJSON, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "gate.yaml")
	cfg := fmt.Sprintf(`version: 1
name: smoke
listen:
  addr: 127.0.0.1:0
auth:
  tokens: {client: "${SMOKE_CLIENT_TOKEN}"}
admin:
  tokens: {owner: "${SMOKE_ADMIN_TOKEN}"}
escrow:
  ttl: 1h
servers:
  local:
    stdio:
      command: %q
      args: %s
  web:
    http:
      url: %q
`, cmd, argsJSON, web.URL())
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	keyHash := sha256.Sum256([]byte(escrowKey))
	gate := exec.CommandContext(context.WithoutCancel(t.Context()), bin, "serve", cfgPath)
	gate.Env = []string{
		"PATH=/usr/bin:/bin",
		"STATE_DIRECTORY=" + stateDir,
		"SMOKE_CLIENT_TOKEN=" + clientToken,
		"SMOKE_ADMIN_TOKEN=" + adminToken,
		"MCP_HUB_ESCROW_KEY_SHA256=" + hex.EncodeToString(keyHash[:]), // the deprecated name, which deployments still use
	}
	stderr, err := gate.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.Start(); err != nil {
		t.Fatal(err)
	}
	logs := &logLines{addr: make(chan string, 1)}
	readDone := make(chan struct{})
	go logs.read(stderr, readDone)
	// exited is closed once the gate has exited; waitErr is then its result.
	exited := make(chan struct{})
	var waitErr error
	go func() {
		<-readDone // Wait closes the pipe; read it to the end first
		waitErr = gate.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		select {
		case <-exited:
		default:
			_ = gate.Process.Kill()
			<-exited
		}
	})

	var base string
	select {
	case addr := <-logs.addr:
		base = "http://" + addr
	case <-exited:
		t.Fatalf("the gate exited before listening: %v\n%s", waitErr, logs)
	case <-time.After(30 * time.Second):
		t.Fatalf("the gate did not listen\n%s", logs)
	}

	tr := &http.Transport{}
	t.Cleanup(tr.CloseIdleConnections)
	hc := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	get := func(path, auth string) (int, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		res, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(body)
	}

	if code, body := get("/_healthz", ""); code != http.StatusOK || !strings.Contains(body, `"status":"ok"`) {
		t.Errorf("/_healthz = %d %s", code, body)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		code, body := get("/_readyz", "")
		if code == http.StatusOK {
			var r struct {
				Name        string `json:"name"`
				ServerCount int    `json:"serverCount"`
				Status      string `json:"status"`
			}
			if err := json.Unmarshal([]byte(body), &r); err != nil || r.Name != "smoke" || r.ServerCount != 2 || r.Status != "ok" {
				t.Errorf("/_readyz = %s (%v)", body, err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("/_readyz = %d %s\n%s", code, body, logs)
		}
		time.Sleep(100 * time.Millisecond)
	}

	sessions := map[string]*mcp.ClientSession{}
	for _, name := range []string{"local", "web"} {
		cs := connect(t, tr, base+"/"+name+"/mcp")
		sessions[name] = cs
		var tools []string
		for tool, err := range cs.Tools(t.Context(), nil) {
			if err != nil {
				t.Fatalf("%s: tools/list: %v", name, err)
			}
			tools = append(tools, tool.Name)
		}
		if !slices.Contains(tools, "echo") || !slices.Contains(tools, "pids") {
			t.Errorf("%s: tools = %v", name, tools)
		}
		if got := callText(t, cs, "echo", map[string]any{"text": "hello " + name}); got != "hello "+name {
			t.Errorf("%s: echo = %q", name, got)
		}
		// Another secret than the one below: the escrow keeps a secret once per server.
		if got := callText(t, cs, "echo", map[string]any{"text": "password: " + otherSecret}); strings.Contains(got, otherSecret) || !markerRE.MatchString(got) {
			t.Errorf("%s: a secret in a result = %q, want it redacted and kept", name, got)
		}
	}

	// A kept secret is released to the escrow key, in the contract of the mcp-proxy escrow.
	local := sessions["local"]
	got := callText(t, local, "echo", map[string]any{"text": "the password: " + secret + " ok", "chat_id": 42})
	m := markerRE.FindStringSubmatch(got)
	if m == nil || got != "the password: "+m[0]+" ok" {
		t.Fatalf("echo = %q", got)
	}
	testkit.CheckEscrowContract(t, testkit.EscrowTarget{
		Base: base, Key: escrowKey, Handle: m[1], Secret: secret, TTL: time.Hour,
		Meta: map[string]any{
			"type": "password", "server": "local", "tool": "echo", "preview": "Summ…77!",
			"source": map[string]any{"chat_id": float64(42)},
		},
	})

	// The child gets neither the escrow key hash nor the gate's secrets.
	env := callText(t, local, "env", nil)
	for _, leak := range []string{"ESCROW_KEY_SHA256", "SMOKE_", "STATE_DIRECTORY"} {
		if strings.Contains(env, leak) {
			t.Errorf("the child's environment holds %s", leak)
		}
	}

	var pids struct{ PID, PGID, Grandchild int }
	if err := json.Unmarshal([]byte(callText(t, local, "pids", nil)), &pids); err != nil || pids.PID == 0 || pids.Grandchild == 0 || pids.PGID <= 1 || pids.PGID == syscall.Getpgrp() {
		t.Fatalf("pids = %+v (%v)", pids, err)
	}
	// If the test fails before the shutdown, the child's group would outlive it.
	t.Cleanup(func() { _ = syscall.Kill(-pids.PGID, syscall.SIGKILL) })
	code, body := get("/_status", adminToken)
	var st struct {
		Servers map[string]struct {
			State string `json:"state"`
			PID   int    `json:"pid"`
		} `json:"servers"`
	}
	if err := json.Unmarshal([]byte(body), &st); code != http.StatusOK || err != nil ||
		st.Servers["local"].State != "ready" || st.Servers["local"].PID != pids.PID || st.Servers["web"].State != "ready" {
		t.Errorf("/_status = %d %s", code, body)
	}
	if code, _ := get("/_status", clientToken); code != http.StatusUnauthorized && code != http.StatusForbidden {
		t.Errorf("/_status with a client token = %d", code)
	}
	for _, cs := range sessions {
		_ = cs.Close()
	}
	tr.CloseIdleConnections()

	// SIGTERM: a clean shutdown, status 0, and the child's whole process group gone.
	if err := gate.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exited:
		if waitErr != nil {
			t.Errorf("exit after SIGTERM: %v\n%s", waitErr, logs)
		}
	case <-time.After(stopWithin):
		t.Fatalf("the gate did not stop within %s\n%s", stopWithin, logs)
	}
	if strings.Contains(logs.String(), "no state directory") {
		t.Error("the gate did not take its state directory from $STATE_DIRECTORY")
	}
	if len(logs.messages("stopped")) != 1 {
		t.Errorf("no stopped line\n%s", logs)
	}
	// The deprecated variable name of a deployment that predates MCP_GATE_ESCROW_KEY_SHA256 still
	// turns the escrow on, with one warning.
	if w := logs.messages("MCP_HUB_ESCROW_KEY_SHA256 is deprecated; rename it MCP_GATE_ESCROW_KEY_SHA256"); len(w) != 1 || w[0]["level"] != "WARN" {
		t.Errorf("deprecation warnings = %v", w)
	}
	for what, pid := range map[string]int{"child": pids.PID, "grandchild": pids.Grandchild, "process group": -pids.PGID} {
		if err := gone(pid); err != nil {
			t.Errorf("%s %d: %v", what, pid, err)
		}
	}

	calls := logs.messages("call")
	if len(calls) == 0 || calls[0]["principal"] != "client" {
		t.Errorf("audit lines = %v", calls)
	}
	all := logs.String()
	for _, leak := range []string{secret, otherSecret, clientToken, adminToken, escrowKey, "hello local"} {
		if strings.Contains(all, leak) {
			t.Errorf("the log holds %q", leak)
		}
	}
}

// gone waits briefly for pid (a negative pid names a process group) to stop existing: a process
// reparented to init when the gate exits may need a moment to be reaped.
func gone(pid int) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return fmt.Errorf("kill 0: %w", err)
			}
			return errors.New("still exists")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// bearer sets the client token on every request.
type bearer struct{ next http.RoundTripper }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+clientToken)
	return b.next.RoundTrip(r)
}

func connect(t *testing.T, tr http.RoundTripper, endpoint string) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "smoke", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: endpoint, HTTPClient: &http.Client{Transport: bearer{tr}}, MaxRetries: -1, DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("connect %s: %v", endpoint, err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func callText(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) string {
	t.Helper()
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	if res.IsError || len(res.Content) == 0 {
		t.Fatalf("%s: %+v", tool, res)
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("%s: first block is %T", tool, res.Content[0])
	}
	return tc.Text
}

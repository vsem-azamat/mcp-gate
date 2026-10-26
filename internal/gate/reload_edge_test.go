package gate_test

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/systemd"
	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

// rawCall posts a tools/call of echo with a token, its body from body, and returns the status and
// the response.
func rawCall(r *running, token string, body io.Reader) (int, string) {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, r.base+"/s/mcp", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2025-06-18")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return -1, err.Error()
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

const revokedCall = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"revoked-but-ran"}}}`

func tokensDoc(srv, tokens, head string) string {
	return "version: 1\n" + head + "auth:\n  tokens: {" + tokens + "}\nservers:\n  s:\n" + srv
}

// TestReloadRevokesSlowBody checks that a request whose headers, with a token, arrived before a
// reload that revokes the token, and whose body arrives after it, runs nothing.
func TestReloadRevokesSlowBody(t *testing.T) {
	srv := stdioServer(t, testkit.Fake{}, "")
	r := startGate(t, tokensDoc(srv, `laptop: "${LAPTOP}", phone: "${PHONE}"`, ""), gateOpts{})
	r.waitReady(t, "s")
	pr, pw := io.Pipe()
	done := make(chan string, 1)
	go func() {
		code, body := rawCall(r, phoneToken, pr)
		done <- strconv.Itoa(code) + " " + body
	}()
	_, _ = pw.Write([]byte(revokedCall[:24]))
	time.Sleep(300 * time.Millisecond) // the headers reach the gate
	r.reload(t, tokensDoc(srv, `laptop: "${LAPTOP}"`, ""))
	_, _ = pw.Write([]byte(revokedCall[24:]))
	_ = pw.Close()
	if got := <-done; strings.Contains(got, "revoked-but-ran") || !strings.HasPrefix(got, "401") {
		t.Errorf("a token revoked while its body arrived: %s", got)
	}
}

// TestReloadRevokesHeldRequest checks that a request held during startup with a token that a
// reload then revokes runs nothing.
func TestReloadRevokesHeldRequest(t *testing.T) {
	srv := stdioServer(t, testkit.Fake{StartDelay: 1500 * time.Millisecond}, "")
	head := "startupGracePeriod: 20s\n"
	r := startGate(t, tokensDoc(srv, `laptop: "${LAPTOP}", phone: "${PHONE}"`, head), gateOpts{})
	done := make(chan string, 1)
	go func() {
		code, body := rawCall(r, phoneToken, strings.NewReader(revokedCall))
		done <- strconv.Itoa(code) + " " + body
	}()
	time.Sleep(300 * time.Millisecond) // the request is held
	r.reload(t, tokensDoc(srv, `laptop: "${LAPTOP}"`, head))
	if got := <-done; strings.Contains(got, "revoked-but-ran") || !strings.HasPrefix(got, "401") {
		t.Errorf("a held request of a revoked token: %s", got)
	}
}

// TestNoReadyAfterStopping checks that a reload that ends during the shutdown does not report
// READY=1 after STOPPING=1.
func TestNoReadyAfterStopping(t *testing.T) {
	var notified states
	srv := stdioServer(t, testkit.Fake{}, "")
	r := startGate(t, configDoc("", map[string]string{"s": withEnv(srv, "MODE=one")}), gateOpts{notify: notified.add})
	r.waitReady(t, "s")
	waitFor(t, "READY=1", func() bool { return len(notified.get()) == 1 })
	o, progressed := progressSignal(clientOpts{})
	cs := r.connect(t, "s", o)
	go func() { _ = slowCall(t, cs) }()
	awaitSignal(t, progressed)
	cfg := parseConfig(t, configDoc("", map[string]string{"s": withEnv(srv, "MODE=two")}))
	reloaded := make(chan error, 1)
	go func() {
		reloaded <- r.g.Reload(context.Background(), func() (*config.Config, error) { return cfg, nil })
	}()
	time.Sleep(200 * time.Millisecond) // the reload waits for the call
	r.stop()
	if err := <-reloaded; err != nil {
		t.Errorf("reload: %v", err)
	}
	got := notified.get()
	if i := slices.Index(got, systemd.Stopping); i < 0 || slices.Contains(got[i:], systemd.Ready) {
		t.Errorf("notifications %q", got)
	}
}

// TestSignalDuringReload checks that a reload whose context a signal cancels, as SIGTERM cancels
// serve's, still gives the servers it replaces their grace: a call in flight on one completes.
func TestSignalDuringReload(t *testing.T) {
	srv := stdioServer(t, testkit.Fake{}, "")
	r := startGate(t, configDoc("", map[string]string{"s": withEnv(srv, "MODE=one")}), gateOpts{})
	r.waitReady(t, "s")
	o, progressed := progressSignal(clientOpts{})
	cs := r.connect(t, "s", o)
	slow := make(chan error, 1)
	go func() { slow <- slowCall(t, cs) }()
	awaitSignal(t, progressed)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGUSR1)
	defer stop()
	cfg := parseConfig(t, configDoc("", map[string]string{"s": withEnv(srv, "MODE=two")}))
	reloaded := make(chan error, 1)
	go func() { reloaded <- r.g.Reload(ctx, func() (*config.Config, error) { return cfg, nil }) }()
	time.Sleep(100 * time.Millisecond) // the reload waits for the call
	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	if err := <-slow; err != nil {
		t.Errorf("the call on the replaced server: %v", err)
	}
	if err := <-reloaded; err != nil {
		t.Errorf("reload: %v", err)
	}
}

// TestReloadHoldsCallsWhileRestarting checks that a call to a server that a reload restarts is
// held until the server is back, not failed.
func TestReloadHoldsCallsWhileRestarting(t *testing.T) {
	srv := stdioServer(t, testkit.Fake{StartDelay: 500 * time.Millisecond}, "")
	r := startGate(t, configDoc("startupGracePeriod: 20s\n", map[string]string{"s": withEnv(srv, "MODE=one")}), gateOpts{})
	r.waitReady(t, "s")
	cs := r.connect(t, "s", clientOpts{})
	r.reload(t, configDoc("startupGracePeriod: 20s\n", map[string]string{"s": withEnv(srv, "MODE=two")}))
	if got, err := echoText(t, cs, "held"); err != nil || got != "held" {
		t.Errorf("a call while the server restarts: %q %v", got, err)
	}
}

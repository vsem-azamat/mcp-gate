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

// TestShutdownEndsStartupHold checks that a request held during startup is refused with 503 as
// soon as the shutdown begins, rather than held through its grace.
func TestShutdownEndsStartupHold(t *testing.T) {
	srv := stdioServer(t, testkit.Fake{StartDelay: 20 * time.Second}, "")
	r := startGate(t, tokensDoc(srv, `laptop: "${LAPTOP}"`, "startupGracePeriod: 30s\n"), gateOpts{})
	held := make(chan int, 1)
	go func() {
		code, _ := rawCall(r, laptopToken, strings.NewReader(revokedCall))
		held <- code
	}()
	time.Sleep(300 * time.Millisecond) // the request is held
	begun := time.Now()
	r.stop()
	if took := time.Since(begun); took > 5*time.Second {
		t.Errorf("the shutdown took %s", took)
	}
	if code := <-held; code != http.StatusServiceUnavailable {
		t.Errorf("the held request: %d", code)
	}
}

// TestShutdownEndsRestartHold checks the same for a call held while a reload restarts its server.
func TestShutdownEndsRestartHold(t *testing.T) {
	fast := stdioServer(t, testkit.Fake{}, "")
	slow := stdioServer(t, testkit.Fake{StartDelay: 25 * time.Second}, "")
	doc := func(srv string) string { return configDoc("startupGracePeriod: 30s\n", map[string]string{"s": srv}) }
	r := startGate(t, doc(fast), gateOpts{})
	r.waitReady(t, "s")
	cs := r.connect(t, "s", clientOpts{})
	r.reload(t, doc(slow))
	held := make(chan error, 1)
	go func() {
		_, err := echoText(t, cs, "x")
		held <- err
	}()
	time.Sleep(time.Second) // the call is held
	begun := time.Now()
	r.stop()
	if took := time.Since(begun); took > 5*time.Second {
		t.Errorf("the shutdown took %s", took)
	}
	select {
	case err := <-held:
		if err == nil {
			t.Error("the held call succeeded during the shutdown")
		}
	case <-time.After(5 * time.Second):
		t.Error("the held call was not answered")
	}
}

// TestHandOnToPublicRoute checks that a request a reload overtakes, handed on to a route the
// reload made public, keeps nothing of the old route's token check: its audit line names no
// principal, and the request line of the old route says it was handed on.
func TestHandOnToPublicRoute(t *testing.T) {
	srv := stdioServer(t, testkit.Fake{}, "log: {requests: true}\n")
	r := startGate(t, tokensDoc(srv, `laptop: "${LAPTOP}"`, ""), gateOpts{})
	r.waitReady(t, "s")
	pr, pw := io.Pipe()
	done := make(chan int, 1)
	go func() {
		code, _ := rawCall(r, laptopToken, pr)
		done <- code
	}()
	_, _ = pw.Write([]byte(revokedCall[:24]))
	time.Sleep(300 * time.Millisecond) // the headers reach the gate
	r.reload(t, tokensDoc(srv+"    auth: {public: true}\n", `laptop: "${LAPTOP}"`, ""))
	_, _ = pw.Write([]byte(revokedCall[24:]))
	_ = pw.Close()
	if code := <-done; code != http.StatusOK {
		t.Fatalf("the handed-on request: %d", code)
	}
	calls := r.logs.lines("call")
	if len(calls) != 1 || calls[0]["principal"] != "" {
		t.Errorf("audit lines %v", calls)
	}
	var handedOn int
	for _, l := range r.logs.lines("request") {
		if l["handedOn"] == true {
			handedOn++
		}
	}
	if handedOn != 1 {
		t.Errorf("request lines %v", r.logs.lines("request"))
	}
}

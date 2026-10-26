package gate_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/systemd"
	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

// reload parses doc and applies it to the running gate.
func (r *running) reload(t *testing.T, doc string) {
	t.Helper()
	cfg := parseConfig(t, doc)
	if err := r.g.Reload(t.Context(), func() (*config.Config, error) { return cfg, nil }); err != nil {
		t.Fatalf("reload: %v", err)
	}
}

// pidOf returns the process ID of a stdio fake.
func pidOf(t *testing.T, cs *mcp.ClientSession) int {
	t.Helper()
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "pids"})
	if err != nil {
		t.Fatal(err)
	}
	var p struct{ PID int }
	if err := json.Unmarshal([]byte(textOf(t, res)), &p); err != nil || p.PID == 0 {
		t.Fatalf("pids: %v", err)
	}
	return p.PID
}

func echoText(t *testing.T, cs *mcp.ClientSession, text string) (string, error) {
	t.Helper()
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": text}})
	if err != nil {
		return "", err
	}
	if res.IsError {
		return "", fmt.Errorf("tool error: %s", textOf(t, res))
	}
	return textOf(t, res), nil
}

// slowCall runs a call of about a second with progress, so that the test knows when it reached the
// server.
func slowCall(t *testing.T, cs *mcp.ClientSession) error {
	params := &mcp.CallToolParams{Name: "progress", Arguments: map[string]any{"steps": 5, "ms": 200}}
	params.SetProgressToken("slow")
	res, err := cs.CallTool(t.Context(), params)
	if err == nil && res.IsError {
		err = errors.New("tool error")
	}
	return err
}

// TestReloadTokens checks that a token removed by a reload is refused for new requests, while a
// call it began before the reload completes, and that other tokens keep working.
func TestReloadTokens(t *testing.T) {
	srv := stdioServer(t, testkit.Fake{}, "")
	doc := func(tokens string) string {
		return "version: 1\nauth:\n  tokens: {" + tokens + "}\nservers:\n  s:\n" + srv
	}
	r := startGate(t, doc(`laptop: "${LAPTOP}", phone: "${PHONE}"`), gateOpts{})
	r.waitReady(t, "s")
	laptop := r.connect(t, "s", clientOpts{})
	progressed := make(chan struct{}, 1)
	var steps atomic.Int64
	phone := r.connect(t, "s", clientOpts{header: "Bearer " + phoneToken, progress: func(*mcp.ProgressNotificationClientRequest) {
		steps.Add(1)
		select {
		case progressed <- struct{}{}:
		default:
		}
	}})
	slow := make(chan error, 1)
	go func() { slow <- slowCall(t, phone) }()
	awaitSignal(t, progressed)
	r.reload(t, doc(`laptop: "${LAPTOP}"`))
	before := steps.Load()
	if code, _, _ := r.get(t, http.MethodPost, "/s/mcp", "Bearer "+phoneToken); code != http.StatusUnauthorized {
		t.Errorf("a revoked token: %d", code)
	}
	if got, err := echoText(t, laptop, "still"); err != nil || got != "still" {
		t.Errorf("a kept token: %q %v", got, err)
	}
	// Before the session's next call: the SDK client fails a session's calls in flight once one
	// of its requests gets 401.
	if err := <-slow; err != nil {
		t.Errorf("the call the revoked token began before the reload: %v", err)
	}
	if steps.Load() <= before {
		t.Error("no progress of the call in flight after the reload")
	}
	if _, err := echoText(t, phone, "after"); err == nil {
		t.Error("a revoked token still calls")
	}
	if lines := r.logs.lines("config reloaded"); len(lines) != 1 {
		t.Errorf("reload lines: %v", lines)
	}
}

// TestReloadServers checks what a reload does to servers: one whose downstream settings are
// unchanged keeps its process and takes the new filters and redaction at once; one whose
// environment changed is restarted, after the call in flight on it has completed; a removed one
// is stopped and its route is gone; an added one starts.
func TestReloadServers(t *testing.T) {
	keep := stdioServer(t, testkit.Fake{}, "")
	changeCmd := stdioServer(t, testkit.Fake{}, "")
	added := stdioServer(t, testkit.Fake{}, "")
	removed := stdioServer(t, testkit.Fake{}, "")
	before := "version: 1\nauth:\n  tokens: {laptop: \"${LAPTOP}\"}\nservers:\n" +
		"  keep:\n" + keep +
		"  change:\n" + withEnv(changeCmd, "MODE=one") +
		"  removed:\n" + removed
	after := "version: 1\nauth:\n  tokens: {laptop: \"${LAPTOP}\"}\nservers:\n" +
		"  keep:\n" + keep + "    tools: {deny: [sleep]}\n    redact: {enabled: false}\n" +
		"  change:\n" + withEnv(changeCmd, "MODE=two") +
		"  added:\n" + added
	r := startGate(t, before, gateOpts{})
	for _, name := range []string{"keep", "change", "removed"} {
		r.waitReady(t, name)
	}
	keepCS := r.connect(t, "keep", clientOpts{})
	progressed := make(chan struct{}, 1)
	changeCS := r.connect(t, "change", clientOpts{progress: func(*mcp.ProgressNotificationClientRequest) {
		select {
		case progressed <- struct{}{}:
		default:
		}
	}})
	removedCS := r.connect(t, "removed", clientOpts{})
	keepPID, changePID, removedPID := pidOf(t, keepCS), pidOf(t, changeCS), pidOf(t, removedCS)
	const secret = "password: Summer-Blue-77!"
	if got, err := echoText(t, keepCS, secret); err != nil || strings.Contains(got, "Summer-Blue-77!") {
		t.Fatalf("before the reload: %q %v", got, err)
	}
	slow := make(chan error, 1)
	go func() { slow <- slowCall(t, changeCS) }()
	awaitSignal(t, progressed)
	r.reload(t, after)
	if err := <-slow; err != nil {
		t.Errorf("the call in flight on the changed server: %v", err)
	}

	// Kept: the same process, the new filter and redaction at once.
	if pid := pidOf(t, keepCS); pid != keepPID {
		t.Errorf("the unchanged server was restarted: pid %d, was %d", pid, keepPID)
	}
	fresh := r.connect(t, "keep", clientOpts{})
	if names := toolNames(t, fresh); slices.Contains(names, "sleep") || !slices.Contains(names, "echo") {
		t.Errorf("tools after the reload: %v", names)
	}
	if got, err := echoText(t, keepCS, secret); err != nil || got != secret {
		t.Errorf("redaction off after the reload: %q %v", got, err)
	}

	// Changed: a new process with the new environment.
	r.waitReady(t, "change")
	waitFor(t, "the changed server to be back", func() bool { _, err := echoText(t, changeCS, "x"); return err == nil })
	if pid := pidOf(t, changeCS); pid == changePID {
		t.Error("the changed server was not restarted")
	}
	res, err := changeCS.CallTool(t.Context(), &mcp.CallToolParams{Name: "env"})
	if err != nil || !strings.Contains(textOf(t, res), "MODE=two") {
		t.Errorf("env of the changed server: %v", err)
	}
	if !gone(changePID) {
		t.Errorf("the old process of the changed server %d is still running", changePID)
	}

	// Removed and added.
	if code, _, _ := r.get(t, http.MethodPost, "/removed/mcp", "Bearer "+laptopToken); code != http.StatusNotFound {
		t.Errorf("route of the removed server: %d", code)
	}
	if !gone(removedPID) {
		t.Errorf("the removed server's process %d is still running", removedPID)
	}
	if _, ok := r.g.Status().Servers["removed"]; ok {
		t.Error("/_status still shows the removed server")
	}
	r.waitReady(t, "added")
	if got, err := echoText(t, r.connect(t, "added", clientOpts{}), "new"); err != nil || got != "new" {
		t.Errorf("the added server: %q %v", got, err)
	}
}

// withEnv adds an env entry to the YAML of a stdio server.
func withEnv(server, kv string) string {
	k, v, _ := strings.Cut(kv, "=")
	return strings.Replace(server, "      args:", "      env: {"+k+": "+v+"}\n      args:", 1)
}

// gone waits briefly for a process to end.
func gone(pid int) bool {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// TestReloadAggregate checks that the aggregate endpoint takes the new tokens and members.
func TestReloadAggregate(t *testing.T) {
	a := stdioServer(t, testkit.Fake{}, "")
	b := stdioServer(t, testkit.Fake{}, "")
	doc := func(bTokens string) string {
		return "version: 1\nauth:\n  tokens: {laptop: \"${LAPTOP}\"}\naggregate: {}\nservers:\n  a:\n" + a +
			"  b:\n" + b + "    auth: {inherit: false, tokens: {" + bTokens + "}}\n"
	}
	r := startGate(t, doc(`phone: "${PHONE}"`), gateOpts{})
	r.waitReady(t, "a")
	r.waitReady(t, "b")
	names := func(header string) []string {
		return toolNames(t, r.connect(t, "", clientOpts{aggregate: true, header: header}))
	}
	if got := names("Bearer " + laptopToken); !slices.Contains(got, "a__echo") || slices.Contains(got, "b__echo") {
		t.Fatalf("laptop before: %v", got)
	}
	r.reload(t, doc(`laptop: "${LAPTOP}"`))
	if got := names("Bearer " + laptopToken); !slices.Contains(got, "a__echo") || !slices.Contains(got, "b__echo") {
		t.Errorf("laptop after: %v", got)
	}
	if code, _, _ := r.get(t, http.MethodPost, "/mcp", "Bearer "+phoneToken); code != http.StatusUnauthorized {
		t.Errorf("phone after: %d", code)
	}
}

// awaitSignal waits for a value on ch, at most 30 seconds.
func awaitSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(30 * time.Second):
		t.Fatal("timed out")
	}
}

// progressSignal returns client options that signal on the returned channel at each progress
// notification.
func progressSignal(o clientOpts) (clientOpts, <-chan struct{}) {
	ch := make(chan struct{}, 1)
	o.progress = func(*mcp.ProgressNotificationClientRequest) {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	return o, ch
}

// TestReloadKeepsUnchangedRoutes checks that a reload that changes nothing a route depends on
// keeps the route, so that a client listening for changes there goes on hearing of them.
func TestReloadKeepsUnchangedRoutes(t *testing.T) {
	a := stdioServer(t, testkit.Fake{}, "")
	b := stdioServer(t, testkit.Fake{}, "")
	doc := func(bExtra string) string {
		return "version: 1\nauth:\n  tokens: {laptop: \"${LAPTOP}\"}\nservers:\n  a:\n" + a + "  b:\n" + b + bExtra
	}
	r := startGate(t, doc(""), gateOpts{})
	r.waitReady(t, "a")
	r.waitReady(t, "b")
	changed := make(chan struct{}, 4)
	listener := r.connect(t, "a", clientOpts{changed: func() {
		select {
		case changed <- struct{}{}:
		default:
		}
	}})
	r.reload(t, doc("    tools: {deny: [sleep]}\n"))
	if _, err := listener.CallTool(t.Context(), &mcp.CallToolParams{Name: "addtool", Arguments: map[string]any{"name": "added"}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changed:
	case <-time.After(10 * time.Second):
		t.Error("the listening client of an unchanged route was not told of a change after the reload")
	}
}

// TestReloadWaitsForOlderSnapshots checks that a server changed by a second reload is stopped
// only after a call that began before the first one, on a route the first one replaced, ends.
func TestReloadWaitsForOlderSnapshots(t *testing.T) {
	srv := stdioServer(t, testkit.Fake{}, "")
	doc := func(tokens, env string) string {
		return "version: 1\nauth:\n  tokens: {" + tokens + "}\nservers:\n  s:\n" + withEnv(srv, env)
	}
	r := startGate(t, doc(`laptop: "${LAPTOP}"`, "MODE=one"), gateOpts{})
	r.waitReady(t, "s")
	o, progressed := progressSignal(clientOpts{})
	cs := r.connect(t, "s", o)
	slow := make(chan error, 1)
	go func() { slow <- slowCall(t, cs) }()
	awaitSignal(t, progressed)
	r.reload(t, doc(`laptop: "${LAPTOP}", phone: "${PHONE}"`, "MODE=one")) // replaces the route
	r.reload(t, doc(`laptop: "${LAPTOP}", phone: "${PHONE}"`, "MODE=two")) // restarts the server
	if err := <-slow; err != nil {
		t.Errorf("the call that began before both reloads: %v", err)
	}
}

// TestReloadAndShutdown checks that a reload waiting for a call ends when the shutdown begins,
// and that a reload after it is refused.
func TestReloadAndShutdown(t *testing.T) {
	srv := stdioServer(t, testkit.Fake{}, "")
	doc := func(env string) string {
		return "version: 1\nauth:\n  tokens: {laptop: \"${LAPTOP}\"}\nservers:\n  s:\n" + withEnv(srv, env)
	}
	r := startGate(t, doc("MODE=one"), gateOpts{})
	r.waitReady(t, "s")
	cs := r.connect(t, "s", clientOpts{})
	go func() {
		_, _ = cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "hang"})
	}()
	time.Sleep(200 * time.Millisecond) // the hanging call reaches the server
	reloaded := make(chan error, 1)
	cfg := parseConfig(t, doc("MODE=two"))
	go func() {
		reloaded <- r.g.Reload(context.Background(), func() (*config.Config, error) { return cfg, nil })
	}()
	time.Sleep(200 * time.Millisecond) // the reload waits for the call
	stopped := make(chan struct{})
	go func() { r.stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(30 * time.Second):
		t.Fatal("the shutdown waited for the reload")
	}
	if err := <-reloaded; err != nil {
		t.Errorf("the reload under way: %v", err)
	}
	if err := r.g.Reload(t.Context(), func() (*config.Config, error) { return cfg, nil }); err == nil {
		t.Error("a reload after the shutdown was taken")
	}
}

// TestReloadDuringStartup checks that a reload before startup is over applies without telling
// systemd, which hears READY=1 only once startup is over, and that one after it does.
func TestReloadDuringStartup(t *testing.T) {
	var notified states
	srv := stdioServer(t, testkit.Fake{StartDelay: 700 * time.Millisecond}, "")
	doc := "version: 1\nstartupGracePeriod: 20s\nauth:\n  tokens: {laptop: \"${LAPTOP}\"}\nservers:\n  s:\n" + srv
	r := startGate(t, doc, gateOpts{notify: notified.add})
	r.reload(t, doc)
	if got := notified.get(); len(got) != 0 {
		t.Errorf("notified %v during startup", got)
	}
	waitFor(t, "READY=1", func() bool { return slices.Equal(notified.get(), []string{systemd.Ready}) })
	r.reload(t, doc)
	got := notified.get()
	if len(got) != 3 || !strings.HasPrefix(got[1], "RELOADING=1\nMONOTONIC_USEC=") || got[2] != systemd.Ready {
		t.Errorf("notifications %q", got)
	}
}

// TestReloadUnderTraffic reloads repeatedly while clients call a server that the reloads keep,
// and checks that no call fails.
func TestReloadUnderTraffic(t *testing.T) {
	a := stdioServer(t, testkit.Fake{}, "")
	b := stdioServer(t, testkit.Fake{}, "")
	doc := func(i int) string {
		names := `laptop: "${LAPTOP}"`
		if i%2 == 1 {
			names += `, phone: "${PHONE}"`
		}
		return "version: 1\nauth:\n  tokens: {" + names + "}\naggregate: {}\nservers:\n  a:\n" + a + "  b:\n" + b +
			fmt.Sprintf("    tools: {deny: [tool%d]}\n", i)
	}
	r := startGate(t, doc(0), gateOpts{})
	r.waitReady(t, "a")
	r.waitReady(t, "b")
	stop := make(chan struct{})
	errs := make(chan error, 64)
	var calls atomic.Int64
	var wg sync.WaitGroup
	for k := range 4 {
		cs := r.connect(t, "a", clientOpts{})
		agg := r.connect(t, "", clientOpts{aggregate: true})
		wg.Go(func() {
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				if got, err := echoText(t, cs, fmt.Sprint(k, i)); err != nil || got != fmt.Sprint(k, i) {
					errs <- fmt.Errorf("route: %q %w", got, err)
					return
				}
				res, err := agg.CallTool(t.Context(), &mcp.CallToolParams{Name: "a__echo", Arguments: map[string]any{"text": "x"}})
				if err != nil || res.IsError {
					errs <- fmt.Errorf("aggregate: %v %w", res, err)
					return
				}
				calls.Add(1)
			}
		})
	}
	// b's catalog changes while the reloads replace its mirror, so its source syncs meanwhile.
	bcs := r.connect(t, "b", clientOpts{})
	wg.Go(func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := bcs.CallTool(t.Context(), &mcp.CallToolParams{Name: "addtool", Arguments: map[string]any{"name": fmt.Sprint("t", i)}}); err != nil {
				errs <- fmt.Errorf("addtool: %w", err)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	for i := 1; i <= 6; i++ {
		time.Sleep(50 * time.Millisecond)
		r.reload(t, doc(i))
	}
	close(stop)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if calls.Load() == 0 {
		t.Error("no call")
	}
}

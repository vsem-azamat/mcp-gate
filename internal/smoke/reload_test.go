//go:build unix

package smoke_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

// TestReload reloads the binary's config with SIGHUP, as systemctl reload does: an invalid config
// is rejected and the running one stays; a valid one revokes a token, lowers the log level and
// leaves the unchanged server running, and each reload is reported to systemd as RELOADING=1,
// then READY=1.
func TestReload(t *testing.T) {
	bin := gateBinary(t)
	dir := t.TempDir()
	cmd, args := testkit.StdioCommand(t, testkit.Fake{Name: "local"})
	argsJSON, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	const otherToken = "smoke-other-0123456789"
	config := func(logLevel, tokens string) string {
		return fmt.Sprintf(`version: 1
name: smoke
listen:
  addr: 127.0.0.1:0
logLevel: %s
auth:
  tokens: {%s}
servers:
  local:
    stdio:
      command: %q
      args: %s
`, logLevel, tokens, cmd, argsJSON)
	}
	cfgPath := filepath.Join(dir, "gate.yaml")
	write := func(doc string) {
		t.Helper()
		if err := os.WriteFile(cfgPath, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(config("info", `client: "${SMOKE_CLIENT_TOKEN}", other: "${SMOKE_OTHER_TOKEN}"`))
	notify := newNotifySocket(t, t.TempDir(), "notify")
	gate := startGate(t, exec.CommandContext(context.WithoutCancel(t.Context()), bin, "serve", cfgPath), []string{
		"PATH=/usr/bin:/bin",
		"SMOKE_CLIENT_TOKEN=" + clientToken,
		"SMOKE_OTHER_TOKEN=" + otherToken,
		"NOTIFY_SOCKET=" + notify.path,
	})
	var base string
	select {
	case addr := <-gate.logs.addr:
		base = "http://" + addr
	case <-gate.exited:
		t.Fatalf("the gate exited before listening: %v\n%s", gate.waitErr, gate.logs)
	case <-time.After(30 * time.Second):
		t.Fatalf("the gate did not listen\n%s", gate.logs)
	}
	notify.await(t, gate, "READY=1")

	tr := &http.Transport{}
	t.Cleanup(tr.CloseIdleConnections)
	status := func(token string) int {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/local/mcp", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		res, err := (&http.Client{Transport: tr}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		return res.StatusCode
	}
	cs := connect(t, tr, base+"/local/mcp")
	var pids struct{ PID int }
	if err := json.Unmarshal([]byte(callText(t, cs, "pids", nil)), &pids); err != nil || pids.PID == 0 {
		t.Fatalf("pids: %v", err)
	}
	hup := func() {
		t.Helper()
		if err := gate.cmd.Process.Signal(syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
		select {
		case reloading := <-notify.msgs:
			if !strings.HasPrefix(reloading, "RELOADING=1\nMONOTONIC_USEC=") {
				t.Errorf("first notification of a reload: %q", reloading)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("no RELOADING=1\n%s", gate.logs)
		}
		notify.await(t, gate, "READY=1")
	}

	// messages waits for a log line, which may reach the test after the notification.
	messages := func(msg string) []map[string]any {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			if m := gate.logs.messages(msg); len(m) > 0 || time.Now().After(deadline) {
				return m
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	// An invalid config: the running one stays.
	write("version: 1\nservers: {}\n")
	hup()
	if lines := messages("the config does not load; keeping the running one"); len(lines) != 1 || lines[0]["level"] != "ERROR" {
		t.Errorf("rejection lines: %v", lines)
	}
	if code := status(otherToken); code == http.StatusUnauthorized {
		t.Error("the rejected config was applied")
	}

	// A valid one: the other token is revoked, debug lines appear, the server keeps running.
	if strings.Contains(gate.logs.String(), `"level":"DEBUG"`) {
		t.Fatal("debug lines at level info")
	}
	write(config("debug", `client: "${SMOKE_CLIENT_TOKEN}"`))
	hup()
	if len(messages("config reloaded")) != 1 {
		t.Fatalf("no reload line\n%s", gate.logs)
	}
	if code := status(otherToken); code != http.StatusUnauthorized {
		t.Errorf("a revoked token: %d", code)
	}
	if got := callText(t, cs, "echo", map[string]any{"text": "still"}); got != "still" {
		t.Errorf("echo after the reload: %q", got)
	}
	var after struct{ PID int }
	if err := json.Unmarshal([]byte(callText(t, cs, "pids", nil)), &after); err != nil || after.PID != pids.PID {
		t.Errorf("the unchanged server was restarted: pid %d, was %d (%v)", after.PID, pids.PID, err)
	}
	if !strings.Contains(gate.logs.String(), `"level":"DEBUG"`) {
		t.Error("no debug line after logLevel: debug")
	}
	_ = cs.Close()
	tr.CloseIdleConnections()
	gate.stop(t)
	if strings.Contains(gate.logs.String(), otherToken) || strings.Contains(gate.logs.String(), clientToken) {
		t.Error("the log holds a token")
	}
}

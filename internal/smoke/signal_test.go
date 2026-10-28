//go:build unix

package smoke_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

// TestSecondSignalForcesExit checks that a second SIGINT during a shutdown that waits for a call
// in flight ends the gate at once, by the signal, and kills its children's process groups.
func TestSecondSignalForcesExit(t *testing.T) {
	cmd, args := testkit.StdioCommand(t, testkit.Fake{Name: "local", Grandchild: true})
	gate, base := serveOne(t, cmd, args)
	tr := &http.Transport{}
	t.Cleanup(tr.CloseIdleConnections)
	cs := connect(t, tr, base+"/local/mcp")
	var pids struct{ PID, PGID, Grandchild int }
	if err := json.Unmarshal([]byte(callText(t, cs, "pids", nil)), &pids); err != nil || pids.Grandchild == 0 || pids.PGID <= 1 {
		t.Fatalf("pids: %+v, %v", pids, err)
	}
	go func() { _, _ = cs.CallTool(context.WithoutCancel(t.Context()), &mcp.CallToolParams{Name: "hang"}) }()
	time.Sleep(300 * time.Millisecond) // the call reaches the server

	if err := gate.cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for len(gate.logs.messages("shutting down")) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the shutdown did not begin\n%s", gate.logs)
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case <-gate.exited:
		t.Fatalf("the gate exited before the second signal, without waiting for the call: %v", gate.waitErr)
	case <-time.After(500 * time.Millisecond):
	}
	if err := gate.cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case <-gate.exited:
	case <-time.After(3 * time.Second):
		t.Fatalf("the gate did not exit at the second signal\n%s", gate.logs)
	}
	var exit *exec.ExitError
	if !errors.As(gate.waitErr, &exit) {
		t.Fatalf("exit = %v", gate.waitErr)
	}
	if ws, ok := exit.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGINT {
		t.Errorf("exit = %v, want death by SIGINT", gate.waitErr)
	}
	// The child's process group is killed, its own child included.
	for what, pid := range map[string]int{"child": pids.PID, "grandchild": pids.Grandchild, "process group": -pids.PGID} {
		if err := gone(pid); err != nil {
			t.Errorf("the %s outlived the forced exit: %v", what, err)
		}
	}
}

// serveOne starts the binary with one stdio server, local, and returns it with its base URL.
func serveOne(t *testing.T, cmd string, args []string) (*process, string) {
	t.Helper()
	bin := gateBinary(t)
	argsJSON, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(t.TempDir(), "gate.yaml")
	doc := fmt.Sprintf("version: 1\nlisten:\n  addr: 127.0.0.1:0\nauth:\n  tokens: {client: \"${SMOKE_CLIENT_TOKEN}\"}\n"+
		"servers:\n  local:\n    stdio:\n      command: %q\n      args: %s\n", cmd, argsJSON)
	if err := os.WriteFile(cfgPath, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	gate := startGate(t, exec.CommandContext(context.WithoutCancel(t.Context()), bin, "serve", cfgPath), []string{
		"PATH=/usr/bin:/bin", "SMOKE_CLIENT_TOKEN=" + clientToken,
	})
	select {
	case addr := <-gate.logs.addr:
		return gate, "http://" + addr
	case <-gate.exited:
		t.Fatalf("the gate exited before listening: %v\n%s", gate.waitErr, gate.logs)
	case <-time.After(30 * time.Second):
		t.Fatalf("the gate did not listen\n%s", gate.logs)
	}
	return nil, ""
}

// TestSecondSignalKillsLeftGroup checks that a forced exit also kills the group of a server whose
// leader already exited: the shutdown closed its stdin, the server ended, and a member that
// ignores SIGTERM keeps the stop waiting.
func TestSecondSignalKillsLeftGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "member.pid")
	cmd, args := testkit.StdioCommand(t, testkit.Fake{Name: "local"})
	script := `(trap "" TERM; exec sleep 300) & echo $! > ` + pidFile + `; exec "$0" "$@"`
	gate, base := serveOne(t, "/bin/sh", append([]string{"-c", script, cmd}, args...))
	tr := &http.Transport{}
	t.Cleanup(tr.CloseIdleConnections)
	cs := connect(t, tr, base+"/local/mcp")
	callText(t, cs, "echo", map[string]any{"text": "up"})
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	member, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(member, syscall.SIGKILL) })

	if err := gate.cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond) // the server has exited; its stop waits for the member
	select {
	case <-gate.exited:
		t.Fatalf("the gate exited before the second signal: %v\n%s", gate.waitErr, gate.logs)
	default:
	}
	if err := gate.cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case <-gate.exited:
	case <-time.After(3 * time.Second):
		t.Fatalf("the gate did not exit at the second signal\n%s", gate.logs)
	}
	if err := gone(member); err != nil {
		t.Errorf("the member that ignores SIGTERM outlived the forced exit: %v", err)
	}
}

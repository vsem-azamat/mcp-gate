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
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

// TestSecondSignalForcesExit checks that a second SIGINT during a shutdown that waits for a call
// in flight ends the gate at once, by the signal.
func TestSecondSignalForcesExit(t *testing.T) {
	bin := gateBinary(t)
	dir := t.TempDir()
	cmd, args := testkit.StdioCommand(t, testkit.Fake{Name: "local"})
	argsJSON, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "gate.yaml")
	doc := fmt.Sprintf("version: 1\nlisten:\n  addr: 127.0.0.1:0\nauth:\n  tokens: {client: \"${SMOKE_CLIENT_TOKEN}\"}\n"+
		"servers:\n  local:\n    stdio:\n      command: %q\n      args: %s\n", cmd, argsJSON)
	if err := os.WriteFile(cfgPath, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	gate := startGate(t, exec.CommandContext(context.WithoutCancel(t.Context()), bin, "serve", cfgPath), []string{
		"PATH=/usr/bin:/bin", "SMOKE_CLIENT_TOKEN=" + clientToken,
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
	tr := &http.Transport{}
	t.Cleanup(tr.CloseIdleConnections)
	cs := connect(t, tr, base+"/local/mcp")
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
}

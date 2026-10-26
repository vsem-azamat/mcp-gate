//go:build unix

package smoke_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

// notifySocket is a socket that receives the sd_notify messages of one gate, as systemd's would.
type notifySocket struct {
	path string
	msgs chan string
}

func newNotifySocket(t *testing.T, dir, name string) *notifySocket {
	t.Helper()
	path := filepath.Join(dir, name)
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	n := &notifySocket{path: path, msgs: make(chan string, 16)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			k, err := conn.Read(buf)
			if err != nil {
				return
			}
			n.msgs <- string(buf[:k])
		}
	}()
	t.Cleanup(func() { _ = conn.Close(); <-done })
	return n
}

// await waits for the message want, which a gate that has exited must have sent already.
func (n *notifySocket) await(t *testing.T, p *process, want string) {
	t.Helper()
	timeout := time.After(30 * time.Second)
	for {
		select {
		case m := <-n.msgs:
			if m == want {
				return
			}
			continue
		default:
		}
		select {
		case m := <-n.msgs:
			if m == want {
				return
			}
		case <-p.exited:
			select {
			case m := <-n.msgs:
				if m == want {
					return
				}
				continue
			case <-time.After(time.Second):
			}
			t.Fatalf("the gate exited without %s: %v\n%s", want, p.waitErr, p.logs)
		case <-timeout:
			t.Fatalf("no %s\n%s", want, p.logs)
		}
	}
}

// traffic is a client that calls in a loop and counts what it sees.
type traffic struct {
	name          string
	ok, failed    atomic.Int64
	okAfter       atomic.Int64 // calls that succeeded after the restart
	firstFailure  atomic.Value
	afterRestart  *atomic.Bool
	call          func(ctx context.Context, i int) error
	stopped, done chan struct{}
}

func (tr *traffic) run(ctx context.Context) {
	defer close(tr.done)
	for i := 0; ; i++ {
		select {
		case <-tr.stopped:
			return
		default:
		}
		after := tr.afterRestart.Load()
		if err := tr.call(ctx, i); err != nil {
			tr.failed.Add(1)
			tr.firstFailure.CompareAndSwap(nil, err.Error())
			continue
		}
		tr.ok.Add(1)
		if after {
			tr.okAfter.Add(1)
		}
	}
}

// TestRestartUnderTraffic restarts the gate as systemd does with a socket unit: the test holds the
// listening socket, as systemd would, and passes it to each gate in LISTEN_FDS; it sends SIGTERM to
// the running gate, waits for it to exit and starts the next, which reports READY=1 on
// NOTIFY_SOCKET. Clients call tools without pause throughout, with retries off: clients connected
// before the restart keep their sessions, new clients connect on fresh connections, and a slow call
// is in flight at the SIGTERM. No connection may be refused and no call may fail.
func TestRestartUnderTraffic(t *testing.T) {
	bin := gateBinary(t)
	dir := t.TempDir()
	sockDir := t.TempDir()

	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tcp, ok := ln.(*net.TCPListener)
	if !ok {
		t.Fatalf("listener is %T", ln)
	}
	sock, err := tcp.File()
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	base := "http://" + ln.Addr().String()

	cmd, args := testkit.StdioCommand(t, testkit.Fake{Name: "local"})
	argsJSON, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "gate.yaml")
	cfg := fmt.Sprintf(`version: 1
name: smoke
listen:
  addr: %s
auth:
  tokens: {client: "${SMOKE_CLIENT_TOKEN}"}
servers:
  local:
    stdio:
      command: %q
      args: %s
`, ln.Addr(), cmd, argsJSON)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	// start runs a gate on the socket as systemd does: LISTEN_PID names the gate's own process,
	// which the shell keeps through exec.
	start := func(name string) (*process, *notifySocket) {
		t.Helper()
		notify := newNotifySocket(t, sockDir, name)
		c := exec.CommandContext(context.WithoutCancel(t.Context()), "/bin/sh", "-c",
			`LISTEN_PID=$$; export LISTEN_PID; exec "$0" "$@"`, bin, "serve", cfgPath)
		c.ExtraFiles = []*os.File{sock} // descriptor 3
		p := startGate(t, c, []string{
			"PATH=/usr/bin:/bin",
			"SMOKE_CLIENT_TOKEN=" + clientToken,
			"LISTEN_FDS=1",
			"LISTEN_FDNAMES=mcp-gate.socket",
			"NOTIFY_SOCKET=" + notify.path,
		})
		notify.await(t, p, "READY=1")
		return p, notify
	}

	old, oldNotify := start("old")

	keepAlive := &http.Transport{}
	t.Cleanup(keepAlive.CloseIdleConnections)
	fresh := &http.Transport{DisableKeepAlives: true}
	t.Cleanup(fresh.CloseIdleConnections)
	endpoint := base + "/local/mcp"

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	var afterRestart atomic.Bool
	var clients []*traffic
	add := func(name string, call func(ctx context.Context, i int) error) {
		clients = append(clients, &traffic{
			name: name, afterRestart: &afterRestart, call: call,
			stopped: make(chan struct{}), done: make(chan struct{}),
		})
	}
	echo := func(ctx context.Context, cs *mcp.ClientSession, text string) error {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": text}})
		if err != nil {
			return err
		}
		if tc, ok := res.Content[0].(*mcp.TextContent); res.IsError || !ok || tc.Text != text {
			return fmt.Errorf("echo %q: %+v", text, res)
		}
		return nil
	}
	// Clients connected before the restart, on kept-alive connections.
	for k := range 3 {
		cs := connect(t, keepAlive, endpoint)
		name := fmt.Sprintf("session-%d", k)
		add(name, func(ctx context.Context, i int) error { return echo(ctx, cs, fmt.Sprintf("%s %d", name, i)) })
	}
	// A client with the SDK's defaults (retries on) and a subscriptions/listen stream, which ends
	// at the restart; its calls go on.
	listening := func() *mcp.ClientSession {
		client := mcp.NewClient(&mcp.Implementation{Name: "smoke", Version: "1"}, &mcp.ClientOptions{
			ToolListChangedHandler: func(context.Context, *mcp.ToolListChangedRequest) {},
		})
		cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{
			Endpoint: endpoint, HTTPClient: &http.Client{Transport: bearer{keepAlive}},
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cs.Close() })
		return cs
	}()
	add("listening", func(ctx context.Context, i int) error { return echo(ctx, listening, fmt.Sprintf("listening %d", i)) })
	// A client that connects anew, on a new connection, for every call.
	add("new-client", func(ctx context.Context, i int) error {
		client := mcp.NewClient(&mcp.Implementation{Name: "smoke", Version: "1"}, nil)
		cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{
			Endpoint: endpoint, HTTPClient: &http.Client{Transport: bearer{fresh}}, MaxRetries: -1, DisableStandaloneSSE: true,
		}, nil)
		if err != nil {
			return fmt.Errorf("connect: %w", err)
		}
		defer cs.Close()
		return echo(ctx, cs, fmt.Sprintf("new %d", i))
	})
	var wg sync.WaitGroup
	for _, c := range clients {
		wg.Go(func() { c.run(ctx) })
	}
	stopTraffic := func() {
		for _, c := range clients {
			close(c.stopped)
		}
		wg.Wait()
	}

	time.Sleep(300 * time.Millisecond)
	// A slow call, with progress so that the test knows it reached the server before the SIGTERM.
	progressed := make(chan struct{}, 1)
	slowClient := mcp.NewClient(&mcp.Implementation{Name: "smoke", Version: "1"}, &mcp.ClientOptions{
		ProgressNotificationHandler: func(context.Context, *mcp.ProgressNotificationClientRequest) {
			select {
			case progressed <- struct{}{}:
			default:
			}
		},
	})
	slowSession, err := slowClient.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: endpoint, HTTPClient: &http.Client{Transport: bearer{keepAlive}}, MaxRetries: -1, DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = slowSession.Close() })
	slow := make(chan error, 1)
	go func() {
		params := &mcp.CallToolParams{Name: "progress", Arguments: map[string]any{"steps": 8, "ms": 200}}
		params.SetProgressToken("slow")
		res, err := slowSession.CallTool(ctx, params)
		if err == nil && (res.IsError || len(res.Content) == 0) {
			err = fmt.Errorf("progress: %+v", res)
		}
		slow <- err
	}()
	select {
	case <-progressed:
	case err := <-slow:
		t.Fatalf("the slow call ended early: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("no progress from the slow call")
	}

	// systemctl restart: stop the running gate, then start the next on the same socket.
	old.stop(t)
	oldNotify.await(t, old, "STOPPING=1")
	next, _ := start("new")
	afterRestart.Store(true)
	select {
	case err := <-slow:
		if err != nil {
			t.Errorf("the call in flight at SIGTERM: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("the call in flight at SIGTERM did not end")
	}
	time.Sleep(time.Second)
	stopTraffic()

	for _, c := range clients {
		if n := c.failed.Load(); n > 0 {
			t.Errorf("%s: %d calls failed (first: %v), %d succeeded", c.name, n, c.firstFailure.Load(), c.ok.Load())
		}
		if c.okAfter.Load() == 0 {
			t.Errorf("%s: no call after the restart", c.name)
		}
		t.Logf("%s: %d calls, %d after the restart", c.name, c.ok.Load(), c.okAfter.Load())
	}
	// The session of the slow call, idle across the restart, still calls.
	if err := echo(ctx, slowSession, "after"); err != nil {
		t.Errorf("a session idle across the restart: %v", err)
	}
	// The stdio server inherits neither the passed socket nor systemd's variables.
	var pids struct{ Sockets int }
	switch err := json.Unmarshal([]byte(callText(t, slowSession, "pids", nil)), &pids); {
	case err != nil:
		t.Errorf("pids: %v", err)
	case pids.Sockets < 0:
		t.Error("the stdio server cannot list its descriptors")
	case pids.Sockets > 0:
		t.Errorf("the stdio server has %d sockets open", pids.Sockets)
	}
	env := callText(t, slowSession, "env", nil)
	for _, leak := range []string{"LISTEN_", "NOTIFY_SOCKET"} {
		if strings.Contains(env, leak) {
			t.Errorf("the stdio server's environment holds %s", leak)
		}
	}
	for _, p := range []*process{old, next} {
		if len(p.logs.messages("serving the socket systemd passed")) != 1 {
			t.Errorf("the gate did not serve the passed socket\n%s", p.logs)
		}
		if strings.Contains(p.logs.String(), "is not on listen.addr") {
			t.Errorf("a socket on listen.addr was reported as elsewhere\n%s", p.logs)
		}
	}
	keepAlive.CloseIdleConnections()
	next.stop(t)
}

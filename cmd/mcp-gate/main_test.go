package main

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"go.uber.org/goleak"

	"github.com/vsem-azamat/mcp-gate/internal/testkit"
	"github.com/vsem-azamat/mcp-gate/internal/version"
)

func TestMain(m *testing.M) {
	testkit.RunFake()
	goleak.VerifyTestMain(m)
}

func noEnv(string) (string, bool) { return "", false }

func TestRun(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "no command", args: nil, wantCode: exitUsage, wantStderr: usage},
		{name: "help", args: []string{"help"}, wantCode: exitOK, wantStdout: usage},
		{name: "help flag", args: []string{"--help"}, wantCode: exitOK, wantStdout: usage},
		{name: "version", args: []string{"version"}, wantCode: exitOK, wantStdout: "mcp-gate " + version.Get().String() + "\n"},
		{
			name:       "unknown command",
			args:       []string{"serve-everything"},
			wantCode:   exitUsage,
			wantStderr: `mcp-gate: unknown command "serve-everything"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			code := run(t.Context(), tt.args, noEnv, &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			if stdout.String() != tt.wantStdout {
				t.Errorf("stdout = %q, want %q", stdout.String(), tt.wantStdout)
			}
			if !strings.HasPrefix(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want prefix %q", stderr.String(), tt.wantStderr)
			}
			if tt.wantStderr == "" && stderr.Len() != 0 {
				t.Errorf("stderr = %q, want empty", stderr.String())
			}
		})
	}
}

func TestChildEnviron(t *testing.T) {
	t.Parallel()
	in := []string{
		"PATH=/bin", "MCP_HUB_ESCROW_KEY_SHA256=abc", "MCP_OTHER=1", "MCP_GATE_ESCROW_KEY_SHA256=abc", "HASH=abc",
		"LISTEN_PID=1", "LISTEN_FDS=1", "LISTEN_FDNAMES=mcp-gate.socket", "NOTIFY_SOCKET=/run/notify",
	}
	got := childEnviron(in, "HASH")
	if len(got) != 2 || got[0] != "PATH=/bin" || got[1] != "MCP_OTHER=1" || in[1] != "MCP_HUB_ESCROW_KEY_SHA256=abc" {
		t.Errorf("childEnviron = %v (input %v)", got, in)
	}
}

func TestSameAddr(t *testing.T) {
	t.Parallel()
	tcp := func(ip string, port int) net.Addr { return &net.TCPAddr{IP: net.ParseIP(ip), Port: port} }
	for _, c := range []struct {
		socket     net.Addr
		configured string
		want       bool
	}{
		{tcp("127.0.0.1", 9090), "127.0.0.1:9090", true},
		{tcp("127.0.0.1", 9090), "127.0.0.1:9091", false},
		{tcp("127.0.0.1", 9090), "localhost:9090", true},
		{tcp("::1", 9090), "localhost:9090", true},
		{tcp("0.0.0.0", 9090), "localhost:9090", false},
		{tcp("::", 9090), "0.0.0.0:9090", true},
		{tcp("::", 9090), ":9090", true},
		{tcp("127.0.0.1", 9090), ":9090", false},
		{tcp("10.0.0.1", 9090), "10.0.0.2:9090", false},
		{tcp("10.0.0.1", 9090), "mcp.example.com:9090", false},
	} {
		if got := sameAddr(c.socket, c.configured); got != c.want {
			t.Errorf("sameAddr(%s, %q) = %v, want %v", c.socket, c.configured, got, c.want)
		}
	}
}

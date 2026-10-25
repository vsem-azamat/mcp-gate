package main

import (
	"bytes"
	"strings"
	"testing"

	"go.uber.org/goleak"

	"github.com/vsem-azamat/mcp-gate/internal/version"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

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

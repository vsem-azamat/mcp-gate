package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vsem-azamat/mcp-gate/internal/config"
)

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// runCmd runs mcp-gate with args.
func runCmd(t *testing.T, e lookupEnv, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(t.Context(), args, e, &stdout, &stderr)
	return result{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

func TestCheckValid(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "gate.yaml", "version: 1\nservers:\n  a:\n    http: {url: 'https://a.example.com/mcp', headers: {X-Key: '${KEY}'}}\n  b:\n    stdio: {command: srv}\n    disabled: true\n")
	r := runCmd(t, env(map[string]string{"KEY": "k-123"}), "check", path)
	if r.code != exitOK || !strings.Contains(r.stdout, "valid, 2 servers (1 disabled)") {
		t.Errorf("check = %+v", r)
	}
}

func TestCheckInvalid(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "gate.yaml", "version: 1\nservers:\n  a:\n    http: {url: '${URL}'}\n  b:\n    stdio: {command: srv, cwd: rel}\n")
	r := runCmd(t, noEnv, "check", path)
	if r.code != exitUsage || !strings.Contains(r.stderr, "servers.a.http.url: environment variable URL is unset") ||
		!strings.Contains(r.stderr, "servers.b.stdio.cwd") {
		t.Errorf("check = %+v", r)
	}
	for _, args := range [][]string{{"check"}, {"check", "a", "b"}, {"check", "-bogus", path}} {
		if r := runCmd(t, noEnv, args...); r.code != exitUsage {
			t.Errorf("%v: code %d", args, r.code)
		}
	}
}

const proxyConfig = `{
  "mcpProxy": {"name": "hub", "type": "streamable-http", "options": {"authTokens": ["${TOKEN_A}"]}},
  "mcpServers": {
    "notes": {"command": "/usr/bin/env", "args": ["-u", "TOKEN_A", "notes-server"], "timeout": "90s"}
  }
}`

func TestImport(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "config.json", proxyConfig)
	r := runCmd(t, noEnv, "import", path)
	if r.code != exitUsage || !strings.Contains(r.stderr, "mcpProxy.options.authTokens") || r.stdout != "" {
		t.Errorf("import without -partial = %+v", r)
	}
	r = runCmd(t, noEnv, "import", "-partial", path)
	if r.code != exitOK || !strings.Contains(r.stderr, "dropped, not implemented: mcpProxy.options.authTokens") ||
		!strings.Contains(r.stdout, "command: notes-server") || !strings.Contains(r.stdout, config.PartialMarker) {
		t.Fatalf("import -partial = %+v", r)
	}
	gate := writeFile(t, "gate.yaml", r.stdout)
	if c := runCmd(t, noEnv, "check", gate); c.code != exitUsage || !strings.Contains(c.stderr, "--partial") {
		t.Errorf("check of a partial import = %+v", c)
	}
	for _, args := range [][]string{{"import"}, {"import", filepath.Join(t.TempDir(), "missing.json")}} {
		if r := runCmd(t, noEnv, args...); r.code != exitUsage {
			t.Errorf("%v: code %d", args, r.code)
		}
	}
}

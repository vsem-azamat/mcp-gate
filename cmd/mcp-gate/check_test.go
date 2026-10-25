package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/testkit"
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

func quote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func stdioServer(t *testing.T, f testkit.Fake) string {
	t.Helper()
	cmd, args := testkit.StdioCommand(t, f)
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = quote(a)
	}
	return "    stdio: {command: " + quote(cmd) + ", args: [" + strings.Join(quoted, ", ") + "]}\n"
}

func TestCheckValid(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "gate.yaml", "version: 1\nauth: {tokens: {t: secret}}\nservers:\n  a:\n    http: {url: 'https://a.example.com/mcp', headers: {X-Key: '${KEY}'}}\n  b:\n    stdio: {command: srv}\n    disabled: true\n")
	r := runCmd(t, env(map[string]string{"KEY": "k-123"}), "check", path)
	if r.code != exitOK || !strings.Contains(r.stdout, "valid, 2 servers (1 disabled)") {
		t.Errorf("check = %+v", r)
	}
}

func TestCheckInvalid(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "gate.yaml", "version: 1\nauth: {tokens: {t: secret}}\nservers:\n  a:\n    http: {url: '${URL}'}\n  b:\n    stdio: {command: srv, cwd: rel}\n")
	r := runCmd(t, noEnv, "check", path)
	if r.code != exitUsage || !strings.Contains(r.stderr, "servers.a.http.url: environment variable URL is unset") ||
		!strings.Contains(r.stderr, "servers.b.stdio.cwd") {
		t.Errorf("check = %+v", r)
	}
	for _, args := range [][]string{{"check"}, {"check", "a", "b"}, {"check", "-timeout", "0s", path}, {"check", "-bogus", path}} {
		if r := runCmd(t, noEnv, args...); r.code != exitUsage {
			t.Errorf("%v: code %d", args, r.code)
		}
	}
}

func TestCheckConnect(t *testing.T) {
	t.Parallel()
	h := testkit.NewFakeHTTP(t, testkit.Fake{}, testkit.FakeHTTPOptions{})
	doc := "version: 1\nauth: {tokens: {t: secret}}\nservers:\n" +
		"  local:\n" + stdioServer(t, testkit.Fake{ProtocolVersions: []string{"2025-06-18"}}) +
		"  legacy:\n" + stdioServer(t, testkit.Fake{SilentDiscover: true}) +
		"  remote:\n    http: {url: " + quote(h.URL()) + "}\n" +
		"  off:\n    stdio: {command: srv}\n    disabled: true\n"
	path := writeFile(t, "gate.yaml", doc)
	r := runCmd(t, noEnv, "check", "-connect", "-timeout", "20s", path)
	want := []string{
		"legacy: ready, protocol 2025-11-25 (pinned automatically",
		"local: ready, protocol 2025-06-18, 13 tools",
		"off: disabled",
		"remote: ready, protocol 2026-07-28, 13 tools",
	}
	for _, w := range want {
		if !strings.Contains(r.stdout, w) {
			t.Errorf("stdout lacks %q:\n%s", w, r.stdout)
		}
	}
	if r.code != exitOK {
		t.Errorf("code = %d, stderr %s", r.code, r.stderr)
	}
}

func TestCheckConnectFailure(t *testing.T) {
	t.Parallel()
	doc := "version: 1\nauth: {tokens: {t: secret}}\nservers:\n  broken:\n" + stdioServer(t, testkit.Fake{ExitAtStart: 4})
	r := runCmd(t, noEnv, "check", "-connect", "-timeout", "20s", writeFile(t, "gate.yaml", doc))
	if r.code != exitTrouble || !strings.Contains(r.stdout, "broken: failed:") {
		t.Errorf("check = %+v", r)
	}
}

const proxyConfig = `{
  "mcpProxy": {"name": "hub", "type": "streamable-http", "options": {"authTokens": ["${TOKEN_A}"], "redact": {"enabled": true, "escrowTTL": "1h"}}},
  "mcpServers": {
    "notes": {"command": "/usr/bin/env", "args": ["-u", "TOKEN_A", "notes-server"], "timeout": "90s"},
    "shop": {"url": "https://shop.example.com/mcp", "transportType": "streamable-http", "oauth": {}}
  }
}`

func TestImport(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "config.json", proxyConfig)
	r := runCmd(t, noEnv, "import", path)
	if r.code != exitUsage || !strings.Contains(r.stderr, "mcpServers.shop.oauth") || r.stdout != "" {
		t.Errorf("import without -partial = %+v", r)
	}
	r = runCmd(t, noEnv, "import", "-partial", path)
	if r.code != exitOK || !strings.Contains(r.stderr, "dropped, not implemented: mcpServers.shop.oauth") ||
		!strings.Contains(r.stdout, "command: notes-server") || !strings.Contains(r.stdout, "escrow:\n  ttl: 1h") ||
		!strings.Contains(r.stdout, config.PartialMarker) {
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

func TestServeUsage(t *testing.T) {
	if r := runCmd(t, noEnv, "serve"); r.code != exitUsage || !strings.Contains(r.stderr, "name one config file") {
		t.Errorf("no file: %+v", r)
	}
	if r := runCmd(t, noEnv, "serve", "-h"); r.code != exitOK || !strings.Contains(r.stderr, "-state-dir") {
		t.Errorf("help: %+v", r)
	}
	path := writeFile(t, "gate.yaml", "version: 1\nservers:\n  a:\n    http: {url: 'https://a.example.com/mcp'}\n")
	if r := runCmd(t, noEnv, "serve", path); r.code != exitUsage || !strings.Contains(r.stderr, "servers.a.auth") {
		t.Errorf("a server without tokens: %+v", r)
	}
}

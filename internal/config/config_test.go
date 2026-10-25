package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func env(vars map[string]string) LookupFunc {
	return func(name string) (string, bool) {
		v, ok := vars[name]
		return v, ok
	}
}

func noEnv(string) (string, bool) { return "", false }

const fullConfig = `
version: 1
name: gate-test
servers:
  notes:
    stdio:
      command: /usr/bin/node
      args: [server.js, --db, "${NOTES_DB}"]
      cwd: /srv/notes
      env: {NOTES_TOKEN: "${NOTES_TOKEN}", PRICE: "$$5"}
      inheritEnv: [PATH, LC_*]
    callTimeout: 3m
    maxMessageBytes: 8MiB
    protocolVersion: "2025-11-25"
    probeInterval: 10s
    restart: {maxBackoff: 1m}
  shop:
    http:
      url: https://shop.example.com/mcp
      headers: {X-Api-Key: "${SHOP_KEY}"}
    disabled: true
`

func TestParseFull(t *testing.T) {
	t.Parallel()
	c, err := Parse([]byte(fullConfig), env(map[string]string{
		"NOTES_DB": "/srv/notes/db", "NOTES_TOKEN": "tok-123", "SHOP_KEY": "key-456",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "gate-test" {
		t.Errorf("name = %q", c.Name)
	}
	n := c.Servers["notes"]
	if got := strings.Join(n.Stdio.Args, " "); got != "server.js --db /srv/notes/db" {
		t.Errorf("args = %q", got)
	}
	if n.Stdio.Env["NOTES_TOKEN"] != "tok-123" || n.Stdio.Env["PRICE"] != "$5" {
		t.Errorf("env = %v", n.Stdio.Env)
	}
	if !slices.Equal(n.Stdio.InheritEnv, []string{"PATH", "LC_*"}) {
		t.Errorf("inheritEnv = %v", n.Stdio.InheritEnv)
	}
	if n.CallTimeout.D() != 3*time.Minute || *n.MaxMessageBytes != 8<<20 || n.ProbeInterval.D() != 10*time.Second ||
		n.Restart.MaxBackoff.D() != time.Minute || n.ProtocolVersion != "2025-11-25" {
		t.Errorf("notes = %+v", n)
	}
	s := c.Servers["shop"]
	if s.HTTP.Headers["X-Api-Key"] != "key-456" || !s.Disabled {
		t.Errorf("shop = %+v", s)
	}
}

func TestDefaults(t *testing.T) {
	t.Parallel()
	c, err := Parse([]byte("version: 1\nservers:\n  a:\n    stdio: {command: srv}\n  b:\n    stdio: {command: srv, inheritEnv: []}\n"), noEnv)
	if err != nil {
		t.Fatal(err)
	}
	a := c.Servers["a"]
	if c.Name != DefaultName || a.CallTimeout != 0 || *a.MaxMessageBytes != DefaultMaxMessageBytes ||
		a.ProbeInterval.D() != DefaultProbeInterval || a.Restart.MaxBackoff.D() != DefaultMaxBackoff {
		t.Errorf("defaults not applied: %+v", a)
	}
	if !slices.Equal(a.Stdio.InheritEnv, DefaultInheritEnv) {
		t.Errorf("inheritEnv = %v, want the default", a.Stdio.InheritEnv)
	}
	if b := c.Servers["b"].Stdio.InheritEnv; b == nil || len(b) != 0 {
		t.Errorf("explicit empty inheritEnv = %#v, want empty", b)
	}
}

func TestParseErrors(t *testing.T) {
	t.Parallel()
	const head = "version: 1\nservers:\n  a:\n"
	cases := []struct {
		name, doc, want string
	}{
		{"empty", "", "empty"},
		{"unknown key", head + "    stdio: {command: x}\n    tools: {allow: [a]}\n", "field tools not found"},
		{"duplicate key", head + "    stdio: {command: x}\n    disabled: true\n    disabled: false\n", "already defined"},
		{"two documents", head + "    stdio: {command: x}\n---\nversion: 1\n", "more than one"},
		{"no version", "servers:\n  a:\n    stdio: {command: x}\n", "version: is required"},
		{"wrong version", "version: 2\nservers:\n  a:\n    stdio: {command: x}\n", "version: must be 1"},
		{"no servers", "version: 1\n", "at least one server"},
		{"bare duration", head + "    stdio: {command: x}\n    callTimeout: 30\n", "string with a unit"},
		{"bad duration", head + "    stdio: {command: x}\n    callTimeout: soon\n", "string with a unit"},
		{"negative duration", head + "    stdio: {command: x}\n    callTimeout: -1s\n", "negative"},
		{"bare size", head + "    stdio: {command: x}\n    maxMessageBytes: 1024\n", "size is a string"},
		{"decimal size", head + "    stdio: {command: x}\n    maxMessageBytes: 16MB\n", "size is a string"},
		{"small size", head + "    stdio: {command: x}\n    maxMessageBytes: 1KiB\n", "maxMessageBytes: must be between"},
		{"short probe", head + "    stdio: {command: x}\n    probeInterval: 10ms\n", "probeInterval: must be at least"},
		{"short backoff", head + "    stdio: {command: x}\n    restart: {maxBackoff: 0s}\n", "maxBackoff: must be at least"},
		{"bad name", "version: 1\nservers:\n  Notes:\n    stdio: {command: x}\n", "servers.Notes: server names"},
		{"underscore name", "version: 1\nservers:\n  _status:\n    stdio: {command: x}\n", "server names"},
		{"no transport", head + "    disabled: true\n", "needs stdio or http"},
		{"two transports", head + "    stdio: {command: x}\n    http: {url: 'https://a.example.com/mcp'}\n", "both stdio and http"},
		{"no command", head + "    stdio: {args: [x]}\n", "command: is required"},
		{"relative cwd", head + "    stdio: {command: x, cwd: srv}\n", "cwd: must be an absolute path"},
		{"bad env name", head + "    stdio: {command: x, env: {'A-B': x}}\n", "valid environment variable name"},
		{"bad inherit", head + "    stdio: {command: x, inheritEnv: ['*']}\n", "inheritEnv[0]"},
		{"bad version pin", head + "    stdio: {command: x}\n    protocolVersion: '2023-01-01'\n", "protocolVersion: must be one of"},
		{"ftp url", head + "    http: {url: 'ftp://a.example.com/mcp'}\n", "http or https"},
		{"userinfo", head + "    http: {url: 'https://user:hunter22@a.example.com/mcp'}\n", "user information"},
		{"fragment", head + "    http: {url: 'https://a.example.com/mcp#x'}\n", "fragment"},
		{"mcp header", head + "    http: {url: 'https://a.example.com/mcp', headers: {Mcp-Method: x}}\n", "set by mcp-gate"},
		{"header case", head + "    http: {url: 'https://a.example.com/mcp', headers: {X-Key: a, x-key: b}}\n", "different letter case"},
		{"type error", head + "    stdio: {command: x}\n    disabled: hunter2secret\n", "value not shown"},
		{"reserved header", head + "    http: {url: 'https://a.example.com/mcp', headers: {accept-encoding: gzip}}\n", "set by mcp-gate"},
		{"unset var", head + "    stdio: {command: '${NOPE}'}\n", "stdio.command: environment variable NOPE is unset or empty"},
		{"bad var", head + "    stdio: {command: '${A-B}'}\n", "invalid variable name"},
		{"unterminated var", head + "    stdio: {command: '${A'}\n", "unterminated"},
		{"partial import", head + "    stdio: {command: x}\n    # " + PartialMarker + ": tools\n", "--partial"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse([]byte(tc.doc), noEnv)
			if err == nil {
				t.Fatalf("Parse succeeded, want an error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestErrorsCollectedWithoutValues(t *testing.T) {
	t.Parallel()
	doc := "version: 1\nservers:\n  a:\n    http: {url: 'https://user:hunter22@a.example.com/mcp?k=${KEY}'}\n" +
		"  b:\n    stdio: {command: x, cwd: rel}\n"
	_, err := Parse([]byte(doc), env(map[string]string{"KEY": "s3cr3t-value"}))
	if err == nil {
		t.Fatal("Parse succeeded")
	}
	msg := err.Error()
	for _, want := range []string{"servers.a.http.url", "servers.b.stdio.cwd"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not name %s", msg, want)
		}
	}
	for _, secret := range []string{"hunter22", "s3cr3t-value", "a.example.com"} {
		if strings.Contains(msg, secret) {
			t.Errorf("error %q quotes a value (%s)", msg, secret)
		}
	}
}

func TestDecodeErrorsHideValues(t *testing.T) {
	t.Parallel()
	_, err := Parse([]byte("version: 1\nservers:\n  a:\n    stdio: {command: x, args: ghp_abcdefghijklmnop}\n"), noEnv)
	if err == nil || strings.Contains(err.Error(), "ghp_") {
		t.Errorf("err = %v", err)
	}
	_, err = Parse([]byte("version: 1\nservers:\n  a:\n    stdio: {command: x}\n    callTimeout: 30\n"), noEnv)
	if err == nil || !strings.Contains(err.Error(), "line 5") {
		t.Errorf("a duration error does not say where: %v", err)
	}
}

func TestExpansionCannotInjectStructure(t *testing.T) {
	t.Parallel()
	doc := "version: 1\nservers:\n  a:\n    stdio:\n      command: x\n      args: ['${EVIL}']\n"
	c, err := Parse([]byte(doc), env(map[string]string{"EVIL": "y\n    disabled: true"}))
	if err != nil {
		t.Fatal(err)
	}
	a := c.Servers["a"]
	if a.Disabled || len(a.Stdio.Args) != 1 || a.Stdio.Args[0] != "y\n    disabled: true" {
		t.Errorf("expansion changed the structure: %+v", a)
	}
}

func TestExpand(t *testing.T) {
	t.Parallel()
	lookup := env(map[string]string{"A": "1", "B_2": "two", "EMPTY": ""})
	cases := map[string]string{
		"plain":        "plain",
		"${A}":         "1",
		"x${A}y${B_2}": "x1ytwo",
		"$$":           "$",
		"$${A}":        "${A}",
		"$A":           "$A",
		"cost $5":      "cost $5",
		"end$":         "end$",
	}
	for in, want := range cases {
		got, err := Expand(in, lookup)
		if err != nil || got != want {
			t.Errorf("Expand(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"${EMPTY}", "${MISSING}", "${A", "${}", "${1A}"} {
		if _, err := Expand(in, lookup); err == nil {
			t.Errorf("Expand(%q) succeeded, want an error", in)
		}
	}
}

func TestByteSize(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]ByteSize{"100B": 100, "4KiB": 4096, "16MiB": 16 << 20, "1GiB": 1 << 30} {
		got, err := ParseByteSize(in)
		if err != nil || got != want {
			t.Errorf("ParseByteSize(%q) = %d, %v", in, got, err)
		}
		if got.String() != in {
			t.Errorf("%d.String() = %q, want %q", got, got.String(), in)
		}
	}
	for _, in := range []string{"", "16", "16mb", "1.5MiB", "-1KiB", "99999999999999999999GiB"} {
		if _, err := ParseByteSize(in); err == nil {
			t.Errorf("ParseByteSize(%q) succeeded", in)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	t.Parallel()
	for d, want := range map[time.Duration]string{
		0: "0s", 30 * time.Second: "30s", 2 * time.Minute: "2m", 90 * time.Second: "1m30s",
		time.Hour: "1h", 90 * time.Minute: "1h30m", 1500 * time.Millisecond: "1.5s",
	} {
		if got := FormatDuration(d); got != want {
			t.Errorf("FormatDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "gate.yaml")
	if err := os.WriteFile(path, []byte(fullConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, env(map[string]string{"NOTES_DB": "d", "NOTES_TOKEN": "t", "SHOP_KEY": "k"})); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml"), noEnv); err == nil {
		t.Error("Load of a missing file succeeded")
	}
}

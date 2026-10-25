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
listen:
  addr: "0.0.0.0:8080"
  behindProxy: true
  trustedProxies: [10.0.0.0/8]
  allowedHosts: [mcp.example.com]
startupGracePeriod: 90s
logLevel: debug
auth:
  tokens: {laptop: "${LAPTOP_TOKEN}"}
admin:
  tokens: {owner: "${ADMIN_TOKEN}"}
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
    tools: {allow: [search, read]}
    prompts: {allow: []}
    resources: {deny: ["notes://private"]}
    log: {requests: true}
    redact: {ru: true, highEntropy: true, disableRules: [jwt]}
  shop:
    http:
      url: https://shop.example.com/mcp
      headers: {X-Api-Key: "${SHOP_KEY}"}
    disabled: true
    auth:
      inherit: false
      tokens: {phone: "${PHONE_TOKEN}"}
    redact: {enabled: false}
`

func TestParseFull(t *testing.T) {
	t.Parallel()
	c, err := Parse([]byte(fullConfig), env(map[string]string{
		"NOTES_DB": "/srv/notes/db", "NOTES_TOKEN": "tok-123", "SHOP_KEY": "key-456",
		"LAPTOP_TOKEN": "lt", "ADMIN_TOKEN": "at", "PHONE_TOKEN": "pt",
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
	if c.Listen.Addr != "0.0.0.0:8080" || !c.Listen.BehindProxy || c.StartupGracePeriod.D() != 90*time.Second ||
		c.LogLevel != "debug" || c.Admin.Tokens["owner"] != "at" {
		t.Errorf("top level = %+v", c)
	}
	if !slices.Equal(n.Tools.Allow, []string{"search", "read"}) || n.Prompts.Allow == nil || len(n.Prompts.Allow) != 0 ||
		n.Resources.Deny[0] != "notes://private" || !n.Log.Requests || !*n.Redact.Enabled || !n.Redact.RU {
		t.Errorf("notes policy = %+v", n)
	}
	if got := c.EffectiveTokens("notes"); len(got) != 1 || got["laptop"] != "lt" {
		t.Errorf("notes tokens = %v", got)
	}
	if got := c.EffectiveTokens("shop"); len(got) != 1 || got["phone"] != "pt" || *s.Redact.Enabled {
		t.Errorf("shop tokens = %v, redact %v", got, *s.Redact.Enabled)
	}
}

func TestServingDefaults(t *testing.T) {
	t.Parallel()
	c, err := Parse([]byte("version: 1\nauth: {tokens: {t: secret}}\nservers:\n  a:\n    stdio: {command: srv}\n"+
		"  b:\n    stdio: {command: srv}\n    auth: {public: true}\n"), noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen.Addr != DefaultListenAddr || !slices.Equal(c.Listen.TrustedProxies, DefaultTrustedProxies) ||
		c.StartupGracePeriod.D() != DefaultStartupGracePeriod || c.LogLevel != DefaultLogLevel {
		t.Errorf("defaults = %+v", c)
	}
	a := c.Servers["a"]
	if !*a.Redact.Enabled || a.Redact.RU || !*a.Auth.Inherit || a.Tools != nil {
		t.Errorf("server defaults = %+v", a)
	}
	if c.EffectiveTokens("b") != nil {
		t.Error("a public server has tokens")
	}
	if c.Escrow.TTL.D() != DefaultEscrowTTL || c.Escrow.MaxEntries != DefaultEscrowMaxEntries || a.Redact.EscrowTTL.D() != DefaultEscrowTTL || a.Redact.Files != nil {
		t.Errorf("escrow defaults = %+v, %+v", c.Escrow, a.Redact)
	}
}

func TestEscrowKeys(t *testing.T) {
	t.Parallel()
	c, err := Parse([]byte("version: 1\nescrow: {ttl: 2h, maxEntries: 50}\nauth: {tokens: {t: secret}}\nservers:\n"+
		"  a:\n    stdio: {command: srv}\n    redact: {escrowTTL: 30m, files: {tools: [download], roots: [/srv/dl]}}\n"+
		"  b:\n    stdio: {command: srv}\n    redact: {files: {tools: [download], roots: [/srv/dl], maxBytes: 1MiB}}\n"), noEnv)
	if err != nil {
		t.Fatal(err)
	}
	a, b := c.Servers["a"].Redact, c.Servers["b"].Redact
	if c.Escrow.TTL.D() != 2*time.Hour || c.Escrow.MaxEntries != 50 || a.EscrowTTL.D() != 30*time.Minute || b.EscrowTTL.D() != 2*time.Hour {
		t.Errorf("ttl = %v, %v, %v; maxEntries %d", c.Escrow.TTL.D(), a.EscrowTTL.D(), b.EscrowTTL.D(), c.Escrow.MaxEntries)
	}
	if *a.Files.MaxBytes != DefaultFileMaxBytes || *b.Files.MaxBytes != 1<<20 || !slices.Equal(a.Files.Roots, []string{"/srv/dl"}) {
		t.Errorf("files = %+v, %+v", a.Files, b.Files)
	}
}

func TestServingErrors(t *testing.T) {
	t.Parallel()
	const srv = "servers:\n  a:\n    stdio: {command: x}\n"
	cases := []struct{ name, doc, want string }{
		{"no tokens", "version: 1\n" + srv, "servers.a.auth: the server accepts no token"},
		{"bad token name", "version: 1\nauth: {tokens: {Laptop: x}}\n" + srv, "auth.tokens.Laptop: token names"},
		{"empty token", "version: 1\nauth: {tokens: {a: ''}}\n" + srv, "auth.tokens.a: must be a non-empty token"},
		{"token with space", "version: 1\nauth: {tokens: {a: 'b c'}}\n" + srv, "auth.tokens.a: must be a non-empty token"},
		{"token with a no-break space", "version: 1\nauth: {tokens: {a: \"b\\u00a0c\"}}\n" + srv, "auth.tokens.a: must be a non-empty token"},
		{"same value", "version: 1\nauth: {tokens: {a: s, b: s}}\n" + srv, "the tokens a and b have the same value"},
		{"shadowed name", "version: 1\nauth: {tokens: {a: s}}\n" + srv + "    auth: {tokens: {a: t}}\n", "servers.a.auth.tokens.a: is also a global token name"},
		{"inherit nothing", "version: 1\nauth: {tokens: {a: s}}\n" + srv + "    auth: {inherit: false}\n", "accepts no token"},
		{"public with tokens", "version: 1\n" + srv + "    auth: {public: true, tokens: {a: s}}\n", "servers.a.auth.public: excludes tokens"},
		{"both lists", "version: 1\nauth: {tokens: {a: s}}\n" + srv + "    tools: {allow: [x], deny: [y]}\n", "servers.a.tools: needs exactly one of allow and deny"},
		{"no list", "version: 1\nauth: {tokens: {a: s}}\n" + srv + "    prompts: {}\n", "servers.a.prompts: needs exactly one"},
		{"empty entry", "version: 1\nauth: {tokens: {a: s}}\n" + srv + "    resources: {deny: [' ']}\n", "servers.a.resources[0]: cannot be empty"},
		{"unknown rule", "version: 1\nauth: {tokens: {a: s}}\n" + srv + "    redact: {disableRules: [nope]}\n", "servers.a.redact.disableRules: names an unknown rule"},
		{"bad addr", "version: 1\nlisten: {addr: localhost}\nauth: {tokens: {a: s}}\n" + srv, "listen.addr: must be host:port"},
		{"bad cidr", "version: 1\nlisten: {trustedProxies: [10.0.0.1]}\nauth: {tokens: {a: s}}\n" + srv, "listen.trustedProxies[0]: must be a CIDR"},
		{"bad host", "version: 1\nlisten: {allowedHosts: ['a/b']}\nauth: {tokens: {a: s}}\n" + srv, "listen.allowedHosts[0]"},
		{"bad level", "version: 1\nlogLevel: loud\nauth: {tokens: {a: s}}\n" + srv, "logLevel: must be one of"},
		{"zero grace", "version: 1\nstartupGracePeriod: 0s\nauth: {tokens: {a: s}}\n" + srv, "startupGracePeriod: must be positive"},
		{"empty meta key", "version: 1\nauth: {tokens: {a: s}}\n" + srv + "    forwardMeta: ['']\n", "servers.a.forwardMeta[0]: cannot be empty"},
		{"blank meta key", "version: 1\nauth: {tokens: {a: s}}\n" + srv + "    forwardMeta: ['  ']\n", "servers.a.forwardMeta[0]: cannot be empty"},
		{"duplicate meta key", "version: 1\nauth: {tokens: {a: s}}\n" + srv + "    forwardMeta: [x/a, x/a]\n", "servers.a.forwardMeta[1]: is listed twice"},
		{"progress token", "version: 1\nauth: {tokens: {a: s}}\n" + srv + "    forwardMeta: [progressToken]\n", "servers.a.forwardMeta[0]: is a key mcp-gate sets itself"},
		{"reserved meta key", "version: 1\nauth: {tokens: {a: s}}\n" + srv + "    forwardMeta: [io.modelcontextprotocol/clientInfo]\n", "servers.a.forwardMeta[0]: is a key mcp-gate sets itself"},
		{"proxy file keys", "version: 1\nauth: {tokens: {a: s}}\n" + srv + "    redact: {fileTools: [x]}\n", "field fileTools not found"},
		{"zero escrow ttl", "version: 1\nescrow: {ttl: 0s}\nauth: {tokens: {a: s}}\n" + srv, "escrow.ttl: must be positive"},
		{"many entries", "version: 1\nescrow: {maxEntries: 100001}\nauth: {tokens: {a: s}}\n" + srv, "escrow.maxEntries: must be between"},
		{"zero server ttl", "version: 1\nauth: {tokens: {a: s}}\n" + srv + "    redact: {escrowTTL: 0s}\n", "servers.a.redact.escrowTTL: must be positive"},
		{"files without tools", "version: 1\nauth: {tokens: {a: s}}\n" + srv + "    redact: {files: {tools: [], roots: [/d]}}\n", "servers.a.redact.files.tools: must name"},
		{"files without roots", "version: 1\nauth: {tokens: {a: s}}\n" + srv + "    redact: {files: {tools: [x]}}\n", "servers.a.redact.files.roots: must name"},
		{"relative root", "version: 1\nauth: {tokens: {a: s}}\n" + srv + "    redact: {files: {tools: [x], roots: [d]}}\n", "servers.a.redact.files.roots[0]: must be an absolute path"},
		{"slash root", "version: 1\nauth: {tokens: {a: s}}\n" + srv + "    redact: {files: {tools: [x], roots: [/]}}\n", "servers.a.redact.files.roots[0]: must be an absolute path other than /"},
		{"twice a tool", "version: 1\nauth: {tokens: {a: s}}\n" + srv + "    redact: {files: {tools: [x, x], roots: [/d]}}\n", "servers.a.redact.files.tools[1]: is listed twice"},
		{"tiny file limit", "version: 1\nauth: {tokens: {a: s}}\n" + srv + "    redact: {files: {tools: [x], roots: [/d], maxBytes: 10B}}\n", "servers.a.redact.files.maxBytes: must be between"},
		{"files unredacted", "version: 1\nauth: {tokens: {a: s}}\n" + srv + "    redact: {enabled: false, files: {tools: [x], roots: [/d]}}\n", "servers.a.redact.files: needs redact.enabled"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse([]byte(c.doc), noEnv)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want it to contain %q", err, c.want)
			}
			if err != nil && (strings.Contains(err.Error(), "b c") || strings.Contains(err.Error(), ": s ")) {
				t.Errorf("the error quotes a token: %v", err)
			}
		})
	}
}

func TestDefaults(t *testing.T) {
	t.Parallel()
	c, err := Parse([]byte("version: 1\nauth: {tokens: {t: secret}}\nservers:\n  a:\n    stdio: {command: srv}\n  b:\n    stdio: {command: srv, inheritEnv: []}\n"), noEnv)
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
	const head = "version: 1\nauth: {tokens: {t: secret}}\nservers:\n  a:\n"
	cases := []struct {
		name, doc, want string
	}{
		{"empty", "", "empty"},
		{"unknown key", head + "    stdio: {command: x}\n    escrow: {ttl: 1h}\n", "field escrow not found"},
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
		{"short backoff", head + "    stdio: {command: x}\n    restart: {maxBackoff: 0s}\n", "maxBackoff: must be between 1s and 5m"},
		{"bad name", "version: 1\nauth: {tokens: {t: secret}}\nservers:\n  Notes:\n    stdio: {command: x}\n", "servers.Notes: server names"},
		{"underscore name", "version: 1\nauth: {tokens: {t: secret}}\nservers:\n  _status:\n    stdio: {command: x}\n", "server names"},
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
	doc := "version: 1\nauth: {tokens: {t: secret}}\nservers:\n  a:\n    http: {url: 'https://user:hunter22@a.example.com/mcp?k=${KEY}'}\n" +
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
	_, err := Parse([]byte("version: 1\nauth: {tokens: {t: secret}}\nservers:\n  a:\n    stdio: {command: x, args: ghp_abcdefghijklmnop}\n"), noEnv)
	if err == nil || strings.Contains(err.Error(), "ghp_") {
		t.Errorf("err = %v", err)
	}
	_, err = Parse([]byte("version: 1\nauth: {tokens: {t: secret}}\nservers:\n  a:\n    stdio: {command: x}\n    callTimeout: 30\n"), noEnv)
	if err == nil || !strings.Contains(err.Error(), "line 6") {
		t.Errorf("a duration error does not say where: %v", err)
	}
}

func TestExpansionCannotInjectStructure(t *testing.T) {
	t.Parallel()
	doc := "version: 1\nauth: {tokens: {t: secret}}\nservers:\n  a:\n    stdio:\n      command: x\n      args: ['${EVIL}']\n"
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
	if _, err := Load(path, env(map[string]string{
		"NOTES_DB": "d", "NOTES_TOKEN": "t", "SHOP_KEY": "k",
		"LAPTOP_TOKEN": "l", "ADMIN_TOKEN": "a", "PHONE_TOKEN": "p",
	})); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml"), noEnv); err == nil {
		t.Error("Load of a missing file succeeded")
	}
}

func TestForwardMeta(t *testing.T) {
	t.Parallel()
	c, err := Parse([]byte("version: 1\nauth: {tokens: {t: secret}}\nservers:\n  a:\n    stdio: {command: srv}\n    forwardMeta: [example.com/trace, plain]\n  b:\n    stdio: {command: srv}\n"), noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.Servers["a"].ForwardMeta, []string{"example.com/trace", "plain"}) || c.Servers["b"].ForwardMeta != nil {
		t.Errorf("forwardMeta = %v, %v", c.Servers["a"].ForwardMeta, c.Servers["b"].ForwardMeta)
	}
	for k, want := range map[string]bool{
		"io.modelcontextprotocol/clientInfo": true, "dev.mcp/x": true, "mcp/x": true, "modelcontextprotocol.io/x": true,
		"mcpish.example.com/x": false, "example.com/mcp": false, "plain": false, "progressToken": false,
	} {
		if got := ReservedMetaKey(k); got != want {
			t.Errorf("ReservedMetaKey(%q) = %v", k, got)
		}
	}
}

func TestOAuth(t *testing.T) {
	head := "version: 1\nauth: {tokens: {a: s}}\nservers:\n  a:\n    http:\n"
	c, err := Parse([]byte(head+"      url: https://a.example.com/mcp\n      oauth: {}\n"), noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if o := c.Servers["a"].HTTP.OAuth; o == nil || o.RedirectURL != DefaultRedirectURL {
		t.Errorf("oauth = %+v", o)
	}
	c, err = Parse([]byte(head+"      url: http://127.0.0.1:8080/mcp\n      oauth:\n        clientID: c\n        clientSecret: \"${SECRET}\"\n"+
		"        redirectURL: https://app.example.com/cb\n        scopes: [read, offline_access]\n"+
		"        authServerMetadataURL: https://auth.example.com/.well-known/oauth-authorization-server\n"), env(map[string]string{"SECRET": "s3cret"}))
	if err != nil {
		t.Fatal(err)
	}
	if o := c.Servers["a"].HTTP.OAuth; o.ClientSecret != "s3cret" || len(o.Scopes) != 2 {
		t.Errorf("oauth = %+v", o)
	}
	for _, tc := range []struct{ name, body, want string }{
		{"plain http", "      url: http://a.example.com/mcp\n      oauth: {}\n", "servers.a.http.url: must be an https URL, or http on a loopback address, with oauth"},
		{"authorization header", "      url: https://a.example.com/mcp\n      headers: {authorization: x}\n      oauth: {}\n", "servers.a.http.headers.Authorization: cannot be set with oauth"},
		{"secret without id", "      url: https://a.example.com/mcp\n      oauth: {clientSecret: x}\n", "servers.a.http.oauth.clientSecret: needs clientID"},
		{"plain redirect", "      url: https://a.example.com/mcp\n      oauth: {redirectURL: 'http://app.example.com/cb'}\n", "servers.a.http.oauth.redirectURL: must be an https URL"},
		{"plain metadata", "      url: https://a.example.com/mcp\n      oauth: {authServerMetadataURL: 'http://auth.example.com/x'}\n", "servers.a.http.oauth.authServerMetadataURL: must be an https URL"},
		{"bad scope", "      url: https://a.example.com/mcp\n      oauth: {scopes: ['a b']}\n", "servers.a.http.oauth.scopes[0]: must be a scope token"},
		{"twice", "      url: https://a.example.com/mcp\n      oauth: {scopes: [a, a]}\n", "servers.a.http.oauth.scopes[1]: is listed twice"},
		{"unknown", "      url: https://a.example.com/mcp\n      oauth: {tokenURL: x}\n", "field tokenURL not found"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(head+tc.body), noEnv)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestMaxBackoffBounds(t *testing.T) {
	head := "version: 1\nauth: {tokens: {a: s}}\nservers:\n  a:\n    stdio: {command: x}\n    restart: {maxBackoff: "
	if _, err := Parse([]byte(head+"5m}\n"), noEnv); err != nil {
		t.Errorf("5m: %v", err)
	}
	for _, v := range []string{"5m1s", "1h", "500ms"} {
		_, err := Parse([]byte(head+v+"}\n"), noEnv)
		if err == nil || !strings.Contains(err.Error(), "servers.a.restart.maxBackoff: must be between 1s and 5m") {
			t.Errorf("%s: err = %v", v, err)
		}
	}
}

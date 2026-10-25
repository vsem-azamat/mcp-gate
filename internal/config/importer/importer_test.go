package importer

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vsem-azamat/mcp-gate/internal/config"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("%s differs (run go test -update):\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

func importFile(t *testing.T, name string, opts Options) (*Result, error) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return Import(data, opts)
}

// anyValue sets every variable, to a value of its own, so that imported configs can be loaded.
func anyValue(name string) (string, bool) { return "value-" + name, true }

func TestImportSupported(t *testing.T) {
	t.Parallel()
	res, err := importFile(t, "supported.json", Options{})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "supported.yaml", res.YAML)
	if len(res.Unimplemented) != 0 {
		t.Errorf("unimplemented = %v", res.Unimplemented)
	}
	wantWarnings := []string{
		"mcpServers.plain.args[1]: a $ that is not a variable reference",
		"mcpServers.plain: the reconnect interval is raised to the minimum of 1s",
		"mcpServers.shop.headers.Accept-Encoding is dropped",
		"mcpServers.wrapped-oddly: the env(1) command line is not understood",
	}
	for _, w := range wantWarnings {
		if !slices.ContainsFunc(res.Warnings, func(s string) bool { return strings.HasPrefix(s, w) }) {
			t.Errorf("no warning %q in %q", w, res.Warnings)
		}
	}
	c, err := config.Parse(res.YAML, anyValue)
	if err != nil {
		t.Fatalf("the imported config does not load: %v", err)
	}
	notes := c.Servers["notes"]
	if notes.Stdio.Command != "notes-server" || notes.Stdio.Env["HOME"] != "/srv/notes-home" ||
		notes.Stdio.Env["NOTES_DB"] != "value-NOTES_DB_PATH" || notes.Stdio.Env["SECRET_ONE"] != "" ||
		slices.Contains(notes.Stdio.InheritEnv, "HOME") || notes.CallTimeout.D().String() != "3m0s" {
		t.Errorf("notes = %+v %+v", notes, notes.Stdio)
	}
	clean := c.Servers["clean-room"]
	if !clean.Disabled || clean.Stdio.Cwd != "/srv/clean" || len(clean.Stdio.InheritEnv) != 0 ||
		len(clean.Stdio.Env) != 1 {
		t.Errorf("clean-room = %+v %+v", clean, clean.Stdio)
	}
	if got := c.Servers["plain"].Stdio.Args[1]; got != "$5" {
		t.Errorf("literal $ = %q", got)
	}
	if c.Listen.Addr != "127.0.0.1:9090" || c.StartupGracePeriod.D().String() != "1m30s" ||
		c.Auth.Tokens["laptop"] != "value-HUB_TOKEN_LAPTOP" || c.Auth.Tokens["phone"] != "value-HUB_TOKEN_PHONE" {
		t.Errorf("top level = %+v", c)
	}
	if notes.Tools != nil || notes.Prompts == nil || len(notes.Prompts.Allow) != 0 || notes.Prompts.Allow == nil ||
		!slices.Equal(notes.Resources.Deny, []string{"notes://private"}) || !notes.Log.Requests ||
		!*notes.Redact.Enabled || !notes.Redact.RU || !notes.Redact.HighEntropy || !slices.Equal(notes.Redact.DisableRules, []string{"jwt"}) {
		t.Errorf("notes serving = %+v %+v", notes, notes.Redact)
	}
	if got := c.EffectiveTokens("notes"); len(got) != 2 {
		t.Errorf("notes tokens = %v", got)
	}
	shop := c.Servers["shop"]
	if got := c.EffectiveTokens("shop"); len(got) != 1 || got["shop"] == "" || shop.Log.Requests || *shop.Redact.Enabled ||
		shop.Resources == nil || shop.Resources.Allow == nil || shop.Prompts != nil {
		t.Errorf("shop = %+v, tokens %v", shop, got)
	}
	if !c.Servers["plain"].Auth.Public || c.EffectiveTokens("wrapped-oddly")["laptop"] == "" || *c.Servers["wrapped-oddly"].Auth.Inherit != true {
		t.Errorf("plain or wrapped-oddly auth: %+v %+v", c.Servers["plain"].Auth, c.Servers["wrapped-oddly"].Auth)
	}
	if !slices.Equal(c.Servers["clean-room"].Tools.Deny, []string{"eval"}) || !*c.Servers["clean-room"].Redact.Enabled {
		t.Errorf("clean-room = %+v", c.Servers["clean-room"])
	}
}

func TestNameTokens(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		tokens []string
		want   []string
	}{
		{[]string{"${HUB_TOKEN_LAPTOP}", "${HUB_TOKEN_PHONE}"}, []string{"laptop", "phone"}},
		{[]string{"${HUB_TOKEN_LAPTOP}", "${HUB_TOKEN_PHONE}", "${HUB_TOKEN_MAIL}"}, []string{"laptop", "phone", "mail"}},
		{[]string{"${MCP_LAPTOP}", "${MCP_LAPTOP_2}"}, []string{"laptop", "laptop_2"}},
		{[]string{"${TOKEN}"}, []string{"token"}},
		{[]string{"${A_X}", "${B_X}"}, []string{"a_x", "b_x"}},
		{[]string{"${T_A}", "${T_}"}, []string{"token1", "token2"}},
		{[]string{"${T_A}", "plain-secret"}, []string{"token1", "token2"}},
	} {
		im := &importer{}
		doc := &document{tokens: c.tokens}
		im.nameTokens(doc)
		var got []string
		for _, v := range c.tokens {
			got = append(got, doc.names[v])
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("names of %v = %v, want %v", c.tokens, got, c.want)
		}
	}
}

// unimplementedDoc holds keys this build does not implement.
const unimplementedDoc = `{
  "mcpProxy": {"type": "streamable-http", "options": {"authTokens": ["${HUB_TOKEN_A}"]}},
  "mcpServers": {
    "files": {"url": "https://files.example.com/mcp", "transportType": "streamable-http",
      "oauth": {"clientId": "c", "pkceDisabled": true, "tokenUrl": "https://auth.example.com/token"}},
    "legacy": {"url": "https://legacy.example.com/sse", "oauth": {}}
  }
}`

func TestImportProductionShape(t *testing.T) {
	t.Parallel()
	res, err := importFile(t, "production-shape.json", Options{})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "production-shape.yaml", res.YAML)
	c, err := config.Parse(res.YAML, anyValue)
	if err != nil {
		t.Fatalf("the import does not load: %v", err)
	}
	if o := c.Servers["mail"].HTTP.OAuth; o == nil || o.RedirectURL != config.DefaultRedirectURL || o.ClientID != "" {
		t.Errorf("mail oauth = %+v", o)
	}
	o := c.Servers["docs"].HTTP.OAuth
	if o == nil || o.AuthServerMetadataURL != "https://auth.example.com/.well-known/oauth-authorization-server/tenant" ||
		!slices.Equal(o.Scopes, []string{"docs.read", "offline_access"}) {
		t.Errorf("docs oauth = %+v", o)
	}
}

func TestImportUnimplemented(t *testing.T) {
	t.Parallel()
	_, err := Import([]byte(unimplementedDoc), Options{})
	var unimpl *UnimplementedError
	if !errors.As(err, &unimpl) {
		t.Fatalf("err = %v, want an UnimplementedError", err)
	}
	want := []string{
		"mcpServers.files.oauth.pkceDisabled (true): mcp-gate always uses PKCE",
		"mcpServers.files.oauth.tokenUrl",
		"mcpServers.legacy (sse transport)",
	}
	if !slices.Equal(unimpl.Keys, want) {
		t.Errorf("unimplemented =\n  %s\nwant\n  %s", strings.Join(unimpl.Keys, "\n  "), strings.Join(want, "\n  "))
	}
	for _, secret := range []string{"HUB_TOKEN", "auth.example.com", "files.example.com"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the error quotes a value (%s): %v", secret, err)
		}
	}
}

func TestImportPartial(t *testing.T) {
	t.Parallel()
	res, err := Import([]byte(unimplementedDoc), Options{Partial: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Unimplemented) != 3 || !strings.Contains(string(res.YAML), config.PartialMarker+": mcpServers.files.oauth.tokenUrl") {
		t.Errorf("unimplemented keys = %v\n%s", res.Unimplemented, res.YAML)
	}
	if _, err := config.Parse(res.YAML, anyValue); err == nil || !strings.Contains(err.Error(), "--partial") {
		t.Errorf("config.Parse of a partial import: err = %v, want a rejection", err)
	}
	// With the marked keys accepted (their comments removed), the config loads.
	var kept []string
	for line := range strings.SplitSeq(string(res.YAML), "\n") {
		if !strings.Contains(line, config.PartialMarker) {
			kept = append(kept, line)
		}
	}
	if _, err := config.Parse([]byte(strings.Join(kept, "\n")), anyValue); err != nil {
		t.Errorf("the accepted partial import does not load: %v", err)
	}
}

func TestImportOAuth(t *testing.T) {
	t.Parallel()
	doc := `{"mcpProxy": {"type": "streamable-http", "options": {"authTokens": ["${T_A}"]}},
  "mcpServers": {
    "a": {"url": "https://a.example.com/mcp", "transportType": "streamable-http",
      "oauth": {"ClientID": "$CLIENT_ID", "clientSecret": "written-secret", "redirectUri": "https://app.example.com/cb", "pkceDisabled": false}},
    "s": {"command": "x", "oauth": {}}
  }}`
	res, err := Import([]byte(doc), Options{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := config.Parse(res.YAML, anyValue)
	if err != nil {
		t.Fatalf("%v\n%s", err, res.YAML)
	}
	o := c.Servers["a"].HTTP.OAuth
	if o.ClientID != "value-CLIENT_ID" || o.ClientSecret != "written-secret" || o.RedirectURL != "https://app.example.com/cb" {
		t.Errorf("oauth = %+v", o)
	}
	warnings := strings.Join(res.Warnings, "\n")
	for _, want := range []string{"mcpServers.a.oauth.clientSecret is written in the file", "mcpServers.s.oauth is dropped"} {
		if !strings.Contains(warnings, want) {
			t.Errorf("warnings lack %q:\n%s", want, warnings)
		}
	}
	if strings.Contains(warnings, "written-secret") {
		t.Error("a warning quotes the secret")
	}
	for name, bad := range map[string]string{
		"plain http":    `"url": "http://a.example.com/mcp", "transportType": "streamable-http", "oauth": {}`,
		"bad redirect":  `"url": "https://a.example.com/mcp", "transportType": "streamable-http", "oauth": {"redirectUri": "http://app.example.com/cb"}`,
		"not an object": `"url": "https://a.example.com/mcp", "transportType": "streamable-http", "oauth": true`,
	} {
		_, err := Import([]byte(`{"mcpProxy": {"type": "streamable-http"}, "mcpServers": {"a": {`+bad+`}}}`), Options{})
		if err == nil {
			t.Errorf("%s: imported", name)
		}
	}
}

func TestImportErrors(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, doc, want string }{
		{"not json", "{", "not valid JSON"},
		{"two values", `{"mcpProxy":{"type":"streamable-http"},"mcpServers":{"a":{"command":"x"}}} {}`, "more than one"},
		{"v1", `{"server":{},"clients":{}}`, "v1 config"},
		{"no proxy", `{"mcpServers":{"a":{"command":"x"}}}`, "mcpProxy is required"},
		{"no servers", `{"mcpProxy":{"type":"streamable-http"}}`, "mcpServers is empty"},
		{"bad name", `{"mcpProxy":{"type":"streamable-http"},"mcpServers":{"My Server":{"command":"x"}}}`, "rename the server"},
		{"both", `{"mcpProxy":{"type":"streamable-http"},"mcpServers":{"a":{"command":"x","url":"https://a.example.com"}}}`, "mutually exclusive"},
		{"neither", `{"mcpProxy":{"type":"streamable-http"},"mcpServers":{"a":{}}}`, "command or url is required"},
		{"bad transport", `{"mcpProxy":{"type":"streamable-http"},"mcpServers":{"a":{"transportType":"ws","url":"https://a.example.com"}}}`, "must be stdio, sse or streamable-http"},
		{"userinfo", `{"mcpProxy":{"type":"streamable-http"},"mcpServers":{"a":{"transportType":"streamable-http","url":"https://u:hunter22@a.example.com"}}}`, "user information"},
		{"bad timeout", `{"mcpProxy":{"type":"streamable-http"},"mcpServers":{"a":{"command":"x","timeout":"soon"}}}`, "timeout: is not a duration"},
		{"case clash", `{"mcpProxy":{"type":"streamable-http"},"mcpServers":{"a":{"command":"x","options":{"disabled":true,"Disabled":false}}}}`, "differ only in case"},
		{"tiny http timeout", `{"mcpProxy":{"type":"streamable-http"},"mcpServers":{"a":{"transportType":"streamable-http","url":"https://a.example.com","timeout":5}}}`, "shorter than a millisecond"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Import([]byte(tc.doc), Options{Partial: true})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), "hunter22") {
				t.Errorf("the error quotes a value: %v", err)
			}
		})
	}
}

func TestParseEnvWrapper(t *testing.T) {
	t.Parallel()
	w, ok := parseEnvWrapper([]string{"-u", "A", "-uB", "--unset=C", "--unset", "D", "-C", "/d", "--", "K=V", "cmd", "-u", "x"})
	if !ok || !slices.Equal(w.unset, []string{"A", "B", "C", "D"}) || w.chdir != "/d" || w.assign["K"] != "V" ||
		w.command != "cmd" || !slices.Equal(w.args, []string{"-u", "x"}) {
		t.Errorf("parseEnvWrapper = %+v, %v", w, ok)
	}
	for _, args := range [][]string{{}, {"-u"}, {"K=V"}, {"-S", "a b"}, {"-iu", "A", "cmd"}, {"-0", "cmd"}} {
		if _, ok := parseEnvWrapper(args); ok {
			t.Errorf("parseEnvWrapper(%q) succeeded", args)
		}
	}
}

func TestConvertVars(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"plain": "plain", "$A": "${A}", "${A}": "${A}", "x$A_1/y": "x${A_1}/y", "$5": "$$5", "a$": "a$$", "$$": "$$$$",
	} {
		var warnings []string
		if got := convertVars(in, &warnings, "p"); got != want {
			t.Errorf("convertVars(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestImportEscrowAndFiles(t *testing.T) {
	t.Parallel()
	doc := `{
  "mcpProxy": {"type": "streamable-http", "options": {"authTokens": ["${T_A}"],
    "redact": {"enabled": true, "escrowTTL": "2h", "escrowMaxEntries": 500000, "fileTools": ["dl"], "fileRoots": ["/srv/dl"]}}},
  "mcpServers": {
    "inherits": {"command": "a"},
    "own": {"command": "b", "options": {"redact": {"enabled": true, "escrowTTL": "30m", "escrowMaxEntries": 5,
      "fileTools": ["get", "get"], "fileRoots": ["/srv/b/", "rel"], "fileMaxBytes": 10}}},
    "noroots": {"command": "c", "options": {"redact": {"enabled": true, "fileTools": ["get"], "fileRoots": ["rel"]}}},
    "off": {"command": "d", "options": {"redact": {"enabled": false, "fileTools": ["get"], "fileRoots": ["/srv/d"]}}}
  }
}`
	res, err := Import([]byte(doc), Options{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := config.Parse(res.YAML, anyValue)
	if err != nil {
		t.Fatalf("%v\n%s", err, res.YAML)
	}
	if c.Escrow.TTL.D().String() != "2h0m0s" || c.Escrow.MaxEntries != config.MaxEscrowEntries {
		t.Errorf("escrow = %+v", c.Escrow)
	}
	in, own := c.Servers["inherits"].Redact, c.Servers["own"].Redact
	if in.EscrowTTL.D().String() != "2h0m0s" || in.Files == nil || !slices.Equal(in.Files.Tools, []string{"dl"}) {
		t.Errorf("inherits = %+v %+v", in, in.Files)
	}
	if own.EscrowTTL.D().String() != "30m0s" || !slices.Equal(own.Files.Tools, []string{"get"}) ||
		!slices.Equal(own.Files.Roots, []string{"/srv/b"}) || *own.Files.MaxBytes != config.MinFileMaxBytes {
		t.Errorf("own = %+v %+v", own, own.Files)
	}
	if c.Servers["noroots"].Redact.Files != nil || c.Servers["off"].Redact.Files != nil || *c.Servers["off"].Redact.Enabled {
		t.Errorf("noroots/off = %+v, %+v", c.Servers["noroots"].Redact, c.Servers["off"].Redact)
	}
	warnings := strings.Join(res.Warnings, "\n")
	for _, want := range []string{
		"mcpProxy.options.redact.escrowMaxEntries is lowered",
		"mcpServers.own.options.redact.escrowMaxEntries is dropped",
		"mcpServers.own.options.redact.fileRoots[1] is dropped",
		"mcpServers.own.options.redact.fileMaxBytes is moved",
		"mcpServers.noroots.options.redact.fileTools is dropped",
		"mcpServers.off: redact has settings but enabled is false",
	} {
		if !strings.Contains(warnings, want) {
			t.Errorf("warnings lack %q:\n%s", want, warnings)
		}
	}
}

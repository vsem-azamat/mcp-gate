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

// anyValue sets every variable, so that imported configs can be loaded.
func anyValue(string) (string, bool) { return "value", true }

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
		notes.Stdio.Env["NOTES_DB"] != "value" || notes.Stdio.Env["SECRET_ONE"] != "" ||
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
}

func TestImportUnimplemented(t *testing.T) {
	t.Parallel()
	_, err := importFile(t, "production-shape.json", Options{})
	var unimpl *UnimplementedError
	if !errors.As(err, &unimpl) {
		t.Fatalf("err = %v, want an UnimplementedError", err)
	}
	want := []string{
		"mcpProxy.addr",
		"mcpProxy.baseURL",
		"mcpProxy.options.authTokens",
		"mcpProxy.options.logEnabled",
		"mcpProxy.options.redact",
		"mcpProxy.startupGracePeriod",
		"mcpServers.browser.options.toolFilter",
		"mcpServers.files.options.redact",
		"mcpServers.files.options.toolFilter",
		"mcpServers.legacy (sse transport)",
		"mcpServers.mail.oauth",
		"mcpServers.mail.options.authTokens",
		"mcpServers.mail.options.logEnabled",
		"mcpServers.mail.options.promptFilter",
		"mcpServers.mail.options.resourceFilter",
		"mcpServers.mail.options.toolFilter",
	}
	if !slices.Equal(unimpl.Keys, want) {
		t.Errorf("unimplemented =\n  %s\nwant\n  %s", strings.Join(unimpl.Keys, "\n  "), strings.Join(want, "\n  "))
	}
	for _, secret := range []string{"HUB_TOKEN", "files.example.com", "download_file", "read_file"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the error quotes a value (%s): %v", secret, err)
		}
	}
}

func TestImportPartial(t *testing.T) {
	t.Parallel()
	res, err := importFile(t, "production-shape.json", Options{Partial: true})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "production-shape.yaml", res.YAML)
	if len(res.Unimplemented) == 0 {
		t.Error("no unimplemented keys reported")
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

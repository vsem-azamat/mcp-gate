package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

const (
	tokenA = "token-a-1111"
	tokenB = "token-b-2222"
)

func env(vars map[string]string) lookupEnv {
	return func(k string) (string, bool) {
		v, ok := vars[k]
		return v, ok
	}
}

var tokens = env(map[string]string{"A_TOKEN": tokenA, "B_TOKEN": tokenB, "EMPTY": ""})

func catalog(schema map[string]any) testkit.Catalog {
	return testkit.Catalog{
		Tools:     []*mcp.Tool{{Name: "search", InputSchema: schema}, {Name: "read", InputSchema: map[string]any{"type": "object"}}},
		Resources: []*mcp.Resource{{URI: "notes://index", Name: "index"}},
	}
}

var (
	schemaQ = map[string]any{"type": "object", "properties": map[string]any{"q": map[string]any{"type": "string"}}}
	schemaN = map[string]any{"type": "object", "properties": map[string]any{"n": map[string]any{"type": "integer"}}}
)

type result struct {
	code           int
	stdout, stderr string
}

func runArgs(t *testing.T, e lookupEnv, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(t.Context(), append([]string{"compare"}, args...), e, &stdout, &stderr)
	r := result{code: code, stdout: stdout.String(), stderr: stderr.String()}
	for _, tok := range []string{tokenA, tokenB} {
		if strings.Contains(r.stdout+r.stderr, tok) {
			t.Errorf("output contains a token:\nstdout: %s\nstderr: %s", r.stdout, r.stderr)
		}
	}
	return r
}

func (r result) want(t *testing.T, code int, stdout ...string) {
	t.Helper()
	if r.code != code {
		t.Errorf("exit code = %d, want %d\nstdout: %s\nstderr: %s", r.code, code, r.stdout, r.stderr)
	}
	for _, s := range stdout {
		if !strings.Contains(r.stdout, s) {
			t.Errorf("stdout does not contain %q:\n%s", s, r.stdout)
		}
	}
}

func TestCompareIdentical(t *testing.T) {
	t.Parallel()
	a := testkit.NewHub(t, testkit.HubOptions{Token: tokenA, Servers: map[string]testkit.Catalog{"server-a": catalog(schemaQ), "server-b": {}}})
	b := testkit.NewHub(t, testkit.HubOptions{Token: tokenB, PageSize: 1, Servers: map[string]testkit.Catalog{"server-a": catalog(schemaQ), "server-b": {}}})
	r := runArgs(t, tokens, "-a", a.URLTemplate(), "-a-token-env", "A_TOKEN", "-b", b.URLTemplate(), "-b-token-env", "B_TOKEN", "server-a", "server-b")
	r.want(t, exitOK,
		"server-a: identical (2 tools, 0 prompts, 1 resource, 0 resource templates)",
		"server-b: identical (0 tools")
	if a.Unauthorized()+b.Unauthorized() != 0 {
		t.Error("a token was sent to the wrong endpoint")
	}
}

func TestCompareDrift(t *testing.T) {
	t.Parallel()
	a := testkit.NewHub(t, testkit.HubOptions{Servers: map[string]testkit.Catalog{"server-a": catalog(schemaQ)}})
	drifted := catalog(schemaN)
	drifted.Resources = nil
	b := testkit.NewHub(t, testkit.HubOptions{Servers: map[string]testkit.Catalog{"server-a": drifted}})
	r := runArgs(t, tokens, "-a", a.URLTemplate(), "-b", b.URLTemplate(), "server-a")
	r.want(t, exitDrift,
		`server-a: tool "search": inputSchema differs`,
		`a: {"properties":{"q":{"type":"string"}},"type":"object"}`,
		`b: {"properties":{"n":{"type":"integer"}},"type":"object"}`,
		`server-a: resource "notes://index": only in a`)
}

func TestCompareUnreadableServer(t *testing.T) {
	t.Parallel()
	a := testkit.NewHub(t, testkit.HubOptions{Token: tokenA, Servers: map[string]testkit.Catalog{"server-a": catalog(schemaQ), "server-b": {}}})
	b := testkit.NewHub(t, testkit.HubOptions{Token: tokenB, Servers: map[string]testkit.Catalog{"server-a": catalog(schemaQ)}})
	r := runArgs(t, tokens, "-a", a.URLTemplate(), "-a-token-env", "A_TOKEN", "-b", b.URLTemplate(), "-b-token-env", "B_TOKEN", "server-b", "server-a")
	r.want(t, exitTrouble, "server-a: identical")
	if !strings.Contains(r.stderr, "server-b: b:") {
		t.Errorf("stderr does not report server-b on b: %s", r.stderr)
	}
}

func TestCompareRejectedToken(t *testing.T) {
	t.Parallel()
	a := testkit.NewHub(t, testkit.HubOptions{Token: "something-else", Servers: map[string]testkit.Catalog{"server-a": {}}})
	r := runArgs(t, tokens, "-a", a.URLTemplate(), "-a-token-env", "A_TOKEN", "-b", a.URLTemplate(), "-b-token-env", "B_TOKEN", "server-a")
	r.want(t, exitTrouble)
	if !strings.Contains(r.stderr, "server-a: a:") || !strings.Contains(r.stderr, "server-a: b:") {
		t.Errorf("stderr does not report server-a as failed on both sources: %s", r.stderr)
	}
	if a.Unauthorized() == 0 {
		t.Error("the hub rejected nothing")
	}
}

func TestCompareSnapshot(t *testing.T) {
	t.Parallel()
	old := testkit.NewHub(t, testkit.HubOptions{Token: tokenA, Servers: map[string]testkit.Catalog{"server-a": catalog(schemaQ), "server-b": {}}})
	path := filepath.Join(t.TempDir(), "old.json")

	r := runArgs(t, tokens, "-a", old.URLTemplate(), "-a-token-env", "A_TOKEN", "-snapshot", path, "server-a", "server-b")
	r.want(t, exitOK, "server-a: read 2 tools", "snapshot of 2 servers written to "+path)

	same := testkit.NewHub(t, testkit.HubOptions{Servers: map[string]testkit.Catalog{"server-a": catalog(schemaQ), "server-b": {}}})
	runArgs(t, tokens, "-a", path, "-b", same.URLTemplate()).want(t, exitOK, "server-a: identical", "server-b: identical")

	drifted := testkit.NewHub(t, testkit.HubOptions{Servers: map[string]testkit.Catalog{"server-a": catalog(schemaN), "server-b": {}}})
	runArgs(t, tokens, "-a", path, "-b", drifted.URLTemplate(), "server-a").want(t, exitDrift, `tool "search": inputSchema differs`)
}

func TestCompareSnapshotPartialRead(t *testing.T) {
	t.Parallel()
	hub := testkit.NewHub(t, testkit.HubOptions{Servers: map[string]testkit.Catalog{"server-a": {}}})
	b := testkit.NewHub(t, testkit.HubOptions{Servers: map[string]testkit.Catalog{"server-a": {}, "server-b": {}}})
	path := filepath.Join(t.TempDir(), "snap.json")
	r := runArgs(t, tokens, "-a", hub.URLTemplate(), "-b", b.URLTemplate(), "-snapshot", path, "server-a", "server-b")
	r.want(t, exitTrouble, "server-a: identical")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("snapshot was written after a failed read (stat: %v)", err)
	}
}

func TestCompareUsage(t *testing.T) {
	t.Parallel()
	snap := filepath.Join(t.TempDir(), "snap.json")
	if err := os.WriteFile(snap, []byte(`{"version":1,"servers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(empty, []byte(`{"version":1,"servers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// Nothing listens there, so a case that wrongly gets past parsing fails fast without network.
	const ep = "http://127.0.0.1:1/{server}/mcp"
	tests := []struct {
		name       string
		args       []string
		wantStderr string
	}{
		{"no a", []string{"-b", ep, "s"}, "-a is required"},
		{"no b", []string{"-a", ep, "s"}, "-b is required unless -snapshot is given"},
		{"no server", []string{"-a", ep, "-b", ep}, "name at least one server"},
		{"no placeholder", []string{"-a", "http://127.0.0.1:1/mcp", "-b", ep, "s"}, "-a: endpoint template has no {server}"},
		{"placeholder in host", []string{"-a", ep, "-b", "https://{server}.example.com/mcp", "s"}, "-b: endpoint template may have {server} only in its path"},
		{"user info", []string{"-a", ep, "-b", "http://u:p@127.0.0.1:1/{server}/mcp", "s"}, "-b: endpoint template must not contain user information"},
		{"query", []string{"-a", "http://127.0.0.1:1/{server}/mcp?key=k", "-b", ep, "s"}, "must not contain a query string"},
		{"empty snapshot", []string{"-a", empty, "-b", ep}, "-a: the snapshot has no servers"},
		{"empty server name", []string{"-a", ep, "-b", ep, ""}, `invalid server name ""`},
		{"flag after servers", []string{"-a", ep, "-b", ep, "s", "-timeout", "5s"}, `invalid server name "-timeout"`},
		{"server named twice", []string{"-a", ep, "-b", ep, "s", "s"}, `server "s" is named twice`},
		{"unset token", []string{"-a", ep, "-a-token-env", "NOPE", "-b", ep, "s"}, "environment variable NOPE is unset or empty"},
		{"empty token", []string{"-a", ep, "-b", ep, "-b-token-env", "EMPTY", "s"}, "environment variable EMPTY is unset or empty"},
		{"token for snapshot", []string{"-a", snap, "-a-token-env", "A_TOKEN", "-b", ep}, "-a-token-env is set, but -a is a snapshot file"},
		{"token without b", []string{"-a", ep, "-snapshot", "x.json", "-b-token-env", "B_TOKEN", "s"}, "-b-token-env is set without -b"},
		{"snapshot from snapshot", []string{"-a", snap, "-snapshot", "x.json"}, "-snapshot needs an endpoint for -a"},
		{"missing snapshot", []string{"-a", filepath.Join(t.TempDir(), "missing.json"), "-b", ep}, "-a: open"},
		{"slash in server", []string{"-a", ep, "-b", ep, "a/b"}, `invalid server name "a/b"`},
		{"bad timeout", []string{"-a", ep, "-b", ep, "-timeout", "0s", "s"}, "-timeout must be positive"},
		{"unknown flag", []string{"-x"}, "flag provided but not defined: -x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := runArgs(t, tokens, tt.args...)
			if r.code != exitUsage {
				t.Errorf("exit code = %d, want %d", r.code, exitUsage)
			}
			if !strings.Contains(r.stderr, tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", r.stderr, tt.wantStderr)
			}
			if r.stdout != "" {
				t.Errorf("stdout = %q, want empty", r.stdout)
			}
		})
	}
}

func TestCompareTimeout(t *testing.T) {
	t.Parallel()
	// The server accepts notifications and never answers requests, until the test ends.
	release := make(chan struct{})
	stall := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg struct {
			ID json.RawMessage `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil || msg.ID == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(stall.Close)
	t.Cleanup(func() { close(release) }) // runs before stall.Close
	hub := testkit.NewHub(t, testkit.HubOptions{Servers: map[string]testkit.Catalog{"server-a": {}}})
	start := time.Now()
	r := runArgs(t, tokens, "-a", hub.URLTemplate(), "-b", stall.URL+"/{server}/mcp", "-timeout", "200ms", "server-a")
	r.want(t, exitTrouble)
	if !strings.Contains(r.stderr, "server-a: b:") {
		t.Errorf("stderr does not report server-a on b: %s", r.stderr)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("compare took %s with a 200ms timeout", d)
	}
}

func TestCompareHelp(t *testing.T) {
	t.Parallel()
	r := runArgs(t, tokens, "-h")
	if r.code != exitOK || !strings.HasPrefix(r.stderr, compareUsage) {
		t.Errorf("exit code = %d, stderr = %q", r.code, r.stderr)
	}
}

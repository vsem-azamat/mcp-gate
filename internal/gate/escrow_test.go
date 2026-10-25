package gate_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

const escrowKey = "escrow-key-0123456789abcdef"

var escrowMarkerRE = regexp.MustCompile(`\[REDACTED:([a-z_]+) #(k[a-z2-7]{10})\]`)

// escrowGet performs a request on the gate with the given headers ("Host" sets the Host).
func (r *running) escrowGet(t *testing.T, method, path string, headers ...string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, r.base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		if headers[i] == "Host" {
			req.Host = headers[i+1]
			continue
		}
		req.Header.Set(headers[i], headers[i+1])
	}
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	res, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, string(body)
}

func TestEscrowContract(t *testing.T) {
	const secret = "Summer-Blue-77!"
	r := startGate(t, configDoc("listen:\n  allowedHosts: [127.0.0.1]\n", map[string]string{
		"chat": stdioServer(t, testkit.Fake{}, "redact: {escrowTTL: 1h}\n"),
	}), gateOpts{escrowKey: escrowKey})
	r.waitReady(t, "chat")
	cs := r.connect(t, "chat", clientOpts{})
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{
		"text": "the password: " + secret + " ok", "chat_id": 42, "message_ids": []int{7}, "query": "private words",
	}})
	if err != nil {
		t.Fatal(err)
	}
	got := textOf(t, res)
	m := escrowMarkerRE.FindStringSubmatch(got)
	if m == nil || m[1] != "password" || strings.Contains(got, secret) || got != "the password: "+m[0]+" ok" {
		t.Fatalf("result = %q", got)
	}
	handle := m[2]
	// The API is outside the MCP routes' checks: a client token does not open it, and the Host
	// check does not apply.
	if code, _, _ := r.escrowGet(t, http.MethodGet, "/_escrow/"+handle+"/meta", "Authorization", "Bearer "+laptopToken); code != http.StatusUnauthorized {
		t.Errorf("a client token = %d, want 401", code)
	}
	if code, _, _ := r.escrowGet(t, http.MethodGet, "/_escrow/"+handle+"/meta", "Authorization", "Bearer "+escrowKey, "Host", "other.example.com"); code != http.StatusOK {
		t.Errorf("another Host = %d, want 200", code)
	}
	testkit.CheckEscrowContract(t, testkit.EscrowTarget{
		Base: r.base, Key: escrowKey, Handle: handle, Secret: secret, TTL: time.Hour,
		Meta: map[string]any{
			"type": "password", "server": "chat", "tool": "echo", "preview": "Summ…77!",
			"source": map[string]any{"chat_id": float64(42), "message_ids": []any{float64(7)}},
		},
	})
	calls := r.logs.lines("call")
	if len(calls) == 0 || calls[0]["redactions"] != float64(1) {
		t.Errorf("audit lines = %v", calls)
	}
	if logs := r.logs.String(); strings.Contains(logs, secret) || strings.Contains(logs, escrowKey) || strings.Contains(logs, "private words") {
		t.Error("a log line holds the secret, the key or an argument")
	}
}

func TestEscrowOff(t *testing.T) {
	r := startGate(t, configDoc("", map[string]string{"chat": stdioServer(t, testkit.Fake{}, "")}), gateOpts{})
	r.waitReady(t, "chat")
	code, _, body := r.escrowGet(t, http.MethodGet, "/_escrow/kaaaaaaaaaa/meta", "Authorization", "Bearer "+escrowKey)
	if code != http.StatusNotFound || body != "404 page not found\n" {
		t.Errorf("without a key hash = %d %q", code, body)
	}
	cs := r.connect(t, "chat", clientOpts{})
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "pass" + "word: Summer-Blue-77!"}})
	if err != nil || textOf(t, res) != "password: [REDACTED:password]" {
		t.Errorf("echo = %v, %v", res, err)
	}
}

// TestEscrowFailedAuthLimit checks that the failed-auth limit is keyed by the client address,
// read from X-Forwarded-For only behind a proxy.
func TestEscrowFailedAuthLimit(t *testing.T) {
	for _, behind := range []bool{true, false} {
		t.Run(fmt.Sprintf("behindProxy=%v", behind), func(t *testing.T) {
			head := ""
			if behind {
				head = "listen:\n  behindProxy: true\n"
			}
			r := startGate(t, configDoc(head, map[string]string{"chat": stdioServer(t, testkit.Fake{}, "")}), gateOpts{escrowKey: escrowKey})
			path := "/_escrow/kaaaaaaaaaa/meta"
			for i := range 20 {
				if code, _, _ := r.escrowGet(t, http.MethodGet, path, "Authorization", "Bearer wrong", "X-Forwarded-For", "203.0.113.5"); code != http.StatusUnauthorized {
					t.Fatalf("failure %d = %d, want 401", i+1, code)
				}
			}
			code, h, _ := r.escrowGet(t, http.MethodGet, path, "Authorization", "Bearer "+escrowKey, "X-Forwarded-For", "203.0.113.5")
			if code != http.StatusTooManyRequests || h.Get("Retry-After") == "" {
				t.Errorf("the limited client with the key = %d %v, want 429", code, h)
			}
			code, _, _ = r.escrowGet(t, http.MethodGet, path, "Authorization", "Bearer "+escrowKey, "X-Forwarded-For", "203.0.113.6")
			want := http.StatusNotFound // a client of its own, past the auth check
			if !behind {
				want = http.StatusTooManyRequests // X-Forwarded-For is ignored: the same peer
			}
			if code != want {
				t.Errorf("another forwarded client = %d, want %d", code, want)
			}
			if lines := r.logs.lines("escrow access"); len(lines) == 0 || (behind && lines[0]["remote"] != "203.0.113.5") || (!behind && lines[0]["remote"] != "127.0.0.1") {
				t.Errorf("access lines = %v", lines)
			}
		})
	}
}

func TestFileScanning(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	r := startGate(t, configDoc("", map[string]string{
		"dl": stdioServer(t, testkit.Fake{}, fmt.Sprintf("redact:\n  files: {tools: [writefile], roots: [%q], maxBytes: 1KiB}\n", dir)),
	}), gateOpts{escrowKey: escrowKey})
	r.waitReady(t, "dl")
	cs := r.connect(t, "dl", clientOpts{})
	call := func(path, text string, repeat int) (*mcp.CallToolResult, error) {
		return cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "writefile", Arguments: map[string]any{
			"path": path, "text": text, "repeat": repeat, "chat_id": "c1",
		}})
	}
	const content = "DB_HOST=db\nDB_PASS" + "WORD=" + "hunter2!x\n"
	secretFile := filepath.Join(dir, "chat_1.txt")
	res, err := call(secretFile, content, 1)
	if err != nil {
		t.Fatal(err)
	}
	got := textOf(t, res)
	m := escrowMarkerRE.FindStringSubmatch(got)
	structured, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if m == nil || m[1] != "file" || strings.Contains(got, dir) || strings.Contains(string(structured), dir) ||
		!strings.Contains(string(structured), m[0]) {
		t.Fatalf("result = %q, structured %s", got, structured)
	}
	code, _, body := r.escrowGet(t, http.MethodGet, "/_escrow/"+m[2]+"/meta", "Authorization", "Bearer "+escrowKey)
	var meta map[string]any
	if err := json.Unmarshal([]byte(body), &meta); err != nil || code != http.StatusOK || meta["kind"] != "file" ||
		meta["file_name"] != "chat_1.txt" || meta["tool"] != "writefile" || meta["size"] != float64(len(content)) {
		t.Fatalf("meta = %d %s", code, body)
	}
	if code, h, body := r.escrowGet(t, http.MethodGet, "/_escrow/"+m[2], "Authorization", "Bearer "+escrowKey); code != http.StatusOK ||
		body != content || h.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("value = %d %q", code, body)
	}

	// A text file too large to scan withholds the whole result.
	res, err = call(filepath.Join(dir, "big.log"), "line of text\n", 200)
	if err == nil || !strings.Contains(err.Error(), "withheld") {
		t.Errorf("a file too large to scan = %v, %v", res, err)
	}
	// Files without secrets and files outside the roots pass.
	for _, path := range []string{filepath.Join(dir, "notes.txt"), filepath.Join(outside, "a.env")} {
		text := "nothing here\n"
		if !strings.HasPrefix(path, dir) {
			text = content
		}
		res, err := call(path, text, 1)
		if err != nil || textOf(t, res) != "Media downloaded to "+path+"." {
			t.Errorf("%s = %v, %v", path, res, err)
		}
	}
	outcomes := map[string]float64{}
	for _, l := range r.logs.lines("call") {
		if o, _ := l["outcome"].(string); o != "" {
			n, _ := l["redactions"].(float64)
			outcomes[o] += n + 1000
		}
	}
	if outcomes["withheld"] != 1000 || outcomes["ok"] != 3001 {
		t.Errorf("audit outcomes (count*1000 + redactions) = %v", outcomes)
	}
}

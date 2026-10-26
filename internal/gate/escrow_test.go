package gate_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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
			code, h, _ := r.escrowGet(t, http.MethodGet, path, "Authorization", "Bearer wrong", "X-Forwarded-For", "203.0.113.5")
			if code != http.StatusTooManyRequests || h.Get("Retry-After") == "" {
				t.Errorf("the limited client's wrong key = %d %v, want 429", code, h)
			}
			if code, _, _ := r.escrowGet(t, http.MethodGet, path, "Authorization", "Bearer "+escrowKey, "X-Forwarded-For", "203.0.113.5"); code != http.StatusTooManyRequests {
				t.Errorf("the limited client with the key = %d, want 429", code)
			}
			code, _, _ = r.escrowGet(t, http.MethodGet, path, "Authorization", "Bearer "+escrowKey, "X-Forwarded-For", "203.0.113.6")
			want := http.StatusNotFound // a client of its own, past the auth check
			if !behind {
				want = http.StatusTooManyRequests // X-Forwarded-For is ignored: the same peer
			}
			if code != want {
				t.Errorf("another forwarded client's wrong key = %d, want %d", code, want)
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

// TestEscrowPerServer checks redact.escrow: false and escrow.sourceArguments.
func TestEscrowPerServer(t *testing.T) {
	dir := t.TempDir()
	r := startGate(t, configDoc("escrow: {sourceArguments: [ticket]}\n", map[string]string{
		"kept":  stdioServer(t, testkit.Fake{}, ""),
		"plain": stdioServer(t, testkit.Fake{}, fmt.Sprintf("redact:\n  escrow: false\n  files: {tools: [writefile], roots: [%q]}\n", dir)),
	}), gateOpts{escrowKey: escrowKey})
	r.waitReady(t, "kept")
	r.waitReady(t, "plain")
	args := map[string]any{"text": "pass" + "word: Summer-Blue-77!", "ticket": "T-1", "chat_id": 42}
	res, err := r.connect(t, "kept", clientOpts{}).CallTool(t.Context(), &mcp.CallToolParams{Name: "echo", Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	m := escrowMarkerRE.FindStringSubmatch(textOf(t, res))
	if m == nil {
		t.Fatalf("kept = %q", textOf(t, res))
	}
	code, _, body := r.escrowGet(t, http.MethodGet, "/_escrow/"+m[2]+"/meta", "Authorization", "Bearer "+escrowKey)
	var meta struct{ Source map[string]any }
	if err := json.Unmarshal([]byte(body), &meta); err != nil || code != http.StatusOK || len(meta.Source) != 1 || meta.Source["ticket"] != "T-1" {
		t.Errorf("meta = %d %s, want the source {ticket}", code, body)
	}

	plain := r.connect(t, "plain", clientOpts{})
	res, err = plain.CallTool(t.Context(), &mcp.CallToolParams{Name: "echo", Arguments: args})
	if err != nil || textOf(t, res) != "password: [REDACTED:password]" {
		t.Errorf("plain = %v, %v", res, err)
	}
	path := filepath.Join(dir, "a.env")
	res, err = plain.CallTool(t.Context(), &mcp.CallToolParams{Name: "writefile", Arguments: map[string]any{
		"path": path, "text": "DB_PASS" + "WORD=" + "hunter2!x\n", "repeat": 1,
	}})
	if err != nil || !strings.Contains(textOf(t, res), "[REDACTED:file] file_name=a.env") || strings.Contains(textOf(t, res), dir) {
		t.Errorf("plain file = %v, %v", res, err)
	}
	if n := len(r.logs.lines("escrowed secret")) + len(r.logs.lines("escrowed file")); n != 1 {
		t.Errorf("%d entries kept, want 1 (from kept)", n)
	}
}

// socketGet performs a request on the escrow socket at sock.
func socketGet(t *testing.T, sock, method, path string, headers ...string) (int, string) {
	t.Helper()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(t.Context(), method, "http://escrow"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	res, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(body)
}

func TestEscrowSocket(t *testing.T) {
	const secret = "Summer-Blue-77!"
	for _, tcp := range []bool{true, false} {
		t.Run(fmt.Sprintf("tcp=%v", tcp), func(t *testing.T) {
			dir, err := os.MkdirTemp("", "esc") //nolint:usetesting // t.TempDir can exceed the socket path limit of about 100 bytes
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			sock := filepath.Join(dir, "run", "escrow.sock")
			r := startGate(t, configDoc(fmt.Sprintf("escrow:\n  tcp: %v\n  socket: {path: %q}\n", tcp, sock), map[string]string{
				"chat": stdioServer(t, testkit.Fake{}, ""),
			}), gateOpts{escrowKey: escrowKey})
			r.waitReady(t, "chat")
			res, err := r.connect(t, "chat", clientOpts{}).CallTool(t.Context(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{
				"text": "the password: " + secret, "chat_id": 42,
			}})
			if err != nil {
				t.Fatal(err)
			}
			m := escrowMarkerRE.FindStringSubmatch(textOf(t, res))
			if m == nil {
				t.Fatalf("result = %q", textOf(t, res))
			}
			// By default no user is served without the key on the socket.
			if code, _ := socketGet(t, sock, http.MethodGet, "/_escrow/"+m[2]); code != http.StatusUnauthorized {
				t.Errorf("socket without a key = %d, want 401", code)
			}
			if code, body := socketGet(t, sock, http.MethodGet, "/_escrow/"+m[2], "Authorization", "Bearer "+escrowKey); code != http.StatusOK || body != secret {
				t.Errorf("socket with the key = %d %q", code, body)
			}
			if code, body := socketGet(t, sock, http.MethodGet, "/_escrow/"+m[2]+"/meta", "Authorization", "Bearer "+escrowKey); code != http.StatusOK || !strings.Contains(body, `"source":{"chat_id":42}`) {
				t.Errorf("socket meta with the key = %d %q", code, body)
			}
			if code, _ := socketGet(t, sock, http.MethodGet, "/chat/mcp"); code != http.StatusNotFound {
				t.Errorf("an MCP route on the socket = %d, want 404", code)
			}
			// The listener never serves without the key.
			if code, _, _ := r.escrowGet(t, http.MethodGet, "/_escrow/"+m[2]); tcp && code != http.StatusUnauthorized {
				t.Errorf("TCP without a key = %d, want 401", code)
			}
			code, _, _ := r.escrowGet(t, http.MethodGet, "/_escrow/"+m[2], "Authorization", "Bearer "+escrowKey)
			if want := map[bool]int{true: http.StatusOK, false: http.StatusNotFound}[tcp]; code != want {
				t.Errorf("TCP with the key = %d, want %d", code, want)
			}
			if lines := r.logs.lines("escrow access"); len(lines) == 0 || lines[0]["remote"] != "unix:uid="+strconv.Itoa(os.Geteuid()) {
				t.Errorf("access lines = %v", lines)
			}
			if fi, err := os.Stat(filepath.Dir(sock)); err != nil || fi.Mode().Perm() != 0o700 {
				t.Errorf("socket directory = %v, %v; want 0700", fi, err)
			}
			if fi, err := os.Lstat(sock); err != nil || fi.Mode().Perm() != 0o600 {
				t.Errorf("socket = %v, %v; want 0600", fi, err)
			}
			r.stop()
			if _, err := os.Lstat(sock); !os.IsNotExist(err) {
				t.Errorf("the socket is still there after shutdown: %v", err)
			}
		})
	}
}

func TestEscrowSocketWhileOff(t *testing.T) {
	dir, err := os.MkdirTemp("", "esc") //nolint:usetesting // t.TempDir can exceed the socket path limit of about 100 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "escrow.sock")
	r := startGate(t, configDoc(fmt.Sprintf("escrow:\n  socket: {path: %q}\n", sock), map[string]string{
		"chat": stdioServer(t, testkit.Fake{}, ""),
	}), gateOpts{})
	r.waitReady(t, "chat")
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Errorf("a socket was opened with the escrow off: %v", err)
	}
	if w := r.logs.lines("escrow.socket is set but the escrow is off: no socket is opened"); len(w) != 1 {
		t.Errorf("warnings = %v", w)
	}
}

func TestEscrowSocketOwnUIDWarning(t *testing.T) {
	dir, err := os.MkdirTemp("", "esc") //nolint:usetesting // t.TempDir can exceed the socket path limit of about 100 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	r := startGate(t, configDoc(fmt.Sprintf("escrow:\n  socket: {path: %q, allowUIDs: [%d]}\n", filepath.Join(dir, "e.sock"), os.Geteuid()), map[string]string{
		"chat": stdioServer(t, testkit.Fake{}, ""),
	}), gateOpts{escrowKey: escrowKey})
	r.waitReady(t, "chat")
	if w := r.logs.lines("escrow.socket.allowUIDs lists the gate's own user"); len(w) != 1 || w[0]["level"] != "WARN" {
		t.Errorf("warnings = %v", w)
	}
}

// The default listen address is loopback, so a gate with the escrow on the listener and no
// behindProxy warns that clients behind a same-host proxy share one budget.
func TestEscrowLoopbackListenerWarning(t *testing.T) {
	for _, tc := range []struct {
		head string
		want int
	}{
		{"", 1},
		{"listen: {behindProxy: true, trustedProxies: [127.0.0.1/32]}\n", 0},
	} {
		r := startGate(t, configDoc(tc.head, map[string]string{"chat": stdioServer(t, testkit.Fake{}, "")}), gateOpts{escrowKey: escrowKey})
		r.waitReady(t, "chat")
		if w := r.logs.lines("the escrow API is on a loopback listener without listen.behindProxy: behind a reverse proxy " +
			"on this host every client is 127.0.0.1 and shares one failed-auth budget; set behindProxy and trustedProxies"); len(w) != tc.want {
			t.Errorf("%q: warnings = %v, want %d", tc.head, w, tc.want)
		}
	}
}

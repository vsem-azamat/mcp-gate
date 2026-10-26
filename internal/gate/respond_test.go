package gate_test

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strings"
	"testing"

	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

// rawPost sends body to path with the laptop token, the protocol version header and the given
// Accept, and returns the status, the media type and the body of the answer.
func (r *running) rawPost(t *testing.T, path, version, accept, body string) (int, string, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, r.base+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+laptopToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Mcp-Protocol-Version", version)
	if version >= "2026-07-28" {
		// The standard headers repeat the method and the name.
		var msg struct {
			Method string `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		_ = json.Unmarshal([]byte(body), &msg)
		req.Header.Set("Mcp-Method", msg.Method)
		if msg.Params.Name != "" {
			req.Header.Set("Mcp-Name", msg.Params.Name)
		}
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	mediaType, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
	return res.StatusCode, mediaType, string(data)
}

// eventData returns the data of each event in an event stream.
func eventData(stream string) []string {
	var out []string
	for line := range strings.SplitSeq(stream, "\n") {
		if data, ok := strings.CutPrefix(line, "data: "); ok {
			out = append(out, data)
		}
	}
	return out
}

// TestResponseTypes checks through the HTTP stack that a call without a progress token is
// answered with plain JSON, that a call with one gets an event stream with its progress and then
// its result, that a client accepting only one of the two types gets that one, and that results
// are redacted and audited the same either way.
func TestResponseTypes(t *testing.T) {
	const secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	r := startGate(t, configDoc("", map[string]string{"s": stdioServer(t, testkit.Fake{}, "")}), gateOpts{})
	r.waitReady(t, "s")
	echo := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"echo","arguments":{"text":"token ` + secret + `"}}}`
	progress := `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"progress","arguments":{"steps":3,"ms":10},` +
		`"_meta":{"progressToken":"tok-1"}}}`
	const both = "application/json, text/event-stream"
	const old, current = "2025-11-25", "2026-07-28"
	// A 2026-07-28 request describes its client in _meta.
	meta := `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
		`"io.modelcontextprotocol/clientInfo":{"name":"raw","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}`
	echoCurrent := strings.Replace(echo, `"params":{`, `"params":{`+meta+`},`, 1)
	progressCurrent := strings.Replace(progress, `"_meta":{`, meta+",", 1)

	// redacted checks that one JSON-RPC response is the echo's, with the secret redacted.
	redacted := func(name, msg string) {
		t.Helper()
		var res struct {
			ID     int `json:"id"`
			Result struct {
				Content []struct{ Text string } `json:"content"`
			} `json:"result"`
		}
		if err := json.Unmarshal([]byte(msg), &res); err != nil || res.ID != 7 || len(res.Result.Content) != 1 {
			t.Fatalf("%s: response %q: %v", name, msg, err)
		}
		if text := res.Result.Content[0].Text; strings.Contains(text, secret) || !strings.Contains(text, "[REDACTED:") {
			t.Errorf("%s: result %q", name, text)
		}
	}

	for _, c := range []struct{ name, version, accept, body, want string }{
		{"both", old, both, echo, "application/json"},
		{"both, stream first", old, "text/event-stream, application/json", echo, "application/json"},
		{"any", old, "*/*", echo, "application/json"},
		{"json only", old, "application/json", echo, "application/json"},
		{"stream only", old, "text/event-stream", echo, "text/event-stream"},
		{"json refused", old, "application/json;q=0, text/event-stream", echo, "text/event-stream"},
		{"2026-07-28", current, both, echoCurrent, "application/json"},
	} {
		code, mediaType, body := r.rawPost(t, "/s/mcp", c.version, c.accept, c.body)
		if code != http.StatusOK || mediaType != c.want {
			t.Errorf("%s: %d %s, want 200 %s: %q", c.name, code, mediaType, c.want, body)
			continue
		}
		if mediaType == "application/json" {
			redacted(c.name, body)
			continue
		}
		data := eventData(body)
		if len(data) != 1 {
			t.Fatalf("%s: events %q", c.name, body)
		}
		redacted(c.name, data[0])
	}

	for _, c := range []struct{ version, body string }{{old, progress}, {current, progressCurrent}} {
		code, mediaType, body := r.rawPost(t, "/s/mcp", c.version, both, c.body)
		if code != http.StatusOK || mediaType != "text/event-stream" {
			t.Fatalf("%s with a progress token: %d %s %q", c.version, code, mediaType, body)
		}
		data := eventData(body)
		if len(data) < 2 {
			t.Fatalf("%s with a progress token: events %q", c.version, body)
		}
		for i, d := range data {
			var msg struct {
				ID     *int   `json:"id"`
				Method string `json:"method"`
				Params struct {
					ProgressToken string `json:"progressToken"`
				} `json:"params"`
			}
			if err := json.Unmarshal([]byte(d), &msg); err != nil {
				t.Fatalf("event %q: %v", d, err)
			}
			last := i == len(data)-1
			switch {
			case last && (msg.ID == nil || *msg.ID != 8):
				t.Errorf("the last event is not the result: %q", d)
			case !last && (msg.Method != "notifications/progress" || msg.Params.ProgressToken != "tok-1"):
				t.Errorf("event %d is not the call's progress: %q", i, d)
			}
		}
	}

	// A client that accepts only JSON gets it, without the progress.
	code, mediaType, body := r.rawPost(t, "/s/mcp", old, "application/json", progress)
	if code != http.StatusOK || mediaType != "application/json" || strings.Contains(body, "notifications/progress") {
		t.Errorf("json only with a progress token: %d %s %q", code, mediaType, body)
	}
	// subscriptions/listen needs an event stream.
	listen := `{"jsonrpc":"2.0","id":9,"method":"subscriptions/listen","params":{` + meta + `},"notifications":{"toolsListChanged":true}}}`
	for _, accept := range []string{"application/json", "application/json, text/event-stream;q=0"} {
		if code, _, body := r.rawPost(t, "/s/mcp", current, accept, listen); code != http.StatusBadRequest || !strings.Contains(body, "Accept") {
			t.Errorf("listen with Accept %s: %d %q", accept, code, body)
		}
	}

	// The SDK's handler still refuses a client that accepts neither.
	if code, _, _ := r.rawPost(t, "/s/mcp", old, "text/html", echo); code != http.StatusBadRequest {
		t.Errorf("Accept text/html: %d", code)
	}
	if code, _, _ := r.rawPost(t, "/s/mcp", old, "application/json;q=0, text/event-stream;q=0", echo); code != http.StatusBadRequest {
		t.Errorf("both refused: %d", code)
	}
	if code, _, _ := r.rawPost(t, "/s/mcp", old, "", echo); code != http.StatusBadRequest {
		t.Errorf("no Accept: %d", code)
	}

	if strings.Contains(r.logs.String(), secret) {
		t.Error("the secret reached the log")
	}
	echoes := 0
	for _, l := range r.logs.lines("call") {
		if l["tool"] != "echo" {
			continue
		}
		echoes++
		if l["redactions"] != float64(1) || l["outcome"] != "ok" || l["principal"] != "laptop" || l["method"] != "tools/call" {
			t.Errorf("audit line %v", l)
		}
	}
	if echoes != 7 {
		t.Errorf("%d audit lines for the echo calls, want 7", echoes)
	}
}

// TestPlainNotification checks that a notification, which has no response, is accepted with 202
// whichever type the client accepts.
func TestPlainNotification(t *testing.T) {
	r := startGate(t, configDoc("", map[string]string{"s": stdioServer(t, testkit.Fake{}, "")}), gateOpts{})
	r.waitReady(t, "s")
	const note = `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	for _, accept := range []string{"application/json, text/event-stream", "application/json", "text/event-stream"} {
		if code, _, body := r.rawPost(t, "/s/mcp", "2025-11-25", accept, note); code != http.StatusAccepted || body != "" {
			t.Errorf("Accept %s: %d %q", accept, code, body)
		}
	}
}

// TestAggregateResponseTypes checks the same choice on the aggregate endpoint: a plain call is
// answered with JSON, a call with a progress token with an event stream of its progress and then
// its result.
func TestAggregateResponseTypes(t *testing.T) {
	r := aggregateGate(t)
	const both = "application/json, text/event-stream"
	echo := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"alpha__echo","arguments":{"text":"x"}}}`
	code, mediaType, body := r.rawPost(t, "/mcp", "2025-11-25", both, echo)
	if code != http.StatusOK || mediaType != "application/json" || !strings.Contains(body, `"id":3`) {
		t.Errorf("plain aggregate call: %d %s %q", code, mediaType, body)
	}
	progress := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"alpha__progress",` +
		`"arguments":{"steps":3,"ms":10},"_meta":{"progressToken":"tok-a"}}}`
	code, mediaType, body = r.rawPost(t, "/mcp", "2025-11-25", both, progress)
	if code != http.StatusOK || mediaType != "text/event-stream" {
		t.Fatalf("aggregate call with a progress token: %d %s %q", code, mediaType, body)
	}
	data := eventData(body)
	if len(data) < 2 || !strings.Contains(data[0], `"notifications/progress"`) || !strings.Contains(data[0], `"tok-a"`) ||
		!strings.Contains(data[len(data)-1], `"id":4`) {
		t.Errorf("aggregate events: %q", body)
	}
	if l := r.lastCall("tool", "echo"); l["server"] != "alpha" || l["outcome"] != "ok" {
		t.Errorf("audit line: %v", l)
	}
}

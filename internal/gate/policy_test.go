package gate_test

import (
	"bytes"
	"io"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/downstream"
	"github.com/vsem-azamat/mcp-gate/internal/proxy"
	"github.com/vsem-azamat/mcp-gate/internal/redact"
	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	var names []string
	for tool, err := range cs.Tools(t.Context(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	return names
}

// firstText returns the text of a prompt result's first message.
func firstText(pr *mcp.GetPromptResult) (string, bool) {
	if pr == nil || len(pr.Messages) == 0 {
		return "", false
	}
	tc, ok := pr.Messages[0].Content.(*mcp.TextContent)
	if !ok {
		return "", false
	}
	return tc.Text, true
}

// A server that lists resources but answers resources/templates/list with "method not found"
// keeps its resources.
func TestResourcesWithoutTemplates(t *testing.T) {
	r := startGate(t, configDoc("", map[string]string{
		"notpl": stdioServer(t, testkit.Fake{Catalog: true, NoTemplates: true}, ""),
	}), gateOpts{})
	r.waitReady(t, "notpl")
	cs := r.connect(t, "notpl", clientOpts{})
	res, err := cs.ListResources(t.Context(), nil)
	if err != nil || len(res.Resources) == 0 {
		t.Fatalf("resources %v %v", res, err)
	}
	tpl, err := cs.ListResourceTemplates(t.Context(), nil)
	if err != nil || len(tpl.ResourceTemplates) != 0 {
		t.Errorf("templates %v %v", tpl, err)
	}
	for _, l := range r.logs.lines("listing the catalog failed; keeping the last one") {
		t.Errorf("listing failed: %v", l)
	}
}

func TestFilters(t *testing.T) {
	f := testkit.Fake{Catalog: true}
	r := startGate(t, configDoc("", map[string]string{
		"allow":    stdioServer(t, f, "tools: {allow: [echo, sleep]}\nprompts: {allow: []}\nresources: {allow: [fake://info, items]}\n"),
		"deny":     stdioServer(t, f, "tools: {deny: [env, pids]}\nresources: {deny: [fake://hidden]}\n"),
		"emptyall": stdioServer(t, f, "tools: {allow: []}\nresources: {allow: []}\n"),
	}), gateOpts{})
	for _, s := range []string{"allow", "deny", "emptyall"} {
		r.waitReady(t, s)
	}

	cs := r.connect(t, "allow", clientOpts{})
	if got := toolNames(t, cs); !slices.Equal(got, []string{"echo", "sleep"}) {
		t.Errorf("allow: tools %v", got)
	}
	if _, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "env"}); err == nil {
		t.Error("allow: a filtered tool was called")
	}
	denied := false
	for _, l := range r.logs.lines("call") {
		denied = denied || l["server"] == "allow" && l["tool"] == "env" && l["outcome"] == "denied" && l["principal"] == "laptop"
	}
	if !denied {
		t.Error("allow: no audit line for the filtered tool")
	}
	caps := cs.InitializeResult().Capabilities
	if caps.Prompts != nil || caps.Resources == nil || caps.Logging != nil || //nolint:staticcheck // the mirror must not advertise logging
		caps.Resources.Subscribe {
		t.Errorf("allow: capabilities %+v", caps)
	}
	res, err := cs.ListResources(t.Context(), nil)
	if err != nil || len(res.Resources) != 1 || res.Resources[0].URI != "fake://info" {
		t.Errorf("allow: resources %v %v", res, err)
	}
	if _, err := cs.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "fake://items/7"}); err != nil {
		t.Errorf("allow: read through the allowed template: %v", err)
	}
	if _, err := cs.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "fake://hidden"}); err == nil {
		t.Error("allow: read a resource that is not allowed")
	}

	cs = r.connect(t, "deny", clientOpts{})
	got := toolNames(t, cs)
	if slices.Contains(got, "env") || slices.Contains(got, "pids") || !slices.Contains(got, "echo") {
		t.Errorf("deny: tools %v", got)
	}
	pr, err := cs.GetPrompt(t.Context(), &mcp.GetPromptParams{Name: "greet", Arguments: map[string]string{"who": "you"}})
	if tc, ok := firstText(pr); err != nil || !ok || tc != "hello you" {
		t.Errorf("deny: prompt %v %v", pr, err)
	}
	// fake://hidden is not listed, and a read of it through the fake://{+path} template, in any
	// spelling, is refused too.
	for _, uri := range []string{"fake://hidden", "FAKE://hidden", "fake://%68idden", "fake://hidden#x", "fake://hidden/", "fake://hidden?", "fake:///hidden", "fake://hidden%20", "fake://x/../hidden", "fake://user@hidden", "fake://hidden:80", "fake://hidden."} {
		if _, err := cs.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: uri}); err == nil {
			t.Errorf("deny: read %s", uri)
		}
	}
	rr, err := cs.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "fake://other"})
	if err != nil || rr.Contents[0].Text != "contents of fake://other" {
		t.Errorf("deny: read through the template: %v %v", rr, err)
	}

	cs = r.connect(t, "emptyall", clientOpts{})
	if got := toolNames(t, cs); len(got) < 10 {
		t.Errorf("an empty tool allow list filters nothing; got %v", got)
	}
	if caps := cs.InitializeResult().Capabilities; caps.Resources != nil || caps.Prompts == nil {
		t.Errorf("emptyall: capabilities %+v", caps)
	}
}

// recorder is a replacer standing in for an escrow: it keeps what it replaced.
type recorder struct{ kept chan string }

func (r recorder) Replace(f redact.Finding) string {
	r.kept <- f.Value
	return "[KEPT:" + f.Kind + "]"
}

func TestRedaction(t *testing.T) {
	const secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	rec := recorder{kept: make(chan string, 16)}
	r := startGate(t, configDoc("", map[string]string{
		"on":   stdioServer(t, testkit.Fake{}, ""),
		"kept": stdioServer(t, testkit.Fake{}, ""),
		"off":  stdioServer(t, testkit.Fake{}, "redact: {enabled: false}\n"),
	}), gateOpts{replacer: func(server string, _ proxy.Request) redact.Replacer {
		if server == "kept" {
			return rec
		}
		return nil
	}})
	for _, s := range []string{"on", "kept", "off"} {
		r.waitReady(t, s)
	}
	echo := func(server string) string {
		cs := r.connect(t, server, clientOpts{})
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "token " + secret}})
		if err != nil {
			t.Fatal(err)
		}
		return textOf(t, res)
	}
	if got := echo("on"); strings.Contains(got, secret) || !strings.Contains(got, "[REDACTED:") {
		t.Errorf("on: %q", got)
	}
	if got := echo("kept"); !strings.Contains(got, "[KEPT:") {
		t.Errorf("kept: %q", got)
	}
	if v := <-rec.kept; v != secret {
		t.Errorf("the replacer got %q", v)
	}
	if got := echo("off"); !strings.Contains(got, secret) {
		t.Errorf("off: %q", got)
	}
	cs := r.connect(t, "on", clientOpts{})
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "badblob"})
	if err == nil || !strings.Contains(err.Error(), "withheld") {
		t.Errorf("a result that cannot be redacted: %v %v", res, err)
	}
	if strings.Contains(r.logs.String(), secret) {
		t.Error("the secret reached the log")
	}
	audit := map[string]any{}
	for _, l := range r.logs.lines("call") {
		if l["server"] == "on" && l["tool"] == "echo" {
			audit = l
		}
	}
	if audit["redactions"] != float64(1) || audit["outcome"] != "ok" || audit["principal"] != "laptop" {
		t.Errorf("audit line %v", audit)
	}
	for _, l := range r.logs.lines("call") {
		if l["tool"] == "badblob" && l["outcome"] != "withheld" {
			t.Errorf("badblob audit %v", l)
		}
	}
}

func TestStaleCatalog(t *testing.T) {
	r := startGate(t, configDoc("", map[string]string{"s": stdioServer(t, testkit.Fake{}, "")}),
		gateOpts{tune: func(o *downstream.Options) { o.InitialBackoff = 2 * time.Second }})
	r.waitReady(t, "s")
	cs := r.connect(t, "s", clientOpts{})
	want := toolNames(t, cs)
	_, _ = cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "crash"})
	waitFor(t, "backoff", func() bool { return r.g.Status().Servers["s"].State == "backoff" })
	if got := toolNames(t, cs); !slices.Equal(got, want) {
		t.Errorf("the catalog changed while the server was down: %v", got)
	}
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "x"}})
	if err != nil || !res.IsError || !strings.Contains(textOf(t, res), "not available (backoff)") {
		t.Errorf("call while down: %v %v", res, err)
	}
	waitFor(t, "restart", func() bool { return r.g.Status().Servers["s"].State == "ready" })
	res, err = cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "x"}})
	if err != nil || res.IsError {
		t.Errorf("call after restart: %v %v", res, err)
	}
}

// TestSlowReader checks that a client that stops reading its stream holds up only its own call.
func TestSlowReader(t *testing.T) {
	r := startGate(t, configDoc("", map[string]string{"s": stdioServer(t, testkit.Fake{}, "")}), gateOpts{})
	r.waitReady(t, "s")
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"progress",` +
		`"arguments":{"steps":2000,"ms":0,"size":32768},"_meta":{"progressToken":"slow"}}}`
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, r.base+"/s/mcp", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+laptopToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	// Read nothing more, so the gate's writes to this stream block.
	time.Sleep(500 * time.Millisecond)

	var got atomic.Int32
	cs := r.connect(t, "s", clientOpts{version: "2026-07-28", progress: func(*mcp.ProgressNotificationClientRequest) { got.Add(1) }})
	// The SDK hands a downstream session's notifications to the gate one at a time, behind the
	// slow call's backlog, while results come at once: a short call can end before its progress
	// reaches the gate, which then drops it. Calls are repeated until one gets its progress;
	// each must be quick, and the slow stream stays blocked throughout.
	for deadline := time.Now().Add(30 * time.Second); got.Load() == 0; {
		if time.Now().After(deadline) {
			t.Fatal("no call next to the slow reader got its progress")
		}
		params := &mcp.CallToolParams{Name: "progress", Arguments: map[string]any{"steps": 3, "ms": 20}}
		params.SetProgressToken("fast")
		start := time.Now()
		if _, err := cs.CallTool(t.Context(), params); err != nil {
			t.Fatal(err)
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Fatalf("a call next to the slow reader took %s", d)
		}
		// the client runs notification handlers apart from the call, so the result can come first
		for wait := time.Now().Add(time.Second); got.Load() == 0 && time.Now().Before(wait); {
			time.Sleep(10 * time.Millisecond)
		}
	}
	_, _ = io.CopyN(io.Discard, res.Body, 1)
}

// A server's filters refuse a read the server could answer through a template they hide, and,
// under an allow list, another spelling of a listed resource they hide.
func TestFilteredReadsThroughTemplates(t *testing.T) {
	f := testkit.Fake{Catalog: true}
	r := startGate(t, configDoc("", map[string]string{
		"deny":  stdioServer(t, f, "resources: {deny: [items]}\n"),
		"allow": stdioServer(t, f, "resources: {allow: [any, fake://info]}\n"),
	}), gateOpts{})
	r.waitReady(t, "deny")
	r.waitReady(t, "allow")
	read := func(server, uri string) error {
		_, err := r.connect(t, server, clientOpts{}).ReadResource(t.Context(), &mcp.ReadResourceParams{URI: uri})
		return err
	}
	for _, c := range []struct {
		server, uri string
		ok          bool
	}{
		{"deny", "fake://items/7", false},
		{"deny", "fake://other", true},
		{"allow", "fake://other", true},
		{"allow", "fake://info", true},
		{"allow", "fake://hidden", false},
		{"allow", "FAKE://%68idden", false},
		{"allow", "fake://hidden?a=b", false},
		{"allow", "fake://hid%E2%80%8Bden", false},
		{"allow", "fake://hidden%EF%BB%BF", false},
		{"allow", "fake://caf%C3%A9", true},
	} {
		if err := read(c.server, c.uri); (err == nil) != c.ok {
			t.Errorf("%s reads %s: %v", c.server, c.uri, err)
		}
	}
}

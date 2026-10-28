package gate_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/approval"
	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

// webhookSink is an approval webhook that hands on every notice it gets.
type webhookSink struct {
	srv     *httptest.Server
	notices chan approval.Notice
}

func newWebhookSink(t *testing.T) *webhookSink {
	t.Helper()
	w := &webhookSink{notices: make(chan approval.Notice, 8)}
	w.srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get(approval.SignatureHeader) != approval.Sign([]byte(webhookSecret), body) {
			t.Errorf("bad signature")
		}
		var n approval.Notice
		if err := json.Unmarshal(body, &n); err != nil {
			t.Errorf("notice: %v", err)
		}
		w.notices <- n
		rw.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(w.srv.Close)
	return w
}

func (w *webhookSink) next(t *testing.T) approval.Notice {
	t.Helper()
	select {
	case n := <-w.notices:
		return n
	case <-time.After(10 * time.Second):
		t.Fatal("no notice")
		return approval.Notice{}
	}
}

const webhookSecret = "webhook-secret-0123456789"

// approvalDoc is a config whose server s holds echo for every token, with a webhook at url and
// the admin token owner; phone's policy hides env and holds sleep.
func approvalDoc(t *testing.T, url string) string {
	t.Helper()
	return `version: 1
auth:
  tokens: {laptop: "${LAPTOP}", phone: "${PHONE}"}
admin:
  tokens: {owner: "${ADMIN}"}
approvals:
  timeout: 1m
  webhook: {url: "` + url + `", secret: "` + webhookSecret + `", linkURL: "https://gate.example.com/"}
policies:
  phone:
    servers:
      s: {tools: {deny: [env]}, approve: [sleep]}
servers:
  s:
` + stdioServer(t, testkit.Fake{}, "approve: [echo, env]\n")
}

type callResult struct {
	res *mcp.CallToolResult
	err error
}

func callBackground(cs *mcp.ClientSession, name string, args map[string]any, meta mcp.Meta) <-chan callResult {
	out := make(chan callResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args, Meta: meta})
		out <- callResult{res, err}
	}()
	return out
}

// link posts a link token to a link endpoint.
func (r *running) link(t *testing.T, path, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, r.base+path, strings.NewReader(`{"token":"`+token+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(body)
}

// decide posts to an approval endpoint with an optional Authorization header.
func (r *running) decide(t *testing.T, path, header string) (int, string) {
	t.Helper()
	code, _, body := r.get(t, http.MethodPost, path, header)
	return code, body
}

func TestApprovals(t *testing.T) {
	hook := newWebhookSink(t)
	r := startGate(t, approvalDoc(t, hook.srv.URL), gateOpts{})
	r.waitReady(t, "s")
	cs := r.connect(t, "s", clientOpts{})
	const admin = "Bearer " + adminToken

	// Approved with the admin endpoint.
	got := callBackground(cs, "echo", map[string]any{"text": "password: hunter2hunter2"}, nil)
	n := hook.next(t)
	if n.Server != "s" || n.Tool != "echo" || n.Principal != "laptop" || !strings.Contains(n.Arguments, "[REDACTED:password]") ||
		strings.Contains(n.Arguments, "hunter2") || !strings.HasPrefix(n.ApproveURL, "https://gate.example.com"+approval.LinkRoute) {
		t.Errorf("notice %+v", n)
	}
	if code, _ := r.decide(t, "/_approvals/"+n.ID+"/approve", ""); code != http.StatusUnauthorized {
		t.Errorf("approve without a token: %d", code)
	}
	code, _, body := r.get(t, http.MethodGet, "/_approvals", admin)
	if code != http.StatusOK || !strings.Contains(body, `"id": "`+n.ID+`"`) && !strings.Contains(body, `"id":"`+n.ID+`"`) || strings.Contains(body, "hunter2") {
		t.Errorf("list: %d %s", code, body)
	}
	if code, body := r.decide(t, "/_approvals/"+n.ID+"/approve", admin); code != http.StatusOK || !strings.Contains(body, `"approval":"approved"`) {
		t.Errorf("approve: %d %s", code, body)
	}
	if c := <-got; c.err != nil || c.res.IsError || textOf(t, c.res) != "password: [REDACTED:password]" {
		t.Errorf("approved call: %+v", c)
	}
	if l := r.lastCall("tool", "echo"); l["outcome"] != "ok" || l["approval"] != "approved" || l["approver"] != "owner" {
		t.Errorf("audit line %v", l)
	}

	// Denied through a link, which decides once; fetching it decides nothing.
	got = callBackground(cs, "echo", map[string]any{"text": "x"}, nil)
	n = hook.next(t)
	approve := strings.TrimPrefix(n.ApproveURL, "https://gate.example.com")
	deny := strings.TrimPrefix(n.DenyURL, "https://gate.example.com")
	if code, _, _ := r.get(t, http.MethodGet, deny, ""); code != http.StatusMethodNotAllowed {
		t.Errorf("GET of a link: %d", code)
	}
	if code, body := r.link(t, deny, n.LinkToken); code != http.StatusOK || !strings.Contains(body, `"approval":"denied"`) {
		t.Errorf("deny link: %d %s", code, body)
	}
	if code, _ := r.link(t, approve, n.LinkToken); code != http.StatusNotFound {
		t.Errorf("a used link: %d", code)
	}
	if c := <-got; c.err != nil || !c.res.IsError || textOf(t, c.res) != "mcp-gate: the owner did not approve this call of echo" {
		t.Errorf("denied call: %+v", c)
	}
	if l := r.lastCall("tool", "echo"); l["outcome"] != "not_approved" || l["approval"] != "denied" || l["approver"] != "link" {
		t.Errorf("audit line %v", l)
	}

	// A tool phone's policy hides is unknown to it, and nothing is held.
	phone := r.connect(t, "s", clientOpts{header: "Bearer " + phoneToken})
	if _, err := phone.CallTool(t.Context(), &mcp.CallToolParams{Name: "env"}); err == nil || !strings.Contains(err.Error(), "unknown tool") {
		t.Errorf("hidden tool: %v", err)
	}
	if _, _, body := r.get(t, http.MethodGet, "/_approvals", admin); strings.TrimSpace(body) != `{"pending":[]}` {
		t.Errorf("pending after a hidden call: %s", body)
	}
	if l := r.lastCall("tool", "env"); l["outcome"] != "denied" || l["approval"] != nil {
		t.Errorf("hidden audit line %v", l)
	}
	// phone's own list holds sleep for it only.
	got = callBackground(phone, "sleep", map[string]any{"ms": 1}, nil)
	n = hook.next(t)
	if n.Tool != "sleep" || n.Principal != "phone" {
		t.Errorf("phone's notice %+v", n)
	}
	r.decide(t, "/_approvals/"+n.ID+"/approve", admin)
	<-got
	if res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "sleep", Arguments: map[string]any{"ms": 1}}); err != nil || res.IsError {
		t.Errorf("laptop's sleep: %v %v", res, err)
	}
}

func TestApprovalProgressAndReload(t *testing.T) {
	old := approval.ProgressInterval
	approval.ProgressInterval = 50 * time.Millisecond
	t.Cleanup(func() { approval.ProgressInterval = old })
	hook := newWebhookSink(t)
	doc := approvalDoc(t, hook.srv.URL)
	r := startGate(t, doc, gateOpts{})
	r.waitReady(t, "s")
	var mu sync.Mutex
	var progress []*mcp.ProgressNotificationParams
	cs := r.connect(t, "s", clientOpts{progress: func(req *mcp.ProgressNotificationClientRequest) {
		mu.Lock()
		defer mu.Unlock()
		progress = append(progress, req.Params)
	}})
	got := callBackground(cs, "echo", map[string]any{"text": "x"}, mcp.Meta{"progressToken": "p1"})
	n := hook.next(t)
	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		k := len(progress)
		mu.Unlock()
		if k >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no progress while waiting")
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	for i, p := range progress[:2] {
		if p.ProgressToken != "p1" || p.Progress != float64(i+1) || p.Message != "waiting for the owner's approval ("+n.ID+")" {
			t.Errorf("progress %d: %+v", i, p)
		}
	}
	mu.Unlock()

	// A reload denies what waits.
	r.reload(t, doc)
	if c := <-got; c.err != nil || !c.res.IsError || textOf(t, c.res) != "mcp-gate: the owner did not approve this call of echo" {
		t.Errorf("after the reload: %+v", c)
	}
	if l := r.lastCall("tool", "echo"); l["approval"] != "denied" || l["approver"] != "gate" {
		t.Errorf("audit line %v", l)
	}
	if code, _ := r.decide(t, "/_approvals/"+n.ID+"/approve", "Bearer "+adminToken); code != http.StatusNotFound {
		t.Errorf("approve after the reload: %d", code)
	}
}

// TestAdminGuessingLimited checks that wrong admin tokens are limited per client on
// /_approvals and /_status, and that without linkURL the link endpoints are 404.
func TestAdminGuessingLimited(t *testing.T) {
	r := startGate(t, configDoc("admin:\n  tokens: {owner: \"${ADMIN}\"}\n", map[string]string{
		"s": stdioServer(t, testkit.Fake{}, "approve: [echo]\n"),
	}), gateOpts{})
	if code, _ := r.link(t, approval.LinkRoute+"approve", "x"); code != http.StatusNotFound {
		t.Errorf("link without linkURL: %d", code)
	}
	limited := false
	for range 30 {
		code, _, _ := r.get(t, http.MethodGet, "/_approvals", "Bearer wrong-guess-0123456789")
		if code == http.StatusTooManyRequests {
			limited = true
			break
		}
		if code != http.StatusUnauthorized {
			t.Fatalf("wrong token: %d", code)
		}
	}
	if !limited {
		t.Fatal("wrong admin tokens are not limited")
	}
	// The client is limited on every admin endpoint, the right token included, until its
	// bucket refills; a request without a token is not counted.
	if code, h, _ := r.get(t, http.MethodGet, "/_status", "Bearer "+adminToken); code != http.StatusTooManyRequests || h.Get("Retry-After") == "" {
		t.Errorf("status while limited: %d", code)
	}
	if code, _, _ := r.get(t, http.MethodGet, "/_approvals", ""); code != http.StatusUnauthorized {
		t.Errorf("no token while limited: %d", code)
	}
}

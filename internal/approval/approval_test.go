package approval

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vsem-azamat/mcp-gate/internal/audit"
	"github.com/vsem-azamat/mcp-gate/internal/config"
)

func TestPatterns(t *testing.T) {
	p := Patterns{"send_message", "delete_*"}
	for tool, want := range map[string]bool{"send_message": true, "delete_item": true, "delete_": true, "send": false, "xdelete_a": false, "send_message2": false} {
		if p.Match(tool) != want {
			t.Errorf("Match(%q) = %v", tool, !want)
		}
	}
	if !(Patterns{"*"}).Match("anything") || (Patterns{}).Match("x") {
		t.Error("* or the empty list")
	}
}

func TestRules(t *testing.T) {
	cfg := &config.Config{
		Servers: map[string]*config.Server{"a": {Approve: []string{"send_*"}}, "b": {}},
		Policies: map[string]*config.TokenPolicy{
			"phone": {Servers: map[string]*config.ServerPolicy{"a": {Approve: []string{"echo"}}}},
		},
	}
	r := NewRules(cfg, "a")
	switch {
	case !r.Holds("laptop", "send_x"), !r.Holds("", "send_x"):
		t.Error("the server's pattern holds for every caller")
	case !r.Holds("phone", "echo"), r.Holds("laptop", "echo"), r.Holds("", "echo"):
		t.Error("the token's pattern holds for that token only")
	case r.Holds("phone", "env"):
		t.Error("an unlisted tool")
	}
	if NewRules(cfg, "b") != nil || (*Rules)(nil).Holds("phone", "x") {
		t.Error("a server without rules")
	}
}

// fastTicks shortens the progress interval for the test.
func fastTicks(t *testing.T, d time.Duration) {
	old := ProgressInterval
	ProgressInterval = d
	t.Cleanup(func() { ProgressInterval = old })
}

// waitPending waits until the store lists n pending approvals and returns them.
func waitPending(t *testing.T, st *Store, n int) []Pending {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if l := st.List(); len(l) == n {
			return l
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending: %v, want %d", st.List(), n)
		}
		time.Sleep(time.Millisecond)
	}
}

var question = Question{Server: "s", Tool: "send", Principal: "phone", Arguments: `{"a":1}`}

func ask(st *Store, s Settings) <-chan Decision {
	out := make(chan Decision, 1)
	go func() { out <- st.Ask(context.Background(), question, s, nil) }()
	return out
}

func TestDecide(t *testing.T) {
	st := NewStore(nil)
	got := ask(st, Settings{Timeout: time.Minute})
	p := waitPending(t, st, 1)[0]
	if len(p.ID) != 16 || p.Server != "s" || p.Tool != "send" || p.Principal != "phone" || p.Arguments != `{"a":1}` ||
		p.Expires.Sub(p.Created) != time.Minute {
		t.Errorf("pending %+v", p)
	}
	if a, ok := st.Decide(p.ID, true, "owner"); !ok || a != audit.Approved {
		t.Fatalf("decide: %v %v", a, ok)
	}
	if d := <-got; d != (Decision{Approval: audit.Approved, By: "owner"}) {
		t.Errorf("decision %+v", d)
	}
	if _, ok := st.Decide(p.ID, false, "owner"); ok || len(st.List()) != 0 {
		t.Error("decided twice")
	}

	got = ask(st, Settings{Timeout: time.Minute})
	p = waitPending(t, st, 1)[0]
	st.Decide(p.ID, false, "owner")
	if d := <-got; d != (Decision{Approval: audit.ApprovalDenied, By: "owner"}) {
		t.Errorf("denied: %+v", d)
	}
}

func TestExpireAndCancel(t *testing.T) {
	st := NewStore(nil)
	if d := st.Ask(context.Background(), question, Settings{Timeout: 20 * time.Millisecond}, nil); d.Approval != audit.ApprovalExpired || d.By != "" {
		t.Errorf("expired: %+v", d)
	}
	if len(st.List()) != 0 {
		t.Error("an expired approval is still pending")
	}
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan Decision, 1)
	go func() { out <- st.Ask(ctx, question, Settings{Timeout: time.Minute}, nil) }()
	waitPending(t, st, 1)
	cancel()
	if d := <-out; d.Approval != audit.ApprovalCancelled {
		t.Errorf("cancelled: %+v", d)
	}
	if len(st.List()) != 0 {
		t.Error("a cancelled approval is still pending")
	}
}

func TestDenyAllAndClose(t *testing.T) {
	st := NewStore(nil)
	a, b := ask(st, Settings{Timeout: time.Minute}), ask(st, Settings{Timeout: time.Minute})
	waitPending(t, st, 2)
	st.DenyAll()
	for _, c := range []<-chan Decision{a, b} {
		if d := <-c; d != (Decision{Approval: audit.ApprovalDenied, By: ByGate}) {
			t.Errorf("after DenyAll: %+v", d)
		}
	}
	c := ask(st, Settings{Timeout: time.Minute})
	waitPending(t, st, 1)
	st.Close()
	if d := <-c; d.By != ByGate {
		t.Errorf("after Close: %+v", d)
	}
	if d := st.Ask(context.Background(), question, Settings{Timeout: time.Minute}, nil); d != (Decision{Approval: audit.ApprovalDenied, By: ByGate}) {
		t.Errorf("held after Close: %+v", d)
	}
}

func TestMaxPending(t *testing.T) {
	st := NewStore(nil)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for range MaxPending {
		wg.Go(func() { st.Ask(ctx, question, Settings{Timeout: time.Minute}, nil) })
	}
	waitPending(t, st, MaxPending)
	if d := st.Ask(context.Background(), question, Settings{Timeout: time.Minute}, nil); d != (Decision{Approval: audit.ApprovalDenied, By: ByGate}) {
		t.Errorf("one too many: %+v", d)
	}
	cancel()
	wg.Wait()
}

func TestProgressWhileWaiting(t *testing.T) {
	fastTicks(t, 10*time.Millisecond)
	st := NewStore(nil)
	ticks := make(chan int, 10)
	var id string
	var mu sync.Mutex
	out := make(chan Decision, 1)
	go func() {
		out <- st.Ask(context.Background(), question, Settings{Timeout: time.Minute}, func(i string, n int) {
			mu.Lock()
			id = i
			mu.Unlock()
			ticks <- n
		})
	}()
	if a, b := <-ticks, <-ticks; a != 1 || b != 2 {
		t.Errorf("ticks %d %d", a, b)
	}
	p := waitPending(t, st, 1)[0]
	mu.Lock()
	if id != p.ID {
		t.Errorf("tick id %q, pending %q", id, p.ID)
	}
	mu.Unlock()
	st.Decide(p.ID, true, "owner")
	<-out
}

// recorder is a notifier that keeps what it is told.
type recorder chan Notice

func (r recorder) Notify(n Notice) { r <- n }

func TestLinks(t *testing.T) {
	st := NewStore(nil)
	rec := make(recorder, 1)
	got := ask(st, Settings{Timeout: time.Minute, Notifier: rec, LinkURL: "https://gate.example.com/base/"})
	n := <-rec
	const prefix = "https://gate.example.com/base" + LinkRoute
	if !strings.HasPrefix(n.ApproveURL, prefix) || !strings.HasSuffix(n.ApproveURL, "/approve") ||
		strings.TrimSuffix(n.ApproveURL, "/approve") != strings.TrimSuffix(n.DenyURL, "/deny") {
		t.Fatalf("links %q %q", n.ApproveURL, n.DenyURL)
	}
	token := strings.TrimSuffix(strings.TrimPrefix(n.ApproveURL, prefix), "/approve")
	if len(token) != 43 {
		t.Errorf("token of %d characters", len(token))
	}
	h := st.LinkHandler()
	path := LinkRoute + token
	if rr := serve(h, http.MethodGet, path+"/approve", ""); rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", rr.Code)
	}
	rr := serve(h, http.MethodPost, path+"/approve", "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"approval":"approved"`) || rr.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("approve: %d %s", rr.Code, rr.Body)
	}
	if d := <-got; d != (Decision{Approval: audit.Approved, By: ByLink}) {
		t.Errorf("decision %+v", d)
	}
	if rr := serve(h, http.MethodPost, path+"/deny", ""); rr.Code != http.StatusNotFound {
		t.Errorf("a second use: %d", rr.Code)
	}
	if rr := serve(h, http.MethodPost, LinkRoute+"nope/deny", ""); rr.Code != http.StatusNotFound {
		t.Errorf("unknown token: %d", rr.Code)
	}

	// Without links the notice carries none.
	got = ask(st, Settings{Timeout: time.Minute, Notifier: rec})
	if n := <-rec; n.ApproveURL != "" || n.DenyURL != "" {
		t.Errorf("links without linkURL: %+v", n)
	}
	st.DenyAll()
	<-got
}

func serve(h http.Handler, method, path, auth string) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(context.Background(), method, path, nil)
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	return rr
}

func TestAdminHandler(t *testing.T) {
	st := NewStore(nil)
	rejected := 0
	h := st.AdminHandler(func(header string) (string, bool) { return "owner", header == "Bearer good" }, func() { rejected++ })
	got := ask(st, Settings{Timeout: time.Minute})
	p := waitPending(t, st, 1)[0]
	for _, c := range []struct{ method, path string }{{http.MethodGet, Route}, {http.MethodPost, Route + "/" + p.ID + "/approve"}} {
		if rr := serve(h, c.method, c.path, "Bearer bad"); rr.Code != http.StatusUnauthorized || rr.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s %s without the token: %d", c.method, c.path, rr.Code)
		}
	}
	if rejected != 2 || len(st.List()) != 1 {
		t.Errorf("rejected %d, pending %d", rejected, len(st.List()))
	}
	rr := serve(h, http.MethodGet, Route, "Bearer good")
	var list struct{ Pending []Pending }
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &list) != nil || len(list.Pending) != 1 || list.Pending[0].ID != p.ID {
		t.Errorf("list: %d %s", rr.Code, rr.Body)
	}
	if rr := serve(h, http.MethodPost, Route+"/nope/approve", "Bearer good"); rr.Code != http.StatusNotFound {
		t.Errorf("unknown id: %d", rr.Code)
	}
	rr = serve(h, http.MethodPost, Route+"/"+p.ID+"/deny", "Bearer good")
	if rr.Code != http.StatusOK || strings.TrimSpace(rr.Body.String()) != `{"id":"`+p.ID+`","approval":"denied"}` {
		t.Errorf("deny: %d %s", rr.Code, rr.Body)
	}
	if d := <-got; d != (Decision{Approval: audit.ApprovalDenied, By: "owner"}) {
		t.Errorf("decision %+v", d)
	}
	if rr := serve(h, http.MethodGet, Route, "Bearer good"); strings.TrimSpace(rr.Body.String()) != `{"pending":[]}` {
		t.Errorf("empty list: %s", rr.Body)
	}
}

func TestWebhook(t *testing.T) {
	type seen struct {
		body             []byte
		signature, ctype string
	}
	hits := make(chan seen, 2)
	status := http.StatusNoContent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		hits <- seen{body, r.Header.Get(SignatureHeader), r.Header.Get("Content-Type")}
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	var logs strings.Builder
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	n := Notice{Pending: Pending{ID: "0123456789abcdef", Server: "s", Tool: "send"}, ApproveURL: "https://gate.example.com/a"}
	const secret = "0123456789abcdef-secret"
	NewWebhook(srv.URL+"/hook", secret, logger).Notify(n)
	h := <-hits
	var back Notice
	if err := json.Unmarshal(h.body, &back); err != nil || back != n || h.ctype != "application/json" {
		t.Errorf("body %s, type %q", h.body, h.ctype)
	}
	if h.signature != Sign([]byte(secret), h.body) || !strings.HasPrefix(h.signature, "sha256=") {
		t.Errorf("signature %q", h.signature)
	}
	if logs.Len() != 0 {
		t.Errorf("logged: %s", logs.String())
	}
	NewWebhook(srv.URL+"/redirect", "", logger).Notify(n)
	if h := <-hits; h.signature != "" {
		t.Error("signed without a secret")
	}
	if len(hits) != 0 || !strings.Contains(logs.String(), "answered 302") {
		t.Errorf("redirect followed or not logged: %s", logs.String())
	}
	logs.Reset()
	status = http.StatusInternalServerError
	NewWebhook(srv.URL+"/secret-path-token", "", logger).Notify(n)
	<-hits
	if !strings.Contains(logs.String(), "answered 500") || strings.Contains(logs.String(), "secret-path-token") {
		t.Errorf("failure log: %s", logs.String())
	}
	logs.Reset()
	// A link-local address is refused; the log does not quote the URL.
	NewWebhook("http://169.254.169.254/latest/secret-path-token", "", logger).Notify(n)
	if !strings.Contains(logs.String(), "link-local or metadata") || strings.Contains(logs.String(), "secret-path-token") {
		t.Errorf("metadata log: %s", logs.String())
	}
}

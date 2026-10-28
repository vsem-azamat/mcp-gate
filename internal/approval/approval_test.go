package approval

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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
	for i := range MaxPending {
		q := question
		q.Principal = fmt.Sprintf("token-%d", i%(MaxPending/MaxPendingPerPrincipal))
		wg.Go(func() { st.Ask(ctx, q, Settings{Timeout: time.Minute}, nil) })
	}
	waitPending(t, st, MaxPending)
	q := question
	q.Principal = "fresh"
	if d := st.Ask(context.Background(), q, Settings{Timeout: time.Minute}, nil); d != (Decision{Approval: audit.ApprovalDenied, By: ByGate}) {
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

func (r recorder) Notify(_ context.Context, n Notice) { r <- n }

func TestLinks(t *testing.T) {
	st := NewStore(nil)
	rec := make(recorder, 1)
	got := ask(st, Settings{Timeout: time.Minute, Notifier: rec, LinkURL: "https://gate.example.com/base/"})
	n := <-rec
	const prefix = "https://gate.example.com/base" + LinkRoute
	if n.ApproveURL != prefix+"approve" || n.DenyURL != prefix+"deny" || len(n.LinkToken) != 43 {
		t.Fatalf("links %q %q, token of %d characters", n.ApproveURL, n.DenyURL, len(n.LinkToken))
	}
	if strings.Contains(n.ApproveURL, n.LinkToken) {
		t.Error("the token is in the URL")
	}
	h := st.LinkHandler()
	body := `{"token":"` + n.LinkToken + `"}`
	if rr := serveBody(h, http.MethodGet, LinkRoute+"approve", body); rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", rr.Code)
	}
	if rr := serveBody(h, http.MethodPost, LinkRoute+"approve", "token="+n.LinkToken); rr.Code != http.StatusBadRequest {
		t.Errorf("not JSON: %d", rr.Code)
	}
	rr := serveBody(h, http.MethodPost, LinkRoute+"approve", body)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"approval":"approved"`) || rr.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("approve: %d %s", rr.Code, rr.Body)
	}
	if d := <-got; d != (Decision{Approval: audit.Approved, By: ByLink}) {
		t.Errorf("decision %+v", d)
	}
	if rr := serveBody(h, http.MethodPost, LinkRoute+"deny", body); rr.Code != http.StatusNotFound {
		t.Errorf("a second use: %d", rr.Code)
	}
	if rr := serveBody(h, http.MethodPost, LinkRoute+"deny", `{"token":"nope"}`); rr.Code != http.StatusNotFound {
		t.Errorf("unknown token: %d", rr.Code)
	}

	// Without links the notice carries none.
	got = ask(st, Settings{Timeout: time.Minute, Notifier: rec})
	if n := <-rec; n.ApproveURL != "" || n.DenyURL != "" || n.LinkToken != "" {
		t.Errorf("links without linkURL: %+v", n)
	}
	st.DenyAll()
	<-got
}

// TestConcurrentLink checks that a link decides once however many use it at once.
func TestConcurrentLink(t *testing.T) {
	st := NewStore(nil)
	defer st.Close()
	rec := make(recorder, 1)
	got := ask(st, Settings{Timeout: time.Minute, Notifier: rec, LinkURL: "https://gate.example.com"})
	token := (<-rec).LinkToken
	var ok atomic.Int64
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Go(func() {
			if _, _, k := st.DecideLink(token, i%2 == 0); k {
				ok.Add(1)
			}
		})
	}
	wg.Wait()
	<-got
	if ok.Load() != 1 {
		t.Errorf("%d decisions", ok.Load())
	}
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

func serveBody(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	return rr
}

// slowNotifier counts its notices and holds each until ctx ends or release is closed.
type slowNotifier struct {
	n       atomic.Int64
	running atomic.Int64
	most    atomic.Int64
	release chan struct{}
}

func (s *slowNotifier) Notify(ctx context.Context, _ Notice) {
	s.n.Add(1)
	r := s.running.Add(1)
	for m := s.most.Load(); r > m && !s.most.CompareAndSwap(m, r); m = s.most.Load() {
	}
	defer s.running.Add(-1)
	select {
	case <-ctx.Done():
	case <-s.release:
	}
}

// TestNoticesBounded checks that held calls that are cancelled at once cannot pile up notices:
// at most maxNotifiers are sent at a time, those of approvals no longer pending are skipped, a
// full queue drops, and Close ends what is in flight.
func TestNoticesBounded(t *testing.T) {
	st := NewStore(nil)
	sn := &slowNotifier{release: make(chan struct{})}
	for range 500 {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { st.Ask(ctx, question, Settings{Timeout: time.Minute, Notifier: sn}, nil); close(done) }()
		waitPending(t, st, 1)
		cancel()
		<-done
	}
	if most := sn.most.Load(); most > maxNotifiers {
		t.Errorf("%d notices at once", most)
	}
	// What was queued while the senders were busy is skipped once they free up.
	close(sn.release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		st.mu.Lock()
		idle := st.senders == 0
		st.mu.Unlock()
		if idle {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("senders still running")
		}
		time.Sleep(time.Millisecond)
	}
	if sent := sn.n.Load(); sent > maxNotifiers {
		t.Errorf("%d notices sent for calls no longer pending", sent)
	}
	if st.Dropped() == 0 {
		t.Error("a full queue dropped nothing")
	}

	// Close cancels a notice in flight.
	sn2 := &slowNotifier{release: make(chan struct{})}
	got := ask(st, Settings{Timeout: time.Minute, Notifier: sn2})
	for sn2.running.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	st.Close()
	<-got
	for deadline := time.Now().Add(5 * time.Second); sn2.running.Load() != 0; {
		if time.Now().After(deadline) {
			t.Fatal("the notice outlived Close")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPendingPerPrincipal(t *testing.T) {
	st := NewStore(nil)
	defer st.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	agent := Question{Server: "s", Tool: "send", Principal: "agent"}
	for range MaxPendingPerPrincipal {
		go st.Ask(ctx, agent, Settings{Timeout: time.Minute}, nil)
	}
	waitPending(t, st, MaxPendingPerPrincipal)
	if d := st.Ask(context.Background(), agent, Settings{Timeout: time.Minute}, nil); d != (Decision{Approval: audit.ApprovalDenied, By: ByGate}) {
		t.Errorf("one more of agent: %+v", d)
	}
	// Another token still gets through.
	out := make(chan Decision, 1)
	go func() {
		out <- st.Ask(context.Background(), Question{Server: "s", Tool: "send", Principal: "phone"}, Settings{Timeout: time.Minute}, nil)
	}()
	waitPending(t, st, MaxPendingPerPrincipal+1)
	for _, p := range st.List() {
		if p.Principal == "phone" {
			st.Decide(p.ID, true, "owner")
		}
	}
	if d := <-out; d.Approval != audit.Approved {
		t.Errorf("phone: %+v", d)
	}
	// A slot frees once a call ends.
	cancel()
	waitPending(t, st, 0)
}

func TestPrintable(t *testing.T) {
	for in, want := range map[string]string{
		"plain text, ünïcode 😀": "plain text, ünïcode 😀",
		"a\u202eb":              `a\u202Eb`,
		"x\u009b2J":             `x\u009B2J`,
		"\x1b]0;t\x07\n":        `\u001B]0;t\u0007\u000A`,
		"z\U000E0001":           `z\U000E0001`,
	} {
		if got := Printable(in); got != want {
			t.Errorf("Printable(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUnmatched(t *testing.T) {
	cfg := &config.Config{
		Servers: map[string]*config.Server{"a": {Approve: []string{"send", "delete_*", "a__send"}}},
		Policies: map[string]*config.TokenPolicy{
			"phone": {Servers: map[string]*config.ServerPolicy{"a": {Approve: []string{"echo", "send"}}}},
		},
	}
	got := NewRules(cfg, "a").Unmatched(map[string]bool{"send": true, "delete_x": true})
	if !slices.Equal(got, []string{"a__send", "echo"}) {
		t.Errorf("unmatched %v", got)
	}
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
	NewWebhook(srv.URL+"/hook", secret, logger).Notify(context.Background(), n)
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
	NewWebhook(srv.URL+"/redirect", "", logger).Notify(context.Background(), n)
	if h := <-hits; h.signature != "" {
		t.Error("signed without a secret")
	}
	if len(hits) != 0 || !strings.Contains(logs.String(), "answered 302") {
		t.Errorf("redirect followed or not logged: %s", logs.String())
	}
	logs.Reset()
	status = http.StatusInternalServerError
	NewWebhook(srv.URL+"/secret-path-token", "", logger).Notify(context.Background(), n)
	<-hits
	if !strings.Contains(logs.String(), "answered 500") || strings.Contains(logs.String(), "secret-path-token") {
		t.Errorf("failure log: %s", logs.String())
	}
	logs.Reset()
	// A link-local address is refused; the log does not quote the URL.
	NewWebhook("http://169.254.169.254/latest/secret-path-token", "", logger).Notify(context.Background(), n)
	if !strings.Contains(logs.String(), "link-local or metadata") || strings.Contains(logs.String(), "secret-path-token") {
		t.Errorf("metadata log: %s", logs.String())
	}
	// A failure is logged by its class, without the relay's host.
	for _, c := range []struct{ url, class string }{
		{"https://private-relay-name.invalid/bot123:SECRET/send", "error=dns"},
		{"http://127.0.0.1:1/hook", "error=connect"},
	} {
		logs.Reset()
		NewWebhook(c.url, "", logger).Notify(context.Background(), n)
		if out := logs.String(); !strings.Contains(out, c.class) || strings.Contains(out, "private-relay-name") ||
			strings.Contains(out, "SECRET") || strings.Contains(out, "127.0.0.1") {
			t.Errorf("%s: %s", c.url, out)
		}
	}
	tlsSrv := httptest.NewUnstartedServer(http.NotFoundHandler())
	tlsSrv.Config.ErrorLog = slog.NewLogLogger(slog.DiscardHandler, slog.LevelError) // the handshake fails on purpose
	tlsSrv.StartTLS()
	defer tlsSrv.Close()
	logs.Reset()
	NewWebhook(tlsSrv.URL, "", logger).Notify(context.Background(), n)
	if !strings.Contains(logs.String(), "error=tls") {
		t.Errorf("tls: %s", logs.String())
	}
}

package proxy

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/approval"
	"github.com/vsem-azamat/mcp-gate/internal/audit"
	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/policy"
	"github.com/vsem-azamat/mcp-gate/internal/redact"
)

// notices is a notifier that keeps what it is told.
type notices chan approval.Notice

func (n notices) Notify(x approval.Notice) { n <- x }

// approvalMirror returns a mirror of down whose server holds send and delete_*, and whose token
// phone has a policy that hides mail and holds echo.
func approvalMirror(t *testing.T, down *fakeDown, timeout time.Duration) (*Mirror, *recorder, *approval.Store, notices) {
	t.Helper()
	cfg := &config.Config{
		Servers: map[string]*config.Server{"s": {Approve: []string{"send", "delete_*", "mail"}}},
		Policies: map[string]*config.TokenPolicy{"phone": {Servers: map[string]*config.ServerPolicy{
			"s": {Tools: &config.PolicyFilter{Deny: []string{"mail"}}, Approve: []string{"echo"}},
		}}},
	}
	engine, err := redact.New(redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	store := approval.NewStore(nil)
	t.Cleanup(store.Close)
	n := make(notices, 4)
	m, rec := fakeMirror(Options{
		Policy: policy.New(&config.Server{Tools: &config.Filter{Deny: []string{"env"}}}),
		Tokens: policy.NewTokens(cfg, "s"),
		Approval: &Approval{
			Rules: approval.NewRules(cfg, "s"), Store: store, Engine: engine,
			Settings: approval.Settings{Timeout: timeout, Notifier: n},
		},
	}, down)
	return m, rec, store, n
}

var phone = &mcp.RequestExtra{TokenInfo: &auth.TokenInfo{UserID: "phone"}}

type called struct {
	res *mcp.CallToolResult
	err error
}

func callAsync(m *Mirror, name, shown, args string, extra *mcp.RequestExtra) <-chan called {
	out := make(chan called, 1)
	go func() {
		req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: name}, Extra: extra}
		if args != "" {
			req.Params.Arguments = json.RawMessage(args)
		}
		res, err := m.callToolAs(context.Background(), req, shown)
		out <- called{res, err}
	}()
	return out
}

func TestApprovalStage(t *testing.T) {
	down := &fakeDown{tool: textResult("sent")}
	m, rec, store, n := approvalMirror(t, down, time.Minute)

	// Approved: forwarded, with the server's result.
	got := callAsync(m, "send", "s__send", `{"text":"password: hunter2hunter2"}`, phone)
	notice := <-n
	if notice.Server != "s" || notice.Tool != "send" || notice.Principal != "phone" ||
		!strings.Contains(notice.Arguments, "[REDACTED:password]") || strings.Contains(notice.Arguments, "hunter2") {
		t.Errorf("notice %+v", notice)
	}
	if len(down.tools) != 0 {
		t.Fatal("forwarded before the decision")
	}
	store.Decide(notice.ID, true, "owner")
	if c := <-got; c.err != nil || firstText(c.res) != "sent" {
		t.Errorf("approved: %+v", c)
	}

	// Denied: a tool error, nothing forwarded.
	got = callAsync(m, "delete_all", "s__delete_all", "", nil)
	store.Decide((<-n).ID, false, "owner")
	c := <-got
	if c.err != nil || !c.res.IsError || firstText(c.res) != "mcp-gate: the owner did not approve this call of s__delete_all" {
		t.Errorf("denied: %+v %q", c, firstText(c.res))
	}

	// Held for phone only.
	got = callAsync(m, "echo", "echo", "", phone)
	store.Decide((<-n).ID, true, "owner")
	<-got
	if c := <-callAsync(m, "echo", "echo", "", nil); c.err != nil || firstText(c.res) != "sent" {
		t.Errorf("echo without a token: %+v", c)
	}

	// Hidden by the server's filter or the token's policy: unknown, not held.
	for _, h := range []struct {
		name  string
		extra *mcp.RequestExtra
	}{{"env", nil}, {"mail", phone}} {
		c := <-callAsync(m, h.name, h.name, "", h.extra)
		if c.err == nil || c.err.Error() != errUnknownTool(h.name).Error() {
			t.Errorf("%s: %+v", h.name, c)
		}
	}
	if len(n) != 0 || len(store.List()) != 0 {
		t.Error("a hidden tool was held")
	}
	if len(down.tools) != 3 {
		t.Errorf("forwarded %d calls", len(down.tools))
	}
	rec2 := func(principal, name string, o audit.Outcome, a audit.Approval, by string, tp policy.Decision) audit.Record {
		return audit.Record{Server: "s", Principal: principal, Kind: audit.Tool, Name: name, Outcome: o, TokenPolicy: tp, Approval: a, Approver: by}
	}
	want := []audit.Record{
		rec2("phone", "send", audit.OK, audit.Approved, "owner", policy.NoPolicy),
		rec2("", "delete_all", audit.NotApproved, audit.ApprovalDenied, "owner", policy.NoPolicy),
		rec2("phone", "echo", audit.OK, audit.Approved, "owner", policy.NoPolicy),
		rec2("", "echo", audit.OK, "", "", policy.NoPolicy),
		rec2("", "env", audit.Denied, "", "", policy.NoPolicy),
		rec2("phone", "mail", audit.Denied, "", "", policy.NoPolicy),
	}
	if got := rec.all(); !slices.Equal(got, want) {
		t.Errorf("records\n%+v\nwant\n%+v", got, want)
	}
}

func TestApprovalExpiresAndCancels(t *testing.T) {
	down := &fakeDown{tool: textResult("sent")}
	m, rec, store, n := approvalMirror(t, down, 20*time.Millisecond)
	c := <-callAsync(m, "send", "send", "", nil)
	<-n
	if c.err != nil || firstText(c.res) != "mcp-gate: the owner did not answer the approval request for send in time" {
		t.Errorf("expired: %+v", c)
	}
	ctx, cancel := context.WithCancel(context.Background())
	m2, rec2, store2, n2 := approvalMirror(t, down, time.Minute)
	out := make(chan error, 1)
	go func() {
		_, err := m2.callTool(ctx, &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "send"}})
		out <- err
	}()
	<-n2
	cancel()
	if err := <-out; err == nil {
		t.Error("a cancelled call succeeded")
	}
	if len(down.tools) != 0 || len(store.List())+len(store2.List()) != 0 {
		t.Error("forwarded or still pending")
	}
	if r := rec.all(); len(r) != 1 || r[0].Outcome != audit.NotApproved || r[0].Approval != audit.ApprovalExpired || r[0].Approver != "" {
		t.Errorf("expired record %+v", r)
	}
	if r := rec2.all(); len(r) != 1 || r[0].Outcome != audit.Error || r[0].Approval != audit.ApprovalCancelled {
		t.Errorf("cancelled record %+v", r)
	}
}

func TestShownArguments(t *testing.T) {
	m, _, _, _ := approvalMirror(t, &fakeDown{}, time.Minute)
	if got := m.shownArguments(nil); got != "" {
		t.Errorf("no arguments: %q", got)
	}
	long := `{"text":"` + strings.Repeat("a", 2*maxShownArguments) + `"}`
	if got := m.shownArguments(json.RawMessage(long)); len(got) > maxShownArguments+len("…") {
		t.Errorf("cut to %d bytes", len(got))
	}
	if got := m.shownArguments(json.RawMessage(`{"key":"` + ghToken + `"}`)); strings.Contains(got, ghToken) {
		t.Errorf("not redacted: %s", got)
	}
}

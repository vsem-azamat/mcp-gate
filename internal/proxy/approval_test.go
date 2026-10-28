package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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

func (n notices) Notify(_ context.Context, x approval.Notice) { n <- x }

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
	if got, cut := m.shownArguments(nil); got != "" || cut {
		t.Errorf("no arguments: %q", got)
	}
	// A long value is cut by itself: every key stays visible.
	long := `{"note":"` + strings.Repeat("a", 5000) + `","to":"alice@example.com"}`
	got, cut := m.shownArguments(json.RawMessage(long))
	if !cut || !strings.Contains(got, `"to":"alice@example.com"`) || len(got) > maxShownValue+100 {
		t.Errorf("long value: %v %q", cut, got)
	}
	if got, cut := m.shownArguments(json.RawMessage(`{"key":"` + ghToken + `"}`)); strings.Contains(got, ghToken) || cut {
		t.Errorf("not redacted: %s", got)
	}
	// Format and C1 characters are written out, not passed to the relay.
	got, _ = m.shownArguments(json.RawMessage(`{"path":"/srv/safe` + "\u202e" + `dwssap","c":"x` + "\u009b" + `2J","k` + "\u200b" + `":1}`))
	if strings.ContainsAny(got, "\u202e\u009b\u200b") || !strings.Contains(got, `\\u202E`) || !strings.Contains(got, `\\u009B`) || !strings.Contains(got, `"k\\u200B"`) {
		t.Errorf("format characters: %q", got)
	}
	// Big arrays and objects are cut, and say so.
	var items []string
	for i := range 100 {
		items = append(items, fmt.Sprintf(`"k%03d":%d`, i, i))
	}
	big := `{"list":[` + strings.Repeat("1,", 99) + `1],` + strings.Join(items, ",") + `}`
	if got, cut := m.shownArguments(json.RawMessage(big)); !cut || !strings.Contains(got, "36 more") {
		t.Errorf("big array: %q", got)
	}
}

func TestCanonicalArguments(t *testing.T) {
	for _, c := range []struct{ in, want, err string }{
		{in: ``, want: ``},
		{in: ` {"b": 1.50, "a": [true, null, "<x>"]} `, want: `{"a":[true,null,"<x>"],"b":1.50}`},
		{in: `{"to":"alice","to":"mallory"}`, err: "a key is given twice"},
		{in: `{"a":{"x":1,"x":2}}`, err: "a key is given twice"},
		{in: `{"a":[{"x":1,"x":2}]}`, err: "a key is given twice"},
		{in: `[1]`, err: "not a JSON object"},
		{in: `{"a":1} {"a":2}`, err: "more than one JSON value"},
		{in: `{"a":`, err: "not valid JSON"},
		{in: strings.Repeat(`{"a":`, 70) + `1` + strings.Repeat(`}`, 70), err: "nested too deep"},
	} {
		got, err := canonicalArguments(json.RawMessage(c.in))
		switch {
		case c.err != "":
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%.40s: %v, want %q", c.in, err, c.err)
			}
		case err != nil || string(got) != c.want:
			t.Errorf("%.40s: %s %v, want %s", c.in, got, err, c.want)
		}
	}
}

// TestHeldArgumentsAsShown checks that the server gets exactly the arguments the owner saw, and
// that arguments with a key given twice are refused without asking.
func TestHeldArgumentsAsShown(t *testing.T) {
	down := &fakeDown{tool: textResult("sent")}
	m, rec, store, n := approvalMirror(t, down, time.Minute)
	got := callAsync(m, "send", "send", `{ "to" : "alice@example.com", "n": 1e2 }`, nil)
	notice := <-n
	if notice.Arguments != `{"n":1e2,"to":"alice@example.com"}` || notice.Size != len(`{"n":1e2,"to":"alice@example.com"}`) || notice.Truncated {
		t.Errorf("notice %+v", notice)
	}
	store.Decide(notice.ID, true, "owner")
	<-got
	if len(down.tools) != 1 || !jsonIs(down.tools[0].Arguments, `{"n":1e2,"to":"alice@example.com"}`) {
		t.Errorf("forwarded %+v", down.tools)
	}
	c := <-callAsync(m, "send", "send", `{"to":"alice@example.com","note":"`+strings.Repeat("a", 5000)+`","to":"mallory@example.com"}`, nil)
	if c.err != nil || !c.res.IsError || !strings.Contains(firstText(c.res), "a key is given twice") {
		t.Errorf("duplicate key: %+v %q", c, firstText(c.res))
	}
	if len(n) != 0 || len(down.tools) != 1 {
		t.Error("a call with a key given twice was held or forwarded")
	}
	if r := rec.all(); r[len(r)-1].Outcome != audit.NotApproved || r[len(r)-1].Approval != audit.ApprovalDenied || r[len(r)-1].Approver != approval.ByGate {
		t.Errorf("record %+v", r[len(r)-1])
	}
}

func TestUnmatchedApprovePatternWarns(t *testing.T) {
	var logs strings.Builder
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	cfg := &config.Config{Servers: map[string]*config.Server{"s": {Approve: []string{"send", "s__delete", "drop_*"}}}}
	m, _ := fakeMirror(Options{Logger: logger, Approval: &Approval{Rules: approval.NewRules(cfg, "s"), Store: approval.NewStore(nil)}}, &fakeDown{})
	m.checkApprove([]*mcp.Tool{{Name: "send"}})
	m.checkApprove([]*mcp.Tool{{Name: "send"}})
	out := logs.String()
	if strings.Count(out, "names no tool") != 1 || !strings.Contains(out, "pattern=s__delete") || strings.Contains(out, "drop_") {
		t.Errorf("warnings: %s", out)
	}
}

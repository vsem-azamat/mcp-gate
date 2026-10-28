package main

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vsem-azamat/mcp-gate/internal/approval"
	"github.com/vsem-azamat/mcp-gate/internal/audit"
)

func TestApprovalsCommand(t *testing.T) {
	store := approval.NewStore(nil)
	defer store.Close()
	const secret = "admin-secret-0123456789"
	srv := httptest.NewServer(store.AdminHandler(func(h string) (string, bool) { return "owner", h == "Bearer "+secret }, nil))
	defer srv.Close()
	env := func(vars map[string]string) lookupEnv {
		return func(k string) (string, bool) { v, ok := vars[k]; return v, ok }
	}
	ok := env(map[string]string{"MCP_GATE_URL": srv.URL, "MCP_GATE_ADMIN_TOKEN": secret})
	runIt := func(e lookupEnv, args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := run(t.Context(), append([]string{"approvals"}, args...), e, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}

	if code, out, _ := runIt(ok, "list"); code != exitOK || out != "no pending approvals\n" {
		t.Errorf("empty list: %d %q", code, out)
	}
	got := make(chan approval.Decision, 1)
	go func() {
		got <- store.Ask(context.Background(), approval.Question{Server: "chat", Tool: "send_message", Principal: "laptop", Arguments: `{"text":"hi"}`},
			approval.Settings{Timeout: time.Minute}, nil)
	}()
	var id string
	for deadline := time.Now().Add(5 * time.Second); id == "" && time.Now().Before(deadline); {
		if l := store.List(); len(l) == 1 {
			id = l[0].ID
		}
		time.Sleep(time.Millisecond)
	}
	code, out, _ := runIt(ok, "list")
	if code != exitOK || !strings.HasPrefix(out, id+"  chat/send_message  by laptop  ") || !strings.Contains(out, "s left\n  {\"text\":\"hi\"}\n") {
		t.Errorf("list: %d %q", code, out)
	}
	if code, _, errOut := runIt(env(map[string]string{"MCP_GATE_URL": srv.URL, "MCP_GATE_ADMIN_TOKEN": "wrong"}), "approve", id); code != exitTrouble ||
		!strings.Contains(errOut, "did not accept") || strings.Contains(errOut, "wrong") {
		t.Errorf("wrong token: %d %q", code, errOut)
	}
	if code, _, errOut := runIt(env(map[string]string{"MCP_GATE_URL": srv.URL}), "list"); code != exitTrouble || !strings.Contains(errOut, "MCP_GATE_ADMIN_TOKEN") {
		t.Errorf("no token: %d %q", code, errOut)
	}
	if code, out, _ := runIt(env(map[string]string{"MCP_GATE_ADMIN_TOKEN": secret}), "-url", srv.URL+"/", "approve", id); code != exitOK || out != id+": approved\n" {
		t.Errorf("approve: %d %q", code, out)
	}
	if d := <-got; d != (approval.Decision{Approval: audit.Approved, By: "owner"}) {
		t.Errorf("decision %+v", d)
	}
	if code, _, errOut := runIt(ok, "deny", id); code != exitTrouble || !strings.Contains(errOut, "no pending approval "+id) {
		t.Errorf("deny a decided one: %d %q", code, errOut)
	}
	for _, args := range [][]string{{}, {"approve"}, {"list", "x"}, {"nope"}} {
		if code, _, _ := runIt(ok, args...); code != exitUsage {
			t.Errorf("%v: %d", args, code)
		}
	}
}

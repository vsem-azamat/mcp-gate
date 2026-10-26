package gate_test

import (
	"slices"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

// reloadPolicyDoc is a config with phone's policy on cat allowing the tool allowed, and a filter
// on other, the server the reloads change besides.
func reloadPolicyDoc(cat, other, allowed, otherDeny string) string {
	return `version: 1
auth:
  tokens: {laptop: "${LAPTOP}", phone: "${PHONE}"}
aggregate: {}
policies:
  phone:
    servers:
      cat:
        tools: {allow: [` + allowed + `]}
servers:
  cat:
` + cat + `  other:
` + other + "    tools: {deny: [" + otherDeny + "]}\n"
}

// phoneTools lists the tools phone sees on cat's route and on /mcp.
func phoneTools(t *testing.T, r *running) (route, aggregate []string) {
	t.Helper()
	header := "Bearer " + phoneToken
	return toolNames(t, r.connect(t, "cat", clientOpts{header: header})),
		toolNames(t, r.connect(t, "", clientOpts{aggregate: true, header: header}))
}

// TestPoliciesHoldAfterReload checks that a reload that leaves the policies as they are keeps
// applying them, on the server's route and on /mcp.
func TestPoliciesHoldAfterReload(t *testing.T) {
	cat, other := stdioServer(t, testkit.Fake{}, ""), stdioServer(t, testkit.Fake{}, "")
	r := startGate(t, reloadPolicyDoc(cat, other, "echo", "env"), gateOpts{})
	r.waitReady(t, "cat")
	r.waitReady(t, "other")
	r.reload(t, reloadPolicyDoc(cat, other, "echo", "pids"))
	route, agg := phoneTools(t, r)
	if !slices.Equal(route, []string{"echo"}) {
		t.Errorf("phone on cat after the reload: %v", route)
	}
	if !slices.Contains(agg, "cat__echo") || slices.Contains(agg, "cat__sleep") {
		t.Errorf("phone on /mcp after the reload: %v", agg)
	}
	if got := toolNames(t, r.connect(t, "cat", clientOpts{})); !slices.Contains(got, "sleep") {
		t.Errorf("laptop on cat after the reload: %v", got)
	}
}

// TestPolicyChangedByReload checks that a reload that changes a token policy applies it at once,
// on the route and on /mcp, for listing and calling, without restarting the server.
func TestPolicyChangedByReload(t *testing.T) {
	cat, other := stdioServer(t, testkit.Fake{}, ""), stdioServer(t, testkit.Fake{}, "")
	r := startGate(t, reloadPolicyDoc(cat, other, "echo", "env"), gateOpts{})
	r.waitReady(t, "cat")
	r.waitReady(t, "other")
	laptop := r.connect(t, "cat", clientOpts{})
	pid := pidOf(t, laptop)
	r.reload(t, reloadPolicyDoc(cat, other, "sleep", "env"))
	route, agg := phoneTools(t, r)
	if !slices.Equal(route, []string{"sleep"}) {
		t.Errorf("phone on cat after the change: %v", route)
	}
	if !slices.Contains(agg, "cat__sleep") || slices.Contains(agg, "cat__echo") {
		t.Errorf("phone on /mcp after the change: %v", agg)
	}
	phone := r.connect(t, "cat", clientOpts{header: "Bearer " + phoneToken})
	if _, err := echoText(t, phone, "x"); err == nil {
		t.Error("phone still calls echo")
	}
	res, err := phone.CallTool(t.Context(), &mcp.CallToolParams{Name: "sleep", Arguments: map[string]any{"ms": 1}})
	if err != nil || res.IsError {
		t.Errorf("phone calls sleep: %v %v", res, err)
	}
	if got := pidOf(t, laptop); got != pid {
		t.Errorf("the server was restarted: pid %d, was %d", got, pid)
	}
	if got := toolNames(t, laptop); !slices.Contains(got, "echo") || !slices.Contains(got, "sleep") {
		t.Errorf("laptop after the change: %v", got)
	}
}

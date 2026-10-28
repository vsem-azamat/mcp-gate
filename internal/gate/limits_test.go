package gate_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/proxy"
	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

// limitsDoc is a config where phone may call cat's echo once an hour and may not see env, with
// a second limit entry on other that the reloads change.
func limitsDoc(cat, other, echoRate, otherRate string) string {
	return `version: 1
auth:
  tokens: {laptop: "${LAPTOP}", phone: "${PHONE}"}
admin:
  tokens: {owner: "${ADMIN}"}
metrics: {enabled: true}
aggregate: {}
policies:
  phone:
    servers:
      cat: {tools: {deny: [env]}}
limits:
  - {token: phone, server: cat, tool: echo, rate: ` + echoRate + `}
  - {server: other, rate: ` + otherRate + `}
servers:
  cat:
` + cat + `  other:
` + other
}

// limitedMessage returns the message of the JSON-RPC error of a call a limit refused, failing
// on any other error.
func limitedMessage(t *testing.T, err error) string {
	t.Helper()
	var rpc *jsonrpc.Error
	if !errors.As(err, &rpc) || rpc.Code != proxy.CodeLimited {
		t.Fatalf("want a limit's error, got %v", err)
	}
	return rpc.Message
}

// TestLimits checks a limit end to end: the client's error, the hidden tool that stays unknown,
// the audit line, the metrics, and the buckets across reloads.
func TestLimits(t *testing.T) {
	cat, other := stdioServer(t, testkit.Fake{}, ""), stdioServer(t, testkit.Fake{}, "")
	r := startGate(t, limitsDoc(cat, other, "1/h", "100/h"), gateOpts{})
	r.waitReady(t, "cat")
	r.waitReady(t, "other")
	phone := r.connect(t, "cat", clientOpts{header: "Bearer " + phoneToken})
	if _, err := echoText(t, phone, "x"); err != nil {
		t.Fatal(err)
	}
	_, err := echoText(t, phone, "x")
	if msg := limitedMessage(t, err); msg != "mcp-gate: rate limit reached: at most 1 call per 1h; retry in 3600s" {
		t.Errorf("message %q", msg)
	}
	// The same bucket on /mcp, under the server's own tool name.
	agg := r.connect(t, "", clientOpts{aggregate: true, header: "Bearer " + phoneToken})
	_, err = agg.CallTool(t.Context(), &mcp.CallToolParams{Name: "cat__echo", Arguments: map[string]any{"text": "x"}})
	limitedMessage(t, err)
	// A hidden tool fails as a missing one, not as a limited one.
	_, errHidden := phone.CallTool(t.Context(), &mcp.CallToolParams{Name: "env"})
	_, errMissing := phone.CallTool(t.Context(), &mcp.CallToolParams{Name: "nosuch"})
	if errHidden == nil || errMissing == nil || strings.ReplaceAll(errHidden.Error(), "env", "nosuch") != errMissing.Error() {
		t.Errorf("hidden %v, missing %v", errHidden, errMissing)
	}
	// Other tokens and tools are not limited.
	if _, err := echoText(t, r.connect(t, "cat", clientOpts{}), "x"); err != nil {
		t.Errorf("laptop: %v", err)
	}
	if _, err := phone.CallTool(t.Context(), &mcp.CallToolParams{Name: "pids"}); err != nil {
		t.Errorf("phone's pids: %v", err)
	}
	var limited int
	for _, line := range r.logs.lines("call") {
		if line["outcome"] == "limited" {
			limited++
			if line["principal"] != "phone" || line["tool"] != "echo" || line["server"] != "cat" {
				t.Errorf("call line %v", line)
			}
		}
	}
	if limited != 2 {
		t.Errorf("%d limited call lines, want 2", limited)
	}
	if m := r.metricsOf(t); !strings.Contains(m, `mcp_gate_requests_total{server="cat",kind="tool",name="echo",token="phone",outcome="limited"} 2`) {
		t.Errorf("metrics:\n%s", m)
	}

	// A reload that changes another entry keeps the bucket; one that changes the entry does not.
	r.reload(t, limitsDoc(cat, other, "1/h", "50/h"))
	_, err = echoText(t, phone, "x")
	limitedMessage(t, err)
	r.reload(t, limitsDoc(cat, other, "2/h", "50/h"))
	if _, err := echoText(t, phone, "x"); err != nil {
		t.Errorf("after the entry changed: %v", err)
	}
}

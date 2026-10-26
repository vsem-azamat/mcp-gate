package gate_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

// The parts of an audit line that change from run to run.
var (
	timeAttr  = regexp.MustCompile(`"time":"[^"]*",`)
	durMsAttr = regexp.MustCompile(`"durMs":\d+`)
)

// TestAuditLinesGolden pins the exact text of the audit lines, attribute order included, for
// calls on a server's route and on the aggregate route, with and without a token policy, and
// refusals before and after a handler.
func TestAuditLinesGolden(t *testing.T) {
	web := testkit.NewFakeHTTP(t, testkit.Fake{}, testkit.FakeHTTPOptions{}).URL()
	doc := `version: 1
auth:
  tokens: {laptop: "${LAPTOP}", phone: "${PHONE}"}
aggregate: {}
policies:
  phone:
    servers:
      cat:
        tools: {allow: [echo]}
        resources: {allow: [fake://info]}
servers:
  cat:
` + stdioServer(t, testkit.Fake{Catalog: true, Failures: true}, "tools: {deny: [env]}\n") + `  web:
` + httpServer(web, "")
	r := startGate(t, doc, gateOpts{})
	for _, s := range []string{"cat", "web"} {
		r.waitReady(t, s)
	}
	laptop := r.connect(t, "cat", clientOpts{})
	phone := r.connect(t, "cat", clientOpts{header: "Bearer " + phoneToken})
	webc := r.connect(t, "web", clientOpts{})
	agg := r.connect(t, "", clientOpts{aggregate: true, header: "Bearer " + phoneToken})

	const secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	tool := func(cs *mcp.ClientSession, name string, args map[string]any) {
		t.Helper()
		_, _ = cs.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: args})
	}
	tool(laptop, "echo", map[string]any{"text": "hello"})
	tool(laptop, "echo", map[string]any{"text": "token " + secret})
	tool(laptop, "env", nil)     // the server's filter hides it
	tool(laptop, "missing", nil) // the server has no such tool
	tool(phone, "echo", map[string]any{"text": "hi"})
	tool(phone, "big", map[string]any{"bytes": 1}) // the token's policy hides it
	tool(webc, "crash", nil)                       // the HTTP fake fails the call
	_, _ = laptop.GetPrompt(t.Context(), &mcp.GetPromptParams{Name: "greet"})
	_, _ = laptop.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "fake://info"})
	_, _ = phone.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "fake://hidden"})  // hidden by the policy
	_, _ = phone.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "fake://nothing"}) // the policy passes no such URI
	tool(agg, "cat__echo", map[string]any{"text": "hi"})
	tool(agg, "cat__big", nil)      // hidden by the policy, audited by cat
	tool(agg, "nowhere__echo", nil) // no such server: audited by the aggregate
	_, _ = agg.GetPrompt(t.Context(), &mcp.GetPromptParams{Name: "cat__greet"})
	tool(laptop, "toolerror", nil)                                          // a tool error
	_, _ = laptop.GetPrompt(t.Context(), &mcp.GetPromptParams{Name: "ask"}) // asks for input

	var got []string
	for line := range strings.SplitSeq(r.logs.String(), "\n") {
		if strings.Contains(line, `"msg":"call"`) {
			line = timeAttr.ReplaceAllString(line, "")
			got = append(got, durMsAttr.ReplaceAllString(line, `"durMs":0`))
		}
	}
	want := []string{
		`{"level":"INFO","msg":"call","server":"cat","principal":"laptop","method":"tools/call","tool":"echo","durMs":0,"outcome":"ok","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"cat","principal":"laptop","method":"tools/call","tool":"echo","durMs":0,"outcome":"ok","tokenPolicy":"none","redactions":1}`,
		`{"level":"INFO","msg":"call","server":"cat","principal":"laptop","method":"tools/call","tool":"env","durMs":0,"outcome":"denied","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"cat","principal":"laptop","method":"tools/call","tool":"missing","durMs":0,"outcome":"denied","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"cat","principal":"phone","method":"tools/call","tool":"echo","durMs":0,"outcome":"ok","tokenPolicy":"allow","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"cat","principal":"phone","method":"tools/call","tool":"big","durMs":0,"outcome":"denied","tokenPolicy":"deny","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"web","principal":"laptop","method":"tools/call","tool":"crash","durMs":0,"outcome":"error","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"cat","principal":"laptop","method":"prompts/get","prompt":"greet","durMs":0,"outcome":"ok","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"cat","principal":"laptop","method":"resources/read","uri":"fake://info","durMs":0,"outcome":"ok","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"cat","principal":"phone","method":"resources/read","uri":"fake://hidden","durMs":0,"outcome":"denied","tokenPolicy":"deny","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"cat","principal":"phone","method":"resources/read","uri":"fake://nothing","durMs":0,"outcome":"denied","tokenPolicy":"deny","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"cat","principal":"phone","method":"tools/call","tool":"echo","durMs":0,"outcome":"ok","tokenPolicy":"allow","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"cat","principal":"phone","method":"tools/call","tool":"big","durMs":0,"outcome":"denied","tokenPolicy":"deny","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"","principal":"phone","method":"tools/call","tool":"nowhere__echo","durMs":0,"outcome":"denied","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"cat","principal":"phone","method":"prompts/get","prompt":"greet","durMs":0,"outcome":"ok","tokenPolicy":"allow","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"cat","principal":"laptop","method":"tools/call","tool":"toolerror","durMs":0,"outcome":"tool_error","tokenPolicy":"none","redactions":0}`,
		`{"level":"INFO","msg":"call","server":"cat","principal":"laptop","method":"prompts/get","prompt":"ask","durMs":0,"outcome":"input_required","tokenPolicy":"none","redactions":0}`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("audit lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

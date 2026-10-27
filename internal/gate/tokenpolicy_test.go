package gate_test

import (
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

// policyDoc is the config of policyGate with the given policies of phone.
func policyDoc(t *testing.T, policies string) string {
	t.Helper()
	return `version: 1
auth:
  tokens: {laptop: "${LAPTOP}", phone: "${PHONE}"}
aggregate: {}
policies:
  phone:
    servers:
` + policies + `servers:
  cat:
` + stdioServer(t, testkit.Fake{Catalog: true}, "") + `  plain:
` + stdioServer(t, testkit.Fake{}, "tools: {deny: [pids]}\n") + `  open:
` + stdioServer(t, testkit.Fake{}, "")
}

// The policies of phone that policyGate serves.
const phonePolicies = `      cat:
        tools: {allow: [echo]}
        prompts: none
        resources: {allow: [fake://info, items]}
      plain:
        tools: {deny: [env]}
`

// policyGate serves cat (a full catalog), plain (tools only, without pids by its own filter)
// and open to the global tokens laptop and phone, also on the aggregate endpoint. laptop has no
// policy; phone sees only echo, no prompts and only fake://info and the items template on cat,
// and every tool but env on plain. Nobody has a policy on open.
func policyGate(t *testing.T) *running {
	t.Helper()
	doc := policyDoc(t, phonePolicies)
	r := startGate(t, doc, gateOpts{})
	for _, s := range []string{"cat", "plain", "open"} {
		r.waitReady(t, s)
	}
	return r
}

func promptNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListPrompts(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range res.Prompts {
		out = append(out, p.Name)
	}
	return out
}

func resourceKeys(t *testing.T, cs *mcp.ClientSession) (resources, templates []string) {
	t.Helper()
	rs, err := cs.ListResources(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs.Resources {
		resources = append(resources, r.URI)
	}
	ts, err := cs.ListResourceTemplates(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tp := range ts.ResourceTemplates {
		templates = append(templates, tp.URITemplate)
	}
	sort.Strings(resources)
	sort.Strings(templates)
	return resources, templates
}

// sameRefusal checks that refusing hidden fails exactly as refusing unknown, an entry that does
// not exist, once the names are swapped.
func sameRefusal(t *testing.T, what, hidden, unknown string, call func(name string) error) {
	t.Helper()
	errHidden, errUnknown := call(hidden), call(unknown)
	if errHidden == nil || errUnknown == nil {
		t.Fatalf("%s: hidden %v, unknown %v", what, errHidden, errUnknown)
	}
	if got, want := strings.ReplaceAll(errHidden.Error(), hidden, unknown), errUnknown.Error(); got != want {
		t.Errorf("%s: a hidden entry fails as %q, an unknown one as %q", what, got, want)
	}
}

func TestTokenPolicyLists(t *testing.T) {
	r := policyGate(t)
	laptop := r.connect(t, "cat", clientOpts{})
	phone := r.connect(t, "cat", clientOpts{header: "Bearer " + phoneToken})

	if got := toolNames(t, laptop); len(got) < 10 {
		t.Errorf("laptop, without a policy, lists %v", got)
	}
	if got := toolNames(t, phone); !slices.Equal(got, []string{"echo"}) {
		t.Errorf("phone lists the tools %v", got)
	}
	if got := promptNames(t, laptop); !slices.Equal(got, []string{"greet"}) {
		t.Errorf("laptop lists the prompts %v", got)
	}
	if got := promptNames(t, phone); len(got) != 0 {
		t.Errorf("phone lists the prompts %v", got)
	}
	res, tpl := resourceKeys(t, phone)
	if !slices.Equal(res, []string{"fake://info"}) || !slices.Equal(tpl, []string{"fake://items/{id}"}) {
		t.Errorf("phone lists the resources %v and templates %v", res, tpl)
	}
	if res, tpl := resourceKeys(t, laptop); len(res) != 2 || len(tpl) != 2 {
		t.Errorf("laptop lists the resources %v and templates %v", res, tpl)
	}
	// Where lists depend on the token, they are not for shared caches.
	for name, cs := range map[string]*mcp.ClientSession{"phone": phone, "laptop": laptop} {
		if lt, err := cs.ListTools(t.Context(), nil); err != nil || lt.CacheScope != "private" {
			t.Errorf("%s's list: %v %v", name, lt, err)
		}
	}
	if lt, err := r.connect(t, "open", clientOpts{}).ListTools(t.Context(), nil); err != nil || lt.CacheScope != "public" {
		t.Errorf("the list of a server without policies: %v %v", lt, err)
	}

	plain := r.connect(t, "plain", clientOpts{header: "Bearer " + phoneToken})
	if got := toolNames(t, plain); slices.Contains(got, "env") || !slices.Contains(got, "echo") {
		t.Errorf("phone lists the tools of plain %v", got)
	}
}

func TestTokenPolicyRefusals(t *testing.T) {
	r := policyGate(t)
	phone := r.connect(t, "cat", clientOpts{header: "Bearer " + phoneToken})
	laptop := r.connect(t, "cat", clientOpts{})

	callTool := func(cs *mcp.ClientSession) func(string) error {
		return func(name string) error {
			_, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: name})
			return err
		}
	}
	getPrompt := func(cs *mcp.ClientSession) func(string) error {
		return func(name string) error {
			_, err := cs.GetPrompt(t.Context(), &mcp.GetPromptParams{Name: name})
			return err
		}
	}
	read := func(cs *mcp.ClientSession) func(string) error {
		return func(uri string) error {
			_, err := cs.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: uri})
			return err
		}
	}
	sameRefusal(t, "tool", "env", "nosuch", callTool(phone))
	sameRefusal(t, "prompt", "greet", "nosuch", getPrompt(phone))
	sameRefusal(t, "resource", "fake://hidden", "none://nothing", read(phone))
	sameRefusal(t, "template", "fake://other", "none://nothing", read(phone))
	if err := read(phone)("fake://items/7"); err != nil {
		t.Errorf("phone reads through the allowed template: %v", err)
	}
	if lines := r.calls("uri", "none://nothing"); len(lines) != 0 {
		t.Errorf("a read of a URI the server does not serve is audited: %v", lines)
	}
	if err := read(laptop)("fake://hidden"); err != nil {
		t.Errorf("laptop reads fake://hidden: %v", err)
	}

	// A policy decides only about what the server has: an unknown name, or one the server's
	// own filter hides, is no policy's doing.
	plain := r.connect(t, "plain", clientOpts{header: "Bearer " + phoneToken})
	for _, name := range []string{"nosuch", "pids"} {
		if _, err := plain.CallTool(t.Context(), &mcp.CallToolParams{Name: name}); err == nil {
			t.Errorf("phone called %s on plain", name)
		}
	}
	for _, c := range []struct{ server, tool string }{{"cat", "nosuch"}, {"plain", "nosuch"}, {"plain", "pids"}} {
		var found map[string]any
		for _, l := range r.calls("tool", c.tool) {
			if l["server"] == c.server && l["principal"] == "phone" {
				found = l
			}
		}
		if found["outcome"] != "denied" || found["tokenPolicy"] != "none" {
			t.Errorf("audit line of phone's %s on %s: %v", c.tool, c.server, found)
		}
	}

	// The audit line records the decision.
	if res, err := phone.CallTool(t.Context(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "x"}}); err != nil || textOf(t, res) != "x" {
		t.Fatalf("phone calls echo: %v %v", res, err)
	}
	if _, err := laptop.CallTool(t.Context(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "x"}}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ key, value, principal, outcome, decision string }{
		{"tool", "env", "phone", "denied", "deny"},
		{"prompt", "greet", "phone", "denied", "deny"},
		{"uri", "fake://hidden", "phone", "denied", "deny"},
		{"uri", "fake://items/7", "phone", "ok", "allow"},
		{"uri", "fake://hidden", "laptop", "ok", "none"},
	} {
		var found map[string]any
		for _, l := range r.calls(c.key, c.value) {
			if l["principal"] == c.principal {
				found = l
			}
		}
		if found["server"] != "cat" || found["outcome"] != c.outcome || found["tokenPolicy"] != c.decision {
			t.Errorf("audit line of %s %s by %s: %v", c.key, c.value, c.principal, found)
		}
	}
	echo := map[any]any{}
	for _, l := range r.calls("tool", "echo") {
		echo[l["principal"]] = l["tokenPolicy"]
	}
	if echo["phone"] != "allow" || echo["laptop"] != "none" {
		t.Errorf("tokenPolicy of the echo calls: %v", echo)
	}
}

func TestTokenPolicyAggregate(t *testing.T) {
	r := policyGate(t)
	laptop := r.connect(t, "", clientOpts{aggregate: true})
	if lt, err := laptop.ListTools(t.Context(), nil); err != nil || lt.CacheScope != "private" {
		t.Errorf("laptop's list: %v %v", lt, err)
	}
	phone := r.connect(t, "", clientOpts{aggregate: true, header: "Bearer " + phoneToken})

	got := toolNames(t, phone)
	if !slices.Contains(got, "cat__echo") || slices.Contains(got, "cat__sleep") || slices.Contains(got, "plain__env") || !slices.Contains(got, "plain__echo") {
		t.Errorf("phone lists %v", got)
	}
	if all := toolNames(t, laptop); !slices.Contains(all, "cat__sleep") || !slices.Contains(all, "plain__env") {
		t.Errorf("laptop lists %v", all)
	}
	if got := promptNames(t, phone); len(got) != 0 {
		t.Errorf("phone lists the prompts %v", got)
	}
	if res, tpl := resourceKeys(t, phone); !slices.Equal(res, []string{"fake://info"}) || !slices.Equal(tpl, []string{"fake://items/{id}"}) {
		t.Errorf("phone lists the resources %v and templates %v", res, tpl)
	}
	if res, _ := resourceKeys(t, laptop); len(res) != 2 {
		t.Errorf("laptop lists the resources %v", res)
	}
	if lt, err := phone.ListTools(t.Context(), nil); err != nil || lt.CacheScope != "private" {
		t.Errorf("phone's list: %v %v", lt, err)
	}

	sameRefusal(t, "tool", "plain__env", "plain__nosuch", func(name string) error {
		_, err := phone.CallTool(t.Context(), &mcp.CallToolParams{Name: name})
		return err
	})
	sameRefusal(t, "prompt", "cat__greet", "cat__nosuch", func(name string) error {
		_, err := phone.GetPrompt(t.Context(), &mcp.GetPromptParams{Name: name})
		return err
	})
	sameRefusal(t, "resource", "fake://hidden", "none://nothing", func(uri string) error {
		_, err := phone.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: uri})
		return err
	})
	if res, err := phone.CallTool(t.Context(), &mcp.CallToolParams{Name: "cat__echo", Arguments: map[string]any{"text": "x"}}); err != nil || textOf(t, res) != "x" {
		t.Fatalf("phone calls cat__echo: %v %v", res, err)
	}
	if res, err := laptop.CallTool(t.Context(), &mcp.CallToolParams{Name: "plain__env"}); err != nil || res.IsError {
		t.Errorf("laptop calls plain__env: %v %v", res, err)
	}

	if l := r.lastCall("tool", "env"); l["server"] != "plain" || l["principal"] != "laptop" || l["tokenPolicy"] != "none" {
		t.Errorf("audit line of laptop's plain__env: %v", l)
	}
	var denied map[string]any
	for _, l := range r.calls("tool", "env") {
		if l["principal"] == "phone" {
			denied = l
		}
	}
	if denied["server"] != "plain" || denied["outcome"] != "denied" || denied["tokenPolicy"] != "deny" {
		t.Errorf("audit line of phone's plain__env: %v", denied)
	}
	if l := r.lastCall("tool", "echo"); l["server"] != "cat" || l["principal"] != "phone" || l["tokenPolicy"] != "allow" {
		t.Errorf("audit line of phone's cat__echo: %v", l)
	}
	if l := r.lastCall("uri", "fake://hidden"); l["server"] != "cat" || l["principal"] != "phone" || l["outcome"] != "denied" || l["tokenPolicy"] != "deny" {
		t.Errorf("audit line of phone's read of fake://hidden: %v", l)
	}
	if lines := r.calls("uri", "none://nothing"); len(lines) != 0 {
		t.Errorf("a read of a URI no server serves is audited: %v", lines)
	}
}

// A tool with a parameter bound to a header is checked by the SDK before any handler runs; a
// hidden one must still fail as an unknown tool.
func TestTokenPolicyHeaderParameters(t *testing.T) {
	schema := map[string]any{"type": "object", "properties": map[string]any{
		"p": map[string]any{"type": "string", "x-mcp-header": "P"},
	}}
	hub := testkit.NewHub(t, testkit.HubOptions{Servers: map[string]testkit.Catalog{"hdr": {Tools: []*mcp.Tool{
		{Name: "bound", InputSchema: schema}, {Name: "plain", InputSchema: map[string]any{"type": "object"}},
	}}}})
	doc := `version: 1
auth:
  tokens: {laptop: "${LAPTOP}", phone: "${PHONE}"}
policies:
  phone: {servers: {hdr: {tools: {allow: [plain]}}}}
servers:
  hdr:
` + httpServer(strings.ReplaceAll(hub.URLTemplate(), "{server}", "hdr"), "")
	r := startGate(t, doc, gateOpts{})
	r.waitReady(t, "hdr")
	phone := r.connect(t, "hdr", clientOpts{version: "2026-07-28", header: "Bearer " + phoneToken})
	if got := toolNames(t, phone); !slices.Equal(got, []string{"plain"}) {
		t.Fatalf("phone lists %v", got)
	}
	sameRefusal(t, "tool with a header parameter", "bound", "nosuch", func(name string) error {
		_, err := phone.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: map[string]any{"p": "x"}})
		return err
	})
}

// A token allowed a catch-all template cannot read a hidden listed resource by adding a query.
func TestTokenPolicyQuerySpelling(t *testing.T) {
	doc := `version: 1
auth:
  tokens: {laptop: "${LAPTOP}", phone: "${PHONE}"}
policies:
  phone: {servers: {cat: {resources: {allow: [any]}}}}
servers:
  cat:
` + stdioServer(t, testkit.Fake{Catalog: true}, "")
	r := startGate(t, doc, gateOpts{})
	r.waitReady(t, "cat")
	phone := r.connect(t, "cat", clientOpts{header: "Bearer " + phoneToken})
	for uri, ok := range map[string]bool{
		"fake://hidden?a=b": false, "fake://hidden": false, "FAKE://%68idden?x": false, "fake://other?a=b": true,
		"fake://hid%E2%80%8Bden": false, "fake://%C3%A9t%C3%A9": true,
	} {
		if _, err := phone.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: uri}); (err == nil) != ok {
			t.Errorf("phone reads %s: %v", uri, err)
		}
	}
}

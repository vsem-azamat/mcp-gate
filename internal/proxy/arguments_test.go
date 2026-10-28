package proxy

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/audit"
	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/escrow"
	"github.com/vsem-azamat/mcp-gate/internal/redact"
)

const vaultPassword = "Summer-Blue-77!"

func testEngine(t *testing.T) *redact.Engine {
	t.Helper()
	e, err := redact.New(redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func toolCall(name, principal, args string) *mcp.CallToolRequest {
	return &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{Name: name, Arguments: json.RawMessage(args)},
		Extra:  &mcp.RequestExtra{TokenInfo: &auth.TokenInfo{UserID: principal}},
	}
}

func TestArgumentScan(t *testing.T) {
	engine := testEngine(t)
	for _, c := range []struct {
		name, mode, args string
		refused          bool
		kinds            string
	}{
		{name: "block", mode: config.ArgumentsBlock, args: `{"text":"the key is ` + ghToken + `"}`, refused: true, kinds: "github_token"},
		{name: "log", mode: config.ArgumentsLog, args: `{"password":"hunter22"}`, kinds: "password"},
		{name: "off", mode: config.ArgumentsOff, args: `{"password":"hunter22"}`},
		{name: "marker", mode: config.ArgumentsBlock, args: `{"password":"[REDACTED:password #kaaaaaaaaaa]","text":"[REDACTED:github_token]"}`},
		{name: "clean", mode: config.ArgumentsBlock, args: `{"text":"hello"}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			down := &fakeDown{tool: textResult("sent")}
			m, rec := fakeMirror(Options{Redaction: NewRedaction(engine, nil, 1<<20), Arguments: c.mode}, down)
			res, err := m.callTool(t.Context(), toolCall("send_message", "laptop", c.args))
			if err != nil {
				t.Fatal(err)
			}
			r := rec.last(t)
			if r.ArgumentSecrets != c.kinds {
				t.Errorf("argumentSecrets = %q, want %q", r.ArgumentSecrets, c.kinds)
			}
			if !c.refused {
				if len(down.tools) != 1 || !jsonIs(down.tools[0].Arguments, c.args) || r.Outcome != audit.OK {
					t.Fatalf("not forwarded unchanged: %v, outcome %s", down.tools, r.Outcome)
				}
				return
			}
			if len(down.tools) != 0 {
				t.Fatal("a refused call was forwarded")
			}
			text := firstText(res)
			if !res.IsError || !strings.Contains(text, "github_token") || strings.Contains(text, ghToken) || r.Outcome != audit.Refused {
				t.Fatalf("result %q (error %v), outcome %s", text, res.IsError, r.Outcome)
			}
		})
	}
}

func TestArgumentScanPromptAndResource(t *testing.T) {
	down := &fakeDown{prompt: &mcp.GetPromptResult{}, read: &mcp.ReadResourceResult{}}
	m, rec := fakeMirror(Options{Redaction: NewRedaction(testEngine(t), nil, 1<<20), Arguments: config.ArgumentsBlock}, down)
	_, err := m.getPrompt(t.Context(), &mcp.GetPromptRequest{Params: &mcp.GetPromptParams{Name: "p", Arguments: map[string]string{"token": ghToken}}})
	if err == nil || !strings.Contains(err.Error(), "(secret)") || strings.Contains(err.Error(), ghToken) {
		t.Fatalf("prompt error %v", err)
	}
	if r := rec.last(t); r.Outcome != audit.Refused || r.ArgumentSecrets != "secret" {
		t.Fatalf("prompt record %+v", r)
	}
	_, err = m.readResource(t.Context(), &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{URI: "db://x?password=hunter22"}})
	if err == nil || !strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "hunter22") {
		t.Fatalf("read error %v", err)
	}
	if len(down.prompts)+len(down.reads) != 0 {
		t.Fatal("a refused request was forwarded")
	}
}

// substitutionFixture is a gate's worth of escrow and an app server with substitution rules.
type substitutionFixture struct {
	escrow *escrow.Escrow
	marker string // shown to laptop by vault
	handle string
	down   *fakeDown
	m      *Mirror
	rec    *recorder
}

func newSubstitutionFixture(t *testing.T, mode string, origin string) *substitutionFixture {
	t.Helper()
	esc := escrow.New(escrow.Options{KeyHash: sha256.Sum256([]byte("key"))})
	marker := esc.Replacer(escrow.Source{Server: origin, Tool: "get", Recipient: "laptop"}).
		Replace(redact.Finding{Kind: "password", Value: vaultPassword})
	handle := escrow.MarkerRE.FindStringSubmatch(marker)[2]
	rules := []config.Substitution{
		{Tool: "login", Argument: "auth", From: map[string][]string{"vault": {"password"}}},
		{Tool: "send", Argument: "messages.*.text", From: map[string][]string{"vault": {"password"}}},
	}
	redaction := NewRedaction(testEngine(t), func(r Request) redact.Replacer {
		return esc.Replacer(escrow.Source{Server: "app", Tool: r.Name, Recipient: r.Recipient})
	}, 1<<20)
	down := &fakeDown{tool: textResult("ok")}
	m, rec := fakeMirror(Options{Name: "app", Redaction: redaction, Arguments: mode, Substitution: NewSubstitution(rules, esc)}, down)
	return &substitutionFixture{escrow: esc, marker: marker, handle: handle, down: down, m: m, rec: rec}
}

func TestSubstitution(t *testing.T) {
	f := newSubstitutionFixture(t, config.ArgumentsBlock, "vault")
	f.down.tool = textResult("welcome alice, your password is " + vaultPassword + ".")
	before := f.escrow.Stats().Entries
	res, err := f.m.callTool(t.Context(), toolCall("login", "laptop", `{"user":"alice <a@example.com>","auth":"`+f.marker+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.down.tools) != 1 || !jsonIs(f.down.tools[0].Arguments, `{"auth":"`+vaultPassword+`","user":"alice <a@example.com>"}`) {
		t.Fatalf("forwarded %v", f.down.tools)
	}
	if got, want := firstText(res), "welcome alice, your password is "+f.marker+"."; got != want {
		t.Fatalf("result %q, want %q", got, want)
	}
	if n := f.escrow.Stats().Entries; n != before {
		t.Fatalf("the echo was kept again: %d entries, want %d", n, before)
	}
	r := f.rec.last(t)
	if r.Outcome != audit.OK || r.ArgumentSecrets != "" || r.Substitutions != f.handle+":password:vault:auth" || r.Redactions != 1 {
		t.Fatalf("record %+v", r)
	}
}

func TestSubstitutionWildcardAndText(t *testing.T) {
	f := newSubstitutionFixture(t, config.ArgumentsLog, "vault")
	args := `{"messages":[{"text":"pw: ` + f.marker + `[REDACTED:continued] ok"},{"text":"none"}],"note":"` + f.marker + `"}`
	if _, err := f.m.callTool(t.Context(), toolCall("send", "laptop", args)); err != nil {
		t.Fatal(err)
	}
	want := `{"messages":[{"text":"pw: ` + vaultPassword + ` ok"},{"text":"none"}],"note":"` + f.marker + `"}`
	if len(f.down.tools) != 1 || !jsonIs(f.down.tools[0].Arguments, want) {
		t.Fatalf("forwarded %s", f.down.tools[0].Arguments)
	}
	if r := f.rec.last(t); r.Substitutions != f.handle+":password:vault:messages.*.text" {
		t.Fatalf("record %+v", r)
	}
}

func TestSubstitutionRefusals(t *testing.T) {
	for _, c := range []struct {
		name, origin, principal, args, want string
	}{
		{name: "other origin", origin: "mail", principal: "laptop", args: `{"auth":"%s"}`, want: "(password from mail) may not be sent there"},
		{name: "other token", origin: "vault", principal: "phone", args: `{"auth":"%s"}`, want: "is unknown or expired"},
		{name: "unknown handle", origin: "vault", principal: "laptop", args: `{"auth":"[REDACTED:password #kaaaaaaaaaa] %s"}`, want: "handle kaaaaaaaaaa is unknown"},
		{name: "other kind", origin: "vault", principal: "laptop", args: `{"auth":"%s"}`, want: "is unknown or expired"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newSubstitutionFixture(t, config.ArgumentsBlock, c.origin)
			marker := f.marker
			if c.name == "other kind" {
				marker = strings.Replace(marker, "password", "jwt", 1)
			}
			res, err := f.m.callTool(t.Context(), toolCall("login", c.principal, strings.Replace(c.args, "%s", marker, 1)))
			if err != nil {
				t.Fatal(err)
			}
			if len(f.down.tools) != 0 {
				t.Fatal("a refused call was forwarded")
			}
			text := firstText(res)
			if !res.IsError || !strings.Contains(text, "argument auth: handle") || !strings.Contains(text, c.want) || strings.Contains(text, vaultPassword) {
				t.Fatalf("result %q", text)
			}
			if r := f.rec.last(t); r.Outcome != audit.Refused || r.Substitutions != "" {
				t.Fatalf("record %+v", r)
			}
		})
	}
}

func TestSubstitutionOutsideRules(t *testing.T) {
	f := newSubstitutionFixture(t, config.ArgumentsBlock, "vault")
	args := `{"user":"` + f.marker + `"}`
	if _, err := f.m.callTool(t.Context(), toolCall("login", "laptop", args)); err != nil {
		t.Fatal(err)
	}
	if len(f.down.tools) != 1 || !jsonIs(f.down.tools[0].Arguments, args) {
		t.Fatalf("forwarded %v", f.down.tools)
	}
	// A secret written out next to a handle is still found.
	res, err := f.m.callTool(t.Context(), toolCall("login", "laptop", `{"auth":"`+f.marker+`","text":"`+ghToken+`"}`))
	if err != nil || !res.IsError || len(f.down.tools) != 1 {
		t.Fatalf("a written-out secret passed: %v %v", res, err)
	}
	if r := f.rec.last(t); r.ArgumentSecrets != "github_token" {
		t.Fatalf("record %+v", r)
	}
}

func TestSubstitutionEchoInError(t *testing.T) {
	f := newSubstitutionFixture(t, config.ArgumentsBlock, "vault")
	f.down.err = &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "wrong password " + vaultPassword}
	_, err := f.m.callTool(t.Context(), toolCall("login", "laptop", `{"auth":"`+f.marker+`"}`))
	if err == nil || strings.Contains(err.Error(), vaultPassword) || !strings.Contains(err.Error(), f.marker) {
		t.Fatalf("error %v", err)
	}
}

func TestSubstitutionPartlyRefusedRecordsNothing(t *testing.T) {
	f := newSubstitutionFixture(t, config.ArgumentsLog, "vault")
	res, err := f.m.callTool(t.Context(), toolCall("login", "laptop", `{"auth":"`+f.marker+` [REDACTED:password #kaaaaaaaaaa]"}`))
	if err != nil || !res.IsError || len(f.down.tools) != 0 {
		t.Fatalf("result %v, error %v, forwarded %d", res, err, len(f.down.tools))
	}
	if r := f.rec.last(t); r.Outcome != audit.Refused || r.Substitutions != "" {
		t.Fatalf("record %+v", r)
	}
}

func TestSubstitutedValueInALaterCall(t *testing.T) {
	f := newSubstitutionFixture(t, config.ArgumentsLog, "vault")
	if _, err := f.m.callTool(t.Context(), toolCall("login", "laptop", `{"auth":"`+f.marker+`"}`)); err != nil {
		t.Fatal(err)
	}
	f.down.tool = textResult("your config: password=" + vaultPassword)
	res, err := f.m.callTool(t.Context(), toolCall("whoami", "laptop", `{}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := firstText(res), "your config: password="+f.marker; got != want {
		t.Fatalf("later result %q, want %q", got, want)
	}
}

package gate_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/oauth"
	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

func TestOAuthServerNeedsLogin(t *testing.T) {
	srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{Fake: testkit.Fake{Name: "mail"}})
	state := t.TempDir()
	r := startGate(t, configDoc("startupGracePeriod: 30s\nadmin:\n  tokens: {owner: \"${ADMIN}\"}\n", map[string]string{
		"good": stdioServer(t, testkit.Fake{}, ""),
		"mail": fmt.Sprintf("    http:\n      url: %q\n      oauth: {}\n", srv.URL()),
	}), gateOpts{stateDir: state})
	const prefix = `{"name":"mcp-gate","serverCount":2,"status":`
	// The server waiting for a login does not hold the startup for its grace period.
	waitFor(t, "degraded naming the server", func() bool {
		code, _, body := r.get(t, http.MethodGet, "/_readyz", "")
		return code == 503 && body == prefix+`"degraded","needsLogin":["mail"],"version":"test"}`+"\n"
	})
	st := r.g.Status().Servers["mail"]
	if st.State != "needs-login" || st.Mounted || !strings.Contains(st.LastError, "auth login") {
		t.Errorf("status: %+v", st)
	}
	if code, _, _ := r.get(t, http.MethodPost, "/mail/mcp", "Bearer "+laptopToken); code != 503 {
		t.Errorf("route of a server needing a login: %d", code)
	}
	if srv.Rejected() != 0 {
		t.Errorf("%d requests went to the server without a grant", srv.Rejected())
	}

	g := srv.Login(t, oauth.NewStore(state), "mail")
	r.waitReady(t, "mail")
	waitFor(t, "ok", func() bool {
		code, _, _ := r.get(t, http.MethodGet, "/_readyz", "")
		return code == 200
	})
	cs := r.connect(t, "mail", clientOpts{})
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "hi"}})
	if err != nil || res.IsError || textOf(t, res) != "hi" {
		t.Fatalf("echo through the gate: %v %+v", err, res)
	}
	for _, secret := range []string{g.AccessToken, g.RefreshToken} {
		if strings.Contains(r.logs.String(), secret) {
			t.Error("a token appears in the logs")
		}
	}

	// A call that finds the grant revoked fails, and the server waits for a login at once.
	srv.RevokeAll()
	res, err = cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "hi"}})
	if err == nil && !res.IsError {
		t.Error("a call went through after the grant was revoked")
	}
	waitFor(t, "needs login again", func() bool { return r.g.Status().Servers["mail"].State == "needs-login" })
}

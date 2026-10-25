package downstream

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vsem-azamat/mcp-gate/internal/oauth"
	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

func oauthOptions(t *testing.T, srv *testkit.OAuthServer, store *oauth.Store) Options {
	t.Helper()
	hc := oauth.NewHTTPClient()
	t.Cleanup(hc.CloseIdleConnections)
	src := oauth.NewSource(oauth.SourceOptions{Name: "fake", ServerURL: srv.URL(), Store: store, HTTPClient: hc})
	return fast(Options{Name: "fake", HTTP: &HTTP{URL: srv.URL(), OAuth: src}})
}

func TestOAuthNeedsLoginThenConnects(t *testing.T) {
	t.Parallel()
	srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{})
	store := oauth.NewStore(t.TempDir())
	s := start(t, oauthOptions(t, srv, store))
	st := waitFor(t, s, "needs-login", func(st Status) bool { return st.State == NeedsLogin })
	if !strings.Contains(st.LastError, "mcp-gate auth login <config> fake") || !strings.Contains(st.LastError, "not logged in") {
		t.Errorf("last error = %q", st.LastError)
	}
	if srv.Rejected() != 0 {
		t.Errorf("%d requests were sent without a grant", srv.Rejected())
	}
	var nr *NotReadyError
	if _, err := callTool(t, s, "echo", map[string]any{"text": "x"}); !errors.As(err, &nr) || nr.State != NeedsLogin {
		t.Errorf("call while needing a login: %v", err)
	}
	if st.Restarts != 0 {
		t.Errorf("restarts = %d while waiting for a login", st.Restarts)
	}

	srv.Login(t, store, "fake")
	waitReady(t, s)
	mustEcho(t, s)
}

func TestOAuthRevokedGrantNeedsLogin(t *testing.T) {
	t.Parallel()
	srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{})
	store := oauth.NewStore(t.TempDir())
	g := srv.Login(t, store, "fake")
	o := oauthOptions(t, srv, store)
	o.ProbeInterval = 30 * time.Millisecond
	s := start(t, o)
	waitReady(t, s)
	mustEcho(t, s)
	srv.RevokeAll()
	st := waitFor(t, s, "needs-login", func(st Status) bool { return st.State == NeedsLogin })
	if !strings.Contains(st.LastError, "invalid_grant") {
		t.Errorf("last error = %q", st.LastError)
	}
	for _, secret := range []string{g.AccessToken, g.RefreshToken} {
		if strings.Contains(st.LastError, secret) {
			t.Error("a token appears in the last error")
		}
	}
}

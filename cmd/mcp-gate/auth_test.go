package main

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vsem-azamat/mcp-gate/internal/oauth"
	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

// promptWriter collects output and hands over the authorization URL once it is printed.
type promptWriter struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	url  chan string
	sent bool
}

var authURLRE = regexp.MustCompile(`(?m)^  (http\S+)$`)

func (w *promptWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	if m := authURLRE.FindStringSubmatch(w.buf.String()); m != nil && !w.sent && strings.HasSuffix(w.buf.String(), "Address: ") {
		w.sent = true
		w.url <- m[1]
	}
	return len(p), nil
}

func (w *promptWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func oauthConfig(t *testing.T, srv *testkit.OAuthServer) string {
	t.Helper()
	return writeFile(t, "gate.yaml", "version: 1\nauth: {tokens: {t: secret}}\nservers:\n"+
		"  mail:\n    http: {url: "+quote(srv.URL())+", oauth: {}}\n"+
		"  local:\n    http: {url: 'https://local.example.com/mcp'}\n")
}

// playLogin runs auth login, playing the user in the browser.
func playLogin(t *testing.T, srv *testkit.OAuthServer, path, stateDir string) (int, string, string) {
	t.Helper()
	pr, pw := io.Pipe()
	old := stdin
	stdin = pr
	t.Cleanup(func() { stdin = old })
	out := &promptWriter{url: make(chan string, 1)}
	var stderr bytes.Buffer
	done := make(chan int)
	go func() {
		done <- run(t.Context(), []string{"auth", "login", "-state-dir", stateDir, path, "mail"}, noEnv, out, &stderr)
	}()
	select {
	case u := <-out.url:
		_, _ = io.WriteString(pw, srv.Approve(t, u)+"\n")
	case code := <-done:
		t.Fatalf("auth login exited %d before asking: %s %s", code, out.String(), stderr.String())
	case <-time.After(20 * time.Second):
		t.Fatal("auth login did not ask for the address")
	}
	code := <-done
	_ = pw.Close()
	return code, out.String(), stderr.String()
}

func TestAuthLoginStatusLogout(t *testing.T) {
	srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{})
	path := oauthConfig(t, srv)
	state := t.TempDir()

	r := runCmd(t, noEnv, "auth", "status", "-state-dir", state, path)
	if r.code != exitTrouble || !strings.Contains(r.stdout, "mail: needs login: not logged in") || strings.Contains(r.stdout, "local") {
		t.Errorf("status before login = %+v", r)
	}
	r = runCmd(t, noEnv, "check", "-connect", "-state-dir", state, path)
	if r.code != exitTrouble || !strings.Contains(r.stdout, "mail: OAuth login required (not logged in): run mcp-gate auth login <config> mail") {
		t.Errorf("check -connect before login = %+v", r)
	}

	code, out, stderr := playLogin(t, srv, path, state)
	if code != exitOK || !strings.Contains(out, "Registered an OAuth client") || !strings.Contains(out, "Logged in to mail: access token valid for 1h0m0s, with a refresh token.") {
		t.Fatalf("auth login = %d\n%s\n%s", code, out, stderr)
	}
	g, err := oauth.NewStore(state).Load("mail")
	if err != nil || g == nil {
		t.Fatalf("no grant saved: %v", err)
	}
	if strings.Contains(out+stderr, g.AccessToken) || strings.Contains(out+stderr, g.RefreshToken) {
		t.Error("auth login printed a token")
	}

	r = runCmd(t, noEnv, "auth", "status", "-state-dir", state, path)
	if r.code != exitOK || !regexp.MustCompile(`mail: logged in \(registered client, since \S+\): access token valid for 1h0m0s, with a refresh token`).MatchString(r.stdout) {
		t.Errorf("status after login = %+v", r)
	}
	if strings.Contains(r.stdout, g.AccessToken) {
		t.Error("status printed a token")
	}

	r = runCmd(t, noEnv, "auth", "logout", "-state-dir", state, path, "mail")
	if r.code != exitOK || !strings.Contains(r.stdout, "Logged out of mail: its grant is deleted. The authorization server offers no revocation endpoint") {
		t.Errorf("logout = %+v", r)
	}
	if _, err := os.Stat(filepath.Join(state, "oauth", "mail.json")); !os.IsNotExist(err) {
		t.Errorf("the grant file is still there: %v", err)
	}
	r = runCmd(t, noEnv, "auth", "logout", "-state-dir", state, path, "mail")
	if r.code != exitOK || !strings.Contains(r.stdout, "was not logged in") {
		t.Errorf("second logout = %+v", r)
	}
}

func TestAuthLogoutRevokes(t *testing.T) {
	srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{Revocation: true})
	path := oauthConfig(t, srv)
	state := t.TempDir()
	if code, out, stderr := playLogin(t, srv, path, state); code != exitOK {
		t.Fatalf("auth login = %d\n%s\n%s", code, out, stderr)
	}
	g, err := oauth.NewStore(state).Load("mail")
	if err != nil || g == nil || g.RefreshToken == "" {
		t.Fatalf("grant = %+v, %v", g, err)
	}
	r := runCmd(t, noEnv, "auth", "logout", "-state-dir", state, path, "mail")
	if r.code != exitOK || !strings.Contains(r.stdout, "Logged out of mail: its grant is deleted. The authorization server revoked it.") || r.stderr != "" {
		t.Errorf("logout = %+v", r)
	}
	if srv.Valid(g.RefreshToken) || srv.Valid(g.AccessToken) {
		t.Error("the authorization server still honours the grant's tokens")
	}
	revs := srv.Revocations()
	if len(revs) != 2 || revs[0].Get("token_type_hint") != "refresh_token" || revs[1].Get("token_type_hint") != "access_token" || revs[0].Get("client_id") != g.ClientID {
		t.Errorf("revocation requests = %v", revs)
	}

	// A revocation that fails is reported, and the grant is deleted all the same.
	if code, out, stderr := playLogin(t, srv, path, state); code != exitOK {
		t.Fatalf("second auth login = %d\n%s\n%s", code, out, stderr)
	}
	g, _ = oauth.NewStore(state).Load("mail")
	srv.RefuseRevocation(http.StatusServiceUnavailable)
	r = runCmd(t, noEnv, "auth", "logout", "-state-dir", state, path, "mail")
	if r.code != exitOK || !strings.Contains(r.stdout, "Revoking it at the authorization server failed") ||
		!strings.Contains(r.stderr, "the revocation endpoint answered 503") {
		t.Errorf("logout with a failing revocation = %+v", r)
	}
	if strings.Contains(r.stdout+r.stderr, g.RefreshToken) || strings.Contains(r.stdout+r.stderr, g.AccessToken) {
		t.Error("logout printed a token")
	}
	if _, err := os.Stat(filepath.Join(state, "oauth", "mail.json")); !os.IsNotExist(err) {
		t.Errorf("the grant file is still there: %v", err)
	}
}

func TestAuthUsage(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "gate.yaml", "version: 1\nauth: {tokens: {t: secret}}\nservers:\n  local:\n    http: {url: 'https://local.example.com/mcp'}\n")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"auth"}, "Usage: mcp-gate auth"},
		{[]string{"auth", "bogus"}, `unknown command "bogus"`},
		{[]string{"auth", "login", "-state-dir", "/x", path}, "name the config file and the server"},
		{[]string{"auth", "status", path}, "no state directory"},
		{[]string{"auth", "login", "-state-dir", "/x", path, "local"}, `no HTTP server "local" with an oauth block`},
	} {
		r := runCmd(t, noEnv, tc.args...)
		if r.code != exitUsage || !strings.Contains(r.stderr, tc.want) {
			t.Errorf("%v = %+v, want %q", tc.args, r, tc.want)
		}
	}
	r := runCmd(t, noEnv, "auth", "status", "-state-dir", t.TempDir(), path)
	if r.code != exitOK || r.stdout != "No server uses OAuth.\n" {
		t.Errorf("status without OAuth servers = %+v", r)
	}
}

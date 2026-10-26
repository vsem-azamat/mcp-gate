package oauth_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.uber.org/goleak"

	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/oauth"
	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func httpClient(t *testing.T) *http.Client {
	t.Helper()
	c := oauth.NewHTTPClient()
	t.Cleanup(c.CloseIdleConnections)
	return c
}

func defaults(o config.OAuth) config.OAuth {
	if o.RedirectURL == "" {
		o.RedirectURL = config.DefaultRedirectURL
	}
	return o
}

// login runs a whole login against srv as the user would, and returns the grant.
func login(t *testing.T, srv *testkit.OAuthServer, conf config.OAuth, prev *oauth.Grant) *oauth.Grant {
	t.Helper()
	p, err := oauth.BeginLogin(t.Context(), oauth.LoginOptions{
		Name: "notes", ServerURL: srv.URL(), Config: defaults(conf), ClientName: "mcp-gate (notes)",
		Previous: prev, HTTPClient: httpClient(t),
	})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	g, err := p.Complete(t.Context(), srv.Approve(t, p.AuthURL))
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	return g
}

// listTools connects to srv with src authorizing the requests and lists its tools.
func listTools(ctx context.Context, t *testing.T, url string, src *oauth.Source) (int, error) {
	t.Helper()
	hc := &http.Client{Transport: &http.Transport{}}
	defer hc.CloseIdleConnections()
	c := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil)
	cs, err := c.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: url, HTTPClient: hc, OAuthHandler: src}, nil)
	if err != nil {
		return 0, err
	}
	defer cs.Close()
	n := 0
	for _, err := range cs.Tools(ctx, nil) {
		if err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func newSource(t *testing.T, store *oauth.Store, url string, logs *bytes.Buffer, now func() time.Time) *oauth.Source {
	t.Helper()
	var logger *slog.Logger
	if logs != nil {
		logger = slog.New(slog.NewTextHandler(logs, nil))
	}
	return oauth.NewSource(oauth.SourceOptions{Name: "notes", ServerURL: url, Store: store, HTTPClient: httpClient(t), Logger: logger, Now: now})
}

func TestLoginWithDiscoveryAndRegistration(t *testing.T) {
	srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{Fake: testkit.Fake{Name: "notes"}, Scopes: []string{"read", "write"}, OfflineAccess: true, Iss: true})
	g := login(t, srv, config.OAuth{}, nil)
	q := srv.LastAuthorize()
	if q.Get("code_challenge_method") != "S256" || q.Get("resource") != srv.URL() || q.Get("scope") != "read write offline_access" {
		t.Errorf("authorization request = %v", q)
	}
	if len(q.Get("state")) < 20 {
		t.Errorf("state %q is too short", q.Get("state"))
	}
	if srv.Registrations() != 1 || !g.Registered || g.ClientSecret != "" || g.AuthStyle != oauth.AuthInParams {
		t.Errorf("registration: %d, grant %+v", srv.Registrations(), g)
	}
	if g.RefreshToken == "" || g.Issuer != srv.Issuer() || g.ServerURL != srv.URL() || g.Expiry.IsZero() {
		t.Errorf("grant = %+v", g)
	}
	tf := srv.LastToken()
	if tf.Get("resource") != srv.URL() || tf.Get("code_verifier") == "" || tf.Get("redirect_uri") != config.DefaultRedirectURL {
		t.Errorf("token request = %v", tf)
	}

	store := oauth.NewStore(t.TempDir())
	if err := store.Save("notes", g); err != nil {
		t.Fatal(err)
	}
	src := newSource(t, store, srv.URL(), nil, nil)
	if src.LoginRequired() {
		t.Fatalf("LoginRequired after login: %s", src.Reason())
	}
	if n, err := listTools(t.Context(), t, srv.URL(), src); err != nil || n == 0 {
		t.Fatalf("listing tools: %d, %v", n, err)
	}

	// A second login reuses the registered client.
	login(t, srv, config.OAuth{}, g)
	if srv.Registrations() != 1 {
		t.Errorf("a second login registered again")
	}
}

func TestLoginWithConfiguredClientAndMetadataURL(t *testing.T) {
	srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{Fake: testkit.Fake{Name: "notes"}, IssuerPath: "/tenant", NoRegistration: true})
	conf := config.OAuth{
		ClientID: testkit.FixedClientID, ClientSecret: testkit.FixedClientSecret,
		Scopes: []string{"mail.read"}, AuthServerMetadataURL: srv.MetadataURL(),
	}
	g := login(t, srv, conf, nil)
	if q := srv.LastAuthorize(); q.Get("scope") != "mail.read" || q.Get("client_id") != testkit.FixedClientID {
		t.Errorf("authorization request = %v", q)
	}
	if g.Registered || g.ClientSecret != "" || g.AuthStyle != oauth.AuthInHeader || g.Issuer != srv.Issuer() {
		t.Errorf("grant = %+v", g)
	}
	if tf := srv.LastToken(); tf.Get("client_secret") != "" {
		t.Error("the secret went in the form, not the header")
	}

	// The configured secret refreshes the token.
	store := oauth.NewStore(t.TempDir())
	if err := store.Save("notes", g); err != nil {
		t.Fatal(err)
	}
	later := func() time.Time { return time.Now().Add(2 * time.Hour) }
	src := oauth.NewSource(oauth.SourceOptions{
		Name: "notes", ServerURL: srv.URL(), ClientID: testkit.FixedClientID, ClientSecret: testkit.FixedClientSecret,
		Store: store, HTTPClient: httpClient(t), Now: later,
	})
	if _, err := src.Token(); err != nil || srv.Refreshes() != 1 {
		t.Fatalf("refresh with the configured client: %v, %d refreshes", err, srv.Refreshes())
	}
}

func TestLoginDiscoveryFallbacks(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts testkit.OAuthOptions
	}{
		{"no challenge", testkit.OAuthOptions{NoChallenge: true}},
		{"no resource metadata", testkit.OAuthOptions{NoResourceMetadata: true, NoChallenge: true}},
		{"issuer with a path", testkit.OAuthOptions{IssuerPath: "/tenant"}},
		{"endpoint with a trailing slash", testkit.OAuthOptions{IssuerPath: "/mcp", TrailingSlash: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.Fake = testkit.Fake{Name: "notes"}
			srv := testkit.NewOAuthServer(t, tc.opts)
			g := login(t, srv, config.OAuth{}, nil)
			if g.Issuer != srv.Issuer() {
				t.Errorf("issuer %q, want %q", g.Issuer, srv.Issuer())
			}
		})
	}
}

func TestLoginRejects(t *testing.T) {
	srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{Fake: testkit.Fake{Name: "notes"}, Iss: true})
	begin := func(t *testing.T, conf config.OAuth) *oauth.Pending {
		t.Helper()
		p, err := oauth.BeginLogin(t.Context(), oauth.LoginOptions{Name: "notes", ServerURL: srv.URL(), Config: defaults(conf), HTTPClient: httpClient(t)})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := begin(t, config.OAuth{})
	redirect := srv.Approve(t, p.AuthURL)
	other := begin(t, config.OAuth{})
	for _, tc := range []struct{ name, pasted, want string }{
		{"empty", "  ", "nothing was pasted"},
		{"bare code", "abc", "paste the whole address"},
		{"other host", strings.Replace(redirect, "localhost:8090", "evil.example.com", 1), "not the redirect URL"},
		{"wrong state", strings.Replace(redirect, "state=", "state=x", 1), "state does not match"},
		{"other login", srv.Approve(t, other.AuthURL), "state does not match"},
		{"no iss", strings.Replace(redirect, "iss=", "x=", 1), "lacks the issuer"},
		{"other iss", strings.Replace(redirect, "iss=", "iss=https%3A%2F%2Fevil.example.com&y=", 1), "another issuer"},
		{"error", config.DefaultRedirectURL + "?error=access_denied&error_description=no%0Athanks", "refused: access_denied: nothanks"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := p.Complete(t.Context(), tc.pasted)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Complete = %v, want %q", err, tc.want)
			}
		})
	}
	// The query alone is accepted.
	_, query, _ := strings.Cut(redirect, "?")
	if _, err := p.Complete(t.Context(), "?"+query); err != nil {
		t.Errorf("the query alone: %v", err)
	}
	// A code is used once.
	if _, err := p.Complete(t.Context(), redirect); err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("a used code: %v", err)
	}
}

func TestLoginRejectsMetadata(t *testing.T) {
	t.Run("issuer mismatch", func(t *testing.T) {
		srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{Fake: testkit.Fake{Name: "notes"}, MetadataIssuer: "https://evil.example.com"})
		_, err := oauth.BeginLogin(t.Context(), oauth.LoginOptions{Name: "notes", ServerURL: srv.URL(), Config: defaults(config.OAuth{}), HTTPClient: httpClient(t)})
		if err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Errorf("BeginLogin = %v", err)
		}
	})
	t.Run("metadata URL of another issuer", func(t *testing.T) {
		srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{Fake: testkit.Fake{Name: "notes"}})
		conf := defaults(config.OAuth{AuthServerMetadataURL: srv.MetadataURL() + "/other"})
		_, err := oauth.BeginLogin(t.Context(), oauth.LoginOptions{Name: "notes", ServerURL: srv.URL(), Config: conf, HTTPClient: httpClient(t)})
		if err == nil || !strings.Contains(err.Error(), "does not list") {
			t.Errorf("BeginLogin = %v", err)
		}
	})
	t.Run("no registration", func(t *testing.T) {
		srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{Fake: testkit.Fake{Name: "notes"}, NoRegistration: true})
		_, err := oauth.BeginLogin(t.Context(), oauth.LoginOptions{Name: "notes", ServerURL: srv.URL(), Config: defaults(config.OAuth{}), HTTPClient: httpClient(t)})
		if err == nil || !strings.Contains(err.Error(), "clientID") {
			t.Errorf("BeginLogin = %v", err)
		}
	})
	t.Run("plain http", func(t *testing.T) {
		_, err := oauth.BeginLogin(t.Context(), oauth.LoginOptions{Name: "notes", ServerURL: "http://mcp.example.com/mcp", Config: defaults(config.OAuth{}), HTTPClient: httpClient(t)})
		if err == nil {
			t.Error("BeginLogin accepted a plain http server")
		}
	})
}

func TestRefresh(t *testing.T) {
	srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{Fake: testkit.Fake{Name: "notes"}, RotateRefresh: true})
	g := login(t, srv, config.OAuth{}, nil)
	store := oauth.NewStore(t.TempDir())
	if err := store.Save("notes", g); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	src := newSource(t, store, srv.URL(), nil, clock)
	tok, err := src.Token()
	if err != nil || tok.AccessToken != g.AccessToken || srv.Refreshes() != 0 {
		t.Fatalf("Token before expiry: %v, %d refreshes", err, srv.Refreshes())
	}

	mu.Lock()
	now = now.Add(59*time.Minute + 30*time.Second) // within a minute of the expiry
	mu.Unlock()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, err := src.Token(); err != nil {
				t.Errorf("Token: %v", err)
			}
		})
	}
	wg.Wait()
	if srv.Refreshes() != 1 {
		t.Errorf("%d refreshes for concurrent calls, want 1", srv.Refreshes())
	}
	saved, err := store.Load("notes")
	if err != nil || saved.RefreshToken == g.RefreshToken || saved.AccessToken == g.AccessToken || srv.LastToken().Get("resource") != srv.URL() {
		t.Fatalf("the rotated grant was not saved: %v", err)
	}

	// Another process using the same store adopts the refreshed grant instead of refreshing.
	other := newSource(t, store, srv.URL(), nil, clock)
	if tok, err := other.Token(); err != nil || tok.AccessToken != saved.AccessToken || srv.Refreshes() != 1 {
		t.Errorf("second source: %v, %d refreshes", err, srv.Refreshes())
	}
}

func TestUnauthorizedRefreshesOnce(t *testing.T) {
	srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{Fake: testkit.Fake{Name: "notes"}})
	store := oauth.NewStore(t.TempDir())
	if err := store.Save("notes", login(t, srv, config.OAuth{}, nil)); err != nil {
		t.Fatal(err)
	}
	src := newSource(t, store, srv.URL(), nil, nil)
	srv.ExpireAccess() // the server forgets the token before its expiry
	if n, err := listTools(t.Context(), t, srv.URL(), src); err != nil || n == 0 {
		t.Fatalf("after a 401: %d, %v", n, err)
	}
	if srv.Refreshes() != 1 || src.LoginRequired() {
		t.Errorf("%d refreshes, login required %v", srv.Refreshes(), src.LoginRequired())
	}
}

func TestRevokedGrantNeedsLogin(t *testing.T) {
	srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{Fake: testkit.Fake{Name: "notes"}})
	g := login(t, srv, config.OAuth{}, nil)
	store := oauth.NewStore(t.TempDir())
	if err := store.Save("notes", g); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	src := newSource(t, store, srv.URL(), &logs, nil)
	srv.RevokeAll()
	_, err := listTools(t.Context(), t, srv.URL(), src)
	if err == nil {
		t.Fatal("connected with a revoked grant")
	}
	if !src.LoginRequired() || !strings.Contains(src.Reason(), "invalid_grant") {
		t.Fatalf("LoginRequired %v, reason %q", src.LoginRequired(), src.Reason())
	}
	if _, err := src.Token(); !errors.Is(err, oauth.ErrLoginRequired) {
		t.Errorf("Token = %v, want ErrLoginRequired", err)
	}
	for _, secret := range []string{g.AccessToken, g.RefreshToken} {
		if strings.Contains(logs.String(), secret) || strings.Contains(src.Reason(), secret) || strings.Contains(err.Error(), secret) {
			t.Errorf("a token appears in the logs, the reason or the error")
		}
	}
	requests := srv.TokenRequests()
	_, _ = src.Token()
	_ = src.LoginRequired()
	if srv.TokenRequests() != requests {
		t.Error("a rejected grant was tried again")
	}

	// A new login is picked up without a restart.
	if err := store.Save("notes", login(t, srv, config.OAuth{}, g)); err != nil {
		t.Fatal(err)
	}
	if src.LoginRequired() {
		t.Fatalf("still login required after a new login: %s", src.Reason())
	}
	if n, err := listTools(t.Context(), t, srv.URL(), src); err != nil || n == 0 {
		t.Errorf("after a new login: %d, %v", n, err)
	}
}

func TestExpiredWithoutRefreshToken(t *testing.T) {
	srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{Fake: testkit.Fake{Name: "notes"}, NoRefreshToken: true})
	store := oauth.NewStore(t.TempDir())
	if err := store.Save("notes", login(t, srv, config.OAuth{}, nil)); err != nil {
		t.Fatal(err)
	}
	src := newSource(t, store, srv.URL(), nil, func() time.Time { return time.Now().Add(2 * time.Hour) })
	if _, err := src.Token(); !errors.Is(err, oauth.ErrLoginRequired) || !strings.Contains(src.Reason(), "no refresh token") {
		t.Errorf("Token = %v, reason %q", err, src.Reason())
	}
}

func TestGrantBinding(t *testing.T) {
	srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{Fake: testkit.Fake{Name: "notes"}})
	store := oauth.NewStore(t.TempDir())
	if err := store.Save("notes", login(t, srv, config.OAuth{}, nil)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		opts oauth.SourceOptions
		want string
	}{
		{"other URL", oauth.SourceOptions{ServerURL: "https://other.example.com/mcp"}, "another server URL"},
		{"configured client", oauth.SourceOptions{ServerURL: srv.URL(), ClientID: "configured"}, "another OAuth client"},
		{"no store", oauth.SourceOptions{ServerURL: srv.URL(), Store: nil}, "no state directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.Name, tc.opts.HTTPClient = "notes", httpClient(t)
			if tc.name != "no store" {
				tc.opts.Store = store
			}
			src := oauth.NewSource(tc.opts)
			if !src.LoginRequired() || !strings.Contains(src.Reason(), tc.want) {
				t.Errorf("LoginRequired %v, reason %q", src.LoginRequired(), src.Reason())
			}
		})
	}
	// Logging out is noticed.
	src := newSource(t, store, srv.URL(), nil, nil)
	if src.LoginRequired() {
		t.Fatal(src.Reason())
	}
	if ok, err := store.Delete("notes"); !ok || err != nil {
		t.Fatalf("Delete = %v, %v", ok, err)
	}
	if _, err := src.Token(); !errors.Is(err, oauth.ErrLoginRequired) {
		t.Errorf("Token after logout = %v", err)
	}
}

func TestStore(t *testing.T) {
	state := t.TempDir()
	store := oauth.NewStore(state)
	if g, err := store.Load("notes"); g != nil || err != nil {
		t.Fatalf("Load of nothing = %v, %v", g, err)
	}
	g := &oauth.Grant{ //nolint:gosec // made-up credentials
		Version: oauth.GrantVersion, ServerURL: "https://mcp.example.com/mcp", TokenEndpoint: "https://auth.example.com/token",
		ClientID: "c", AuthStyle: oauth.AuthInParams, AccessToken: "secret-access", ObtainedAt: time.Now(),
	}
	if err := store.Save("notes", g); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(state, "oauth")
	fi, err := os.Stat(dir)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("directory mode %v, %v", fi.Mode(), err)
	}
	fi, err = os.Stat(filepath.Join(dir, "notes.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode %v, %v", fi.Mode(), err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), "tmp") {
			t.Errorf("temporary file left: %s", e.Name())
		}
	}
	if back, err := store.Load("notes"); err != nil || back.AccessToken != "secret-access" {
		t.Fatalf("Load = %+v, %v", back, err)
	}

	path := filepath.Join(dir, "notes.json")
	if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // the test widens the mode on purpose
		t.Fatal(err)
	}
	if _, err := store.Load("notes"); err == nil || strings.Contains(err.Error(), "secret-access") {
		t.Errorf("Load of a world-readable file = %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load("notes"); err == nil {
		t.Error("Load followed a symbolic link")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load("notes"); err == nil {
		t.Error("Load accepted an unknown key")
	}
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // the test widens the mode on purpose
		t.Fatal(err)
	}
	if err := store.Save("notes", g); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("Save left the directory %v", fi.Mode())
	}
}

// A logout while a refresh waits for the lock wins: the refresh does not write the grant back.
func TestRefreshAfterLogout(t *testing.T) {
	srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{Fake: testkit.Fake{Name: "notes"}})
	store := oauth.NewStore(t.TempDir())
	if err := store.Save("notes", login(t, srv, config.OAuth{}, nil)); err != nil {
		t.Fatal(err)
	}
	later := func() time.Time { return time.Now().Add(2 * time.Hour) } // token expired
	src := newSource(t, store, srv.URL(), nil, later)
	unlock, err := store.Lock("notes") // "auth logout" holds the lock
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() { _, _ = src.Token() }) // stats the file, then waits on the lock
	time.Sleep(200 * time.Millisecond)
	if ok, err := store.Delete("notes"); !ok || err != nil {
		t.Fatal(ok, err)
	}
	unlock()
	wg.Wait()
	if g, _ := store.Load("notes"); g != nil {
		t.Errorf("logout undone: the grant file was written again by a refresh")
	}
}

// A new login while a refresh waits for the lock wins over the old grant.
func TestRefreshAfterNewLogin(t *testing.T) {
	srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{Fake: testkit.Fake{Name: "notes"}})
	store := oauth.NewStore(t.TempDir())
	if err := store.Save("notes", login(t, srv, config.OAuth{}, nil)); err != nil {
		t.Fatal(err)
	}
	fresh := login(t, srv, config.OAuth{}, nil) // registers a second client
	later := func() time.Time { return time.Now().Add(2 * time.Hour) }
	src := newSource(t, store, srv.URL(), nil, func() time.Time { return later().Add(-3 * time.Hour) })
	_ = src.LoginRequired()
	src2 := newSource(t, store, srv.URL(), nil, later)
	unlock, err := store.Lock("notes")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() { _, _ = src2.Token() })
	time.Sleep(200 * time.Millisecond)
	fresh.Expiry = time.Now().Add(10 * time.Hour)
	if err := store.Save("notes", fresh); err != nil {
		t.Fatal(err)
	}
	unlock()
	wg.Wait()
	g, _ := store.Load("notes")
	if g == nil || g.ClientID != fresh.ClientID {
		t.Errorf("the fresh login was overwritten by the old client's refresh")
	}
}

// A token that lives a minute or less is not refreshed on every request.
func TestShortLivedTokens(t *testing.T) {
	srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{Fake: testkit.Fake{Name: "notes"}, AccessTTL: 50 * time.Second})
	store := oauth.NewStore(t.TempDir())
	if err := store.Save("notes", login(t, srv, config.OAuth{}, nil)); err != nil {
		t.Fatal(err)
	}
	src := newSource(t, store, srv.URL(), nil, nil)
	for range 5 {
		if _, err := src.Token(); err != nil {
			t.Fatal(err)
		}
	}
	if srv.Refreshes() > 1 {
		t.Errorf("%d refreshes for 5 back-to-back Token calls", srv.Refreshes())
	}
}

// A 401 to a token a 401 refresh obtained, once, does not reject the grant.
func TestUnrelated401s(t *testing.T) {
	srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{Fake: testkit.Fake{Name: "notes"}})
	store := oauth.NewStore(t.TempDir())
	if err := store.Save("notes", login(t, srv, config.OAuth{}, nil)); err != nil {
		t.Fatal(err)
	}
	src := newSource(t, store, srv.URL(), nil, nil)
	srv.ExpireAccess()
	if _, err := listTools(t.Context(), t, srv.URL(), src); err != nil {
		t.Fatal(err)
	}
	// the token works for a while...
	if _, err := listTools(t.Context(), t, srv.URL(), src); err != nil {
		t.Fatal(err)
	}
	srv.ExpireAccess() // e.g. it expired without expires_in, or the server restarted
	_, err := listTools(t.Context(), t, srv.URL(), src)
	if err != nil || src.LoginRequired() {
		t.Errorf("second, unrelated 401 killed the grant: %v, reason %q", err, src.Reason())
	}
}

// A server that answers 401 to every token rejects the grant after a few refreshes; a 403
// refreshes nothing.
func TestServerRefusing(t *testing.T) {
	srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{Fake: testkit.Fake{Name: "notes"}})
	store := oauth.NewStore(t.TempDir())
	if err := store.Save("notes", login(t, srv, config.OAuth{}, nil)); err != nil {
		t.Fatal(err)
	}
	src := newSource(t, store, srv.URL(), nil, nil)
	srv.Refuse(http.StatusForbidden)
	if _, err := listTools(t.Context(), t, srv.URL(), src); err == nil {
		t.Error("a 403 did not fail")
	}
	if srv.Refreshes() != 0 || src.LoginRequired() {
		t.Errorf("a 403: %d refreshes, login required %v", srv.Refreshes(), src.LoginRequired())
	}
	srv.Refuse(http.StatusUnauthorized)
	for i := 0; i < 5 && !src.LoginRequired(); i++ {
		_, _ = listTools(t.Context(), t, srv.URL(), src)
	}
	if !src.LoginRequired() || !strings.Contains(src.Reason(), "rejects the grant") || srv.Refreshes() > 3 {
		t.Errorf("login required %v (%q) after %d refreshes", src.LoginRequired(), src.Reason(), srv.Refreshes())
	}
}

// A server that rejects every token is noticed even when the attempts are spaced like the
// longest backoff.
func TestSpacedRefusals(t *testing.T) {
	srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{Fake: testkit.Fake{Name: "notes"}, AccessTTL: 10 * time.Hour})
	store := oauth.NewStore(t.TempDir())
	if err := store.Save("notes", login(t, srv, config.OAuth{}, nil)); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	src := newSource(t, store, srv.URL(), nil, clock)
	srv.Refuse(http.StatusUnauthorized)
	for i := 0; i < 10 && !src.LoginRequired(); i++ {
		_, _ = listTools(t.Context(), t, srv.URL(), src)
		mu.Lock()
		now = now.Add(31 * time.Second)
		mu.Unlock()
	}
	if !src.LoginRequired() || srv.Refreshes() > 3 {
		t.Errorf("login required %v after %d refreshes", src.LoginRequired(), srv.Refreshes())
	}
}

func TestExpiresInForms(t *testing.T) {
	for _, tc := range []struct {
		ttl  string
		want bool
	}{{"3600", true}, {"3600.0", true}, {`"3600"`, true}, {"0", false}, {"null", false}, {`"soon"`, false}, {"-5", false}} {
		srv := testkit.NewOAuthServer(t, testkit.OAuthOptions{Fake: testkit.Fake{Name: "notes"}, ExpiresIn: tc.ttl})
		g := login(t, srv, config.OAuth{}, nil)
		if !g.Expiry.IsZero() != tc.want {
			t.Errorf("expires_in %s: expiry %v", tc.ttl, g.Expiry)
		}
	}
}

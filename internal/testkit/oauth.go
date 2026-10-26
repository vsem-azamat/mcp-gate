package testkit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/oauth"
)

// Credentials of the client a fake authorization server knows without registration.
const (
	FixedClientID     = "fixed-client"
	FixedClientSecret = "fixed-client-secret-0123456789"
)

// OAuthOptions configure a fake OAuth-protected server.
type OAuthOptions struct {
	// Fake is the MCP server behind the authorization.
	Fake Fake
	// AccessTTL is the lifetime the token endpoint gives access tokens; zero is an hour.
	AccessTTL time.Duration
	// IssuerPath puts the issuer under a path, such as /tenant.
	IssuerPath string
	// NoRegistration leaves out dynamic client registration; only FixedClientID is known.
	NoRegistration bool
	// NoResourceMetadata serves no protected resource metadata, as servers of 2025-03-26.
	NoResourceMetadata bool
	// NoChallenge answers 401 without a WWW-Authenticate header.
	NoChallenge bool
	// Scopes are the scopes the resource metadata lists.
	Scopes []string
	// OfflineAccess lists offline_access among the authorization server's scopes.
	OfflineAccess bool
	// RotateRefresh issues a new refresh token on every refresh and voids the old one.
	RotateRefresh bool
	// Iss adds the issuer to the authorization response (RFC 9207) and says so in the metadata.
	Iss bool
	// NoRefreshToken issues no refresh tokens.
	NoRefreshToken bool
	// ExpiresIn, if set, is the raw JSON of expires_in in token answers, in place of the TTL.
	ExpiresIn string
	// MetadataIssuer, if set, is the issuer the metadata claims, in place of the real one.
	MetadataIssuer string
	// TrailingSlash serves the MCP endpoint at /mcp/, with a challenge naming resource metadata
	// at a URL that redirects to the one without the slash, and that metadata naming /mcp
	// without the slash as the resource.
	TrailingSlash bool
}

// OAuthServer is a fake MCP server behind OAuth on one loopback listener: protected resource
// metadata, an authorization server with dynamic registration, PKCE and refresh tokens, and the
// MCP endpoint, which takes only the access tokens it issued. It is closed when the test ends.
type OAuthServer struct {
	srv  *httptest.Server
	opts OAuthOptions

	mu            sync.Mutex
	clients       map[string]oauthClient
	codes         map[string]oauthCode
	access        map[string]time.Time // access token to expiry
	refresh       map[string]string    // refresh token to client
	n             int
	registrations int
	refreshes     int
	tokenRequests int
	rejected      int
	refuse        int // the status the MCP endpoint answers every request with, if not zero
	lastAuthorize url.Values
	lastToken     url.Values
}

type oauthClient struct {
	secret    string
	redirects []string
}

type oauthCode struct {
	client, redirect, challenge, resource string
}

// NewOAuthServer starts a fake OAuth-protected server.
func NewOAuthServer(t testing.TB, opts OAuthOptions) *OAuthServer {
	t.Helper()
	s := &OAuthServer{
		opts: opts, clients: map[string]oauthClient{}, codes: map[string]oauthCode{},
		access: map[string]time.Time{}, refresh: map[string]string{},
	}
	stop := make(chan struct{})
	ms := newFakeServer(opts.Fake, nil, 0, stop)
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return ms }, &mcp.StreamableHTTPOptions{Stateless: true})
	mux := http.NewServeMux()
	if opts.TrailingSlash {
		mux.Handle("/mcp/", s.protect(handler))
		mux.Handle("GET /.well-known/oauth-protected-resource/mcp/", http.RedirectHandler("/.well-known/oauth-protected-resource/mcp", http.StatusTemporaryRedirect))
	} else {
		mux.Handle("/mcp", s.protect(handler))
	}
	if !opts.NoResourceMetadata {
		mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", s.resourceMetadata)
	}
	mux.HandleFunc("GET /.well-known/oauth-authorization-server"+opts.IssuerPath, s.serverMetadata)
	mux.HandleFunc("GET "+opts.IssuerPath+"/authorize", s.authorize)
	mux.HandleFunc("POST "+opts.IssuerPath+"/token", s.token)
	if !opts.NoRegistration {
		mux.HandleFunc("POST "+opts.IssuerPath+"/register", s.register)
	}
	s.clients[FixedClientID] = oauthClient{secret: FixedClientSecret, redirects: []string{"http://localhost:8090/oauth/callback"}}
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	t.Cleanup(func() { close(stop) })
	return s
}

// URL is the MCP endpoint.
func (s *OAuthServer) URL() string {
	if s.opts.TrailingSlash {
		return s.srv.URL + "/mcp/"
	}
	return s.srv.URL + "/mcp"
}

// Issuer is the authorization server's issuer.
func (s *OAuthServer) Issuer() string { return s.srv.URL + s.opts.IssuerPath }

// MetadataURL is where the authorization server's metadata is.
func (s *OAuthServer) MetadataURL() string {
	return s.srv.URL + "/.well-known/oauth-authorization-server" + s.opts.IssuerPath
}

// Approve plays the user who opens authURL and signs in: it returns the address the browser
// is redirected to.
func (s *OAuthServer) Approve(t testing.TB, authURL string) string {
	t.Helper()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer c.CloseIdleConnections()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: status %d", resp.StatusCode)
	}
	return resp.Header.Get("Location")
}

// Login runs mcp-gate's login against the server, with dynamic registration and the default
// redirect URL, and saves the grant under name in store.
func (s *OAuthServer) Login(t testing.TB, store *oauth.Store, name string) *oauth.Grant {
	t.Helper()
	hc := oauth.NewHTTPClient(s.URL())
	defer hc.CloseIdleConnections()
	p, err := oauth.BeginLogin(t.Context(), oauth.LoginOptions{
		Name: name, ServerURL: s.URL(), Config: config.OAuth{RedirectURL: config.DefaultRedirectURL}, HTTPClient: hc,
	})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	g, err := p.Complete(t.Context(), s.Approve(t, p.AuthURL))
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if err := store.Save(name, g); err != nil {
		t.Fatal(err)
	}
	return g
}

// Refuse makes the MCP endpoint answer every request with status (401 or 403), whatever its
// token; 0 serves again.
func (s *OAuthServer) Refuse(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refuse = status
}

// ExpireAccess voids every access token issued so far; refresh tokens stay valid.
func (s *OAuthServer) ExpireAccess() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.access)
}

// RevokeAll voids every access and refresh token issued so far.
func (s *OAuthServer) RevokeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.access)
	clear(s.refresh)
}

// Registrations counts dynamic client registrations.
func (s *OAuthServer) Registrations() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.registrations
}

// Refreshes counts successful refresh token grants.
func (s *OAuthServer) Refreshes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshes
}

// TokenRequests counts the requests to the token endpoint.
func (s *OAuthServer) TokenRequests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokenRequests
}

// Rejected counts MCP requests rejected with 401.
func (s *OAuthServer) Rejected() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rejected
}

// LastAuthorize returns the query of the last authorization request.
func (s *OAuthServer) LastAuthorize() url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastAuthorize
}

// LastToken returns the form of the last token request.
func (s *OAuthServer) LastToken() url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastToken
}

func (s *OAuthServer) protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		s.mu.Lock()
		exp, ok := s.access[tok]
		ok = ok && time.Now().Before(exp)
		refuse := s.refuse
		if !ok || refuse == http.StatusUnauthorized {
			ok = false
			s.rejected++
		}
		s.mu.Unlock()
		if ok && refuse != 0 {
			http.Error(w, http.StatusText(refuse), refuse)
			return
		}
		if !ok {
			if !s.opts.NoChallenge {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource%s"`, s.srv.URL, strings.TrimPrefix(s.URL(), s.srv.URL)))
			}
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(data)
}

func (s *OAuthServer) resourceMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"resource": s.srv.URL + "/mcp", "authorization_servers": []string{s.Issuer()}, "scopes_supported": s.opts.Scopes,
	})
}

func (s *OAuthServer) serverMetadata(w http.ResponseWriter, _ *http.Request) {
	issuer := s.Issuer()
	if s.opts.MetadataIssuer != "" {
		issuer = s.opts.MetadataIssuer
	}
	m := map[string]any{
		"issuer":                                         issuer,
		"authorization_endpoint":                         s.Issuer() + "/authorize",
		"token_endpoint":                                 s.Issuer() + "/token",
		"response_types_supported":                       []string{"code"},
		"code_challenge_methods_supported":               []string{"S256"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported":          []string{"none", "client_secret_basic"},
		"authorization_response_iss_parameter_supported": s.opts.Iss,
	}
	if !s.opts.NoRegistration {
		m["registration_endpoint"] = s.Issuer() + "/register"
	}
	if s.opts.OfflineAccess {
		m["scopes_supported"] = []string{"read", "offline_access"}
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *OAuthServer) register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
		AuthMethod   string   `json:"token_endpoint_auth_method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.RedirectURIs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata"})
		return
	}
	s.mu.Lock()
	s.registrations++
	id := "client-" + rand.Text()[:8]
	s.clients[id] = oauthClient{redirects: req.RedirectURIs}
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{"client_id": id, "redirect_uris": req.RedirectURIs, "token_endpoint_auth_method": "none"})
}

func (s *OAuthServer) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastAuthorize = q
	c, ok := s.clients[q.Get("client_id")]
	switch {
	case !ok || !slices.Contains(c.redirects, q.Get("redirect_uri")):
		http.Error(w, "unknown client or redirect", http.StatusBadRequest)
		return
	case q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("state") == "":
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	code := "code-" + rand.Text()
	s.codes[code] = oauthCode{client: q.Get("client_id"), redirect: q.Get("redirect_uri"), challenge: q.Get("code_challenge"), resource: q.Get("resource")}
	back := url.Values{"code": {code}, "state": {q.Get("state")}}
	if s.opts.Iss {
		back.Set("iss", s.Issuer())
	}
	w.Header().Set("Location", q.Get("redirect_uri")+"?"+back.Encode())
	w.WriteHeader(http.StatusFound)
}

func (s *OAuthServer) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	f := r.PostForm
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastToken = f
	s.tokenRequests++
	id, secret, basic := r.BasicAuth()
	if basic {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = f.Get("client_id"), f.Get("client_secret")
	}
	c, ok := s.clients[id]
	if !ok || c.secret != secret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	switch f.Get("grant_type") {
	case "authorization_code":
		code, ok := s.codes[f.Get("code")]
		delete(s.codes, f.Get("code"))
		sum := sha256.Sum256([]byte(f.Get("code_verifier")))
		if !ok || code.client != id || code.redirect != f.Get("redirect_uri") ||
			base64.RawURLEncoding.EncodeToString(sum[:]) != code.challenge || code.resource != f.Get("resource") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
		s.issue(w, id, "")
	case "refresh_token":
		rt := f.Get("refresh_token")
		if s.refresh[rt] != id {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "refresh token " + rt + " is not valid"})
			return
		}
		s.refreshes++
		if s.opts.RotateRefresh {
			delete(s.refresh, rt)
			rt = ""
		}
		s.issue(w, id, rt)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
	}
}

// issue answers with a new access token and, unless keep is set, a new refresh token.
func (s *OAuthServer) issue(w http.ResponseWriter, client, keep string) {
	ttl := s.opts.AccessTTL
	if ttl == 0 {
		ttl = time.Hour
	}
	s.n++
	at := fmt.Sprintf("at-%d-%s", s.n, rand.Text()[:6])
	s.access[at] = time.Now().Add(ttl)
	resp := map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": int(ttl.Seconds())}
	if s.opts.ExpiresIn != "" {
		resp["expires_in"] = json.RawMessage(s.opts.ExpiresIn)
	}
	if !s.opts.NoRefreshToken && keep == "" {
		rt := fmt.Sprintf("rt-%d-%s", s.n, rand.Text()[:6])
		s.refresh[rt] = client
		resp["refresh_token"] = rt
	}
	writeJSON(w, http.StatusOK, resp)
}

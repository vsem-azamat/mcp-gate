package oauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"

	"github.com/vsem-azamat/mcp-gate/internal/config"
)

// maxPasteBytes bounds the redirect address pasted at login.
const maxPasteBytes = 16 << 10

// LoginOptions describe the server to log in to.
type LoginOptions struct {
	// Name is the server's name in the config; it goes into the registered client's name.
	Name string
	// ServerURL is the server's MCP endpoint.
	ServerURL string
	// Config is the server's oauth block, with defaults applied.
	Config config.OAuth
	// ClientName is sent at dynamic registration.
	ClientName string
	// Previous is the grant kept from an earlier login, if any: its dynamically registered
	// client is reused when it is for the same authorization server and redirect URL.
	Previous *Grant
	// HTTPClient makes the requests; see NewHTTPClient.
	HTTPClient *http.Client
	// Now returns the time; nil is time.Now.
	Now func() time.Time
}

// Pending is a login waiting for the user: the URL to open, and what checks the answer.
type Pending struct {
	// AuthURL is the authorization URL the user opens in a browser.
	AuthURL string
	// Registered reports that a client was registered dynamically for this login.
	Registered bool

	opts     LoginOptions
	asm      *oauthex.AuthServerMeta
	resource string
	scopes   []string
	client   client
	state    string
	verifier string
}

// BeginLogin discovers the server's authorization server, registers a client when none is
// configured, and returns the authorization URL, with PKCE (S256) and a random state.
func BeginLogin(ctx context.Context, opts LoginOptions) (*Pending, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.HTTPClient == nil {
		return nil, errors.New("oauth: no HTTP client")
	}
	if !config.SecureURL(opts.ServerURL) {
		return nil, errors.New("the server URL must be https, or http on a loopback address")
	}
	d, err := discover(ctx, opts)
	if err != nil {
		return nil, err
	}
	p := &Pending{opts: opts, asm: d.asm, resource: d.resource, scopes: d.scopes}
	if p.client, p.Registered, err = resolveClient(ctx, opts, d.asm); err != nil {
		return nil, err
	}
	p.state = rand.Text()
	p.verifier = oauth2.GenerateVerifier()
	cfg := oauth2.Config{
		ClientID:    p.client.id,
		Endpoint:    oauth2.Endpoint{AuthURL: d.asm.AuthorizationEndpoint, TokenURL: d.asm.TokenEndpoint},
		RedirectURL: opts.Config.RedirectURL,
		Scopes:      d.scopes,
	}
	p.AuthURL = cfg.AuthCodeURL(p.state, oauth2.S256ChallengeOption(p.verifier), oauth2.SetAuthURLParam("resource", d.resource))
	return p, nil
}

type discovery struct {
	asm      *oauthex.AuthServerMeta
	resource string
	scopes   []string
}

// discover finds the authorization server of a server (MCP authorization, 2025-11-25): the
// protected resource metadata named by the server's 401 challenge or at its well-known
// locations, then the authorization server's metadata, at authServerMetadataURL when it is set.
// Without protected resource metadata, the server's origin is taken as the authorization
// server, as servers of 2025-03-26 have it. The SDK checks that the documents name the resource
// and issuer they were fetched for, and that their endpoints are https or loopback.
func discover(ctx context.Context, opts LoginOptions) (*discovery, error) {
	dc := discoveryClient(opts.HTTPClient)
	challenges := challenge(ctx, opts.HTTPClient, opts.ServerURL)
	var prm *oauthex.ProtectedResourceMetadata
	for _, c := range prmCandidates(resourceMetadataURL(challenges), opts.ServerURL) {
		m, err := oauthex.GetProtectedResourceMetadata(ctx, c.url, c.resource, dc)
		if err != nil || m == nil {
			continue
		}
		if len(m.AuthorizationServers) == 0 {
			return nil, errors.New("the server's protected resource metadata names no authorization server")
		}
		prm = m
		break
	}
	d := &discovery{resource: opts.ServerURL}
	var issuer string
	if prm != nil {
		d.resource = prm.Resource
		issuer = prm.AuthorizationServers[0]
	} else {
		u, _ := url.Parse(opts.ServerURL) // checked by SecureURL
		issuer = u.Scheme + "://" + u.Host
	}
	var err error
	if mu := opts.Config.AuthServerMetadataURL; mu != "" {
		issuer, err = issuerOf(mu)
		if err != nil {
			return nil, err
		}
		if prm != nil && !slices.ContainsFunc(prm.AuthorizationServers, func(s string) bool { return sameIssuer(s, issuer) }) {
			return nil, fmt.Errorf("authServerMetadataURL names the issuer %s, which the server does not list as its authorization server", issuer)
		}
		d.asm, err = oauthex.GetAuthServerMeta(ctx, mu, issuer, dc)
	} else {
		d.asm, err = auth.GetAuthServerMetadata(ctx, issuer, dc)
	}
	if err != nil {
		return nil, fmt.Errorf("authorization server metadata: %w", err)
	}
	if d.asm == nil {
		return nil, fmt.Errorf("no authorization server metadata found for the issuer %s; set authServerMetadataURL", issuer)
	}
	if err := checkMetadata(d.asm); err != nil {
		return nil, err
	}
	d.scopes = requestedScopes(opts.Config.Scopes, challenges, prm, d.asm)
	return d, nil
}

// challenge sends an unauthenticated request to the server and returns the challenges of its
// 401 answer, if any.
func challenge(ctx context.Context, hc *http.Client, serverURL string) []oauthex.Challenge {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL, bytes.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := hc.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusUnauthorized {
		return nil
	}
	cs, err := oauthex.ParseWWWAuthenticate(resp.Header.Values("WWW-Authenticate"))
	if err != nil {
		return nil
	}
	return cs
}

func resourceMetadataURL(cs []oauthex.Challenge) string {
	for _, c := range cs {
		if c.Scheme == "bearer" && c.Params["resource_metadata"] != "" {
			return c.Params["resource_metadata"]
		}
	}
	return ""
}

type prmCandidate struct{ url, resource string }

// prmCandidates lists where protected resource metadata may be: the challenge's URL, then the
// well-known location at the endpoint's path, then at the root, for the origin as resource.
// For an endpoint whose path ends in a slash, the first two are also tried for the resource
// without that slash, which servers that redirect /mcp to /mcp/ name as their resource.
func prmCandidates(fromChallenge, serverURL string) []prmCandidate {
	var out []prmCandidate
	resources := []string{serverURL}
	if u, err := url.Parse(serverURL); err == nil && len(u.Path) > 1 && strings.HasSuffix(u.Path, "/") && u.RawQuery == "" {
		resources = append(resources, strings.TrimSuffix(serverURL, "/"))
	}
	add := func(metadataURL string) {
		for _, r := range resources {
			out = append(out, prmCandidate{metadataURL, r})
		}
	}
	if fromChallenge != "" {
		add(fromChallenge)
	}
	u, err := url.Parse(serverURL)
	if err != nil {
		return out
	}
	w := *u
	w.RawQuery = ""
	if p := strings.Trim(u.Path, "/"); p != "" {
		w.Path, w.RawPath = "/.well-known/oauth-protected-resource/"+p, ""
		add(w.String())
	}
	w.Path, w.RawPath = "/.well-known/oauth-protected-resource", ""
	out = append(out, prmCandidate{w.String(), u.Scheme + "://" + u.Host})
	return out
}

// issuerOf returns the issuer whose metadata a metadata URL is, by the well-known forms of RFC
// 8414 (the suffix inserted before the issuer's path) and OpenID Connect (appended to it).
func issuerOf(metadataURL string) (string, error) {
	u, err := url.Parse(metadataURL)
	if err != nil || u.RawQuery != "" {
		return "", errors.New("authServerMetadataURL must be a well-known metadata URL without a query")
	}
	origin := u.Scheme + "://" + u.Host
	for _, wk := range []string{"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"} {
		if rest, ok := strings.CutPrefix(u.Path, wk); ok && (rest == "" || strings.HasPrefix(rest, "/")) {
			return origin + rest, nil
		}
	}
	if prefix, ok := strings.CutSuffix(u.Path, "/.well-known/openid-configuration"); ok {
		return origin + prefix, nil
	}
	return "", errors.New("authServerMetadataURL must end in or contain /.well-known/oauth-authorization-server or /.well-known/openid-configuration")
}

func sameIssuer(a, b string) bool { return strings.TrimSuffix(a, "/") == strings.TrimSuffix(b, "/") }

// checkMetadata requires what a login needs: the authorization code flow with PKCE S256.
func checkMetadata(asm *oauthex.AuthServerMeta) error {
	switch {
	case asm.AuthorizationEndpoint == "" || asm.TokenEndpoint == "":
		return errors.New("the authorization server metadata lacks the authorization or token endpoint")
	case !slices.Contains(asm.CodeChallengeMethodsSupported, "S256"):
		return errors.New("the authorization server does not support PKCE with S256")
	case len(asm.ResponseTypesSupported) > 0 && !slices.Contains(asm.ResponseTypesSupported, "code"):
		return errors.New("the authorization server does not support the authorization code flow")
	}
	for _, e := range []string{asm.AuthorizationEndpoint, asm.TokenEndpoint, asm.RegistrationEndpoint} {
		if e != "" && !config.SecureURL(e) {
			return errors.New("an authorization server endpoint is neither https nor loopback")
		}
	}
	return nil
}

// requestedScopes are the configured scopes, or else those the challenge or the resource
// metadata name, with offline_access added when the authorization server offers it, so that a
// refresh token is issued.
func requestedScopes(configured []string, cs []oauthex.Challenge, prm *oauthex.ProtectedResourceMetadata, asm *oauthex.AuthServerMeta) []string {
	if len(configured) > 0 {
		return slices.Clone(configured)
	}
	var out []string
	for _, c := range cs {
		if c.Scheme == "bearer" && c.Params["scope"] != "" {
			out = strings.Fields(c.Params["scope"])
			break
		}
	}
	if len(out) == 0 && prm != nil {
		out = slices.Clone(prm.ScopesSupported)
	}
	if slices.Contains(asm.ScopesSupported, "offline_access") && !slices.Contains(out, "offline_access") {
		out = append(out, "offline_access")
	}
	return out
}

// resolveClient returns the configured client, the previous login's registered client when it
// fits, or registers a new one (RFC 7591).
func resolveClient(ctx context.Context, opts LoginOptions, asm *oauthex.AuthServerMeta) (client, bool, error) {
	if id := opts.Config.ClientID; id != "" {
		return client{id: id, secret: opts.Config.ClientSecret, style: preferredStyle(asm.TokenEndpointAuthMethodsSupported, opts.Config.ClientSecret != "")}, false, nil
	}
	if p := opts.Previous; p != nil && p.Registered && sameIssuer(p.Issuer, asm.Issuer) && p.RedirectURL == opts.Config.RedirectURL {
		return client{id: p.ClientID, secret: p.ClientSecret, style: p.AuthStyle}, false, nil
	}
	if asm.RegistrationEndpoint == "" {
		return client{}, false, errors.New("the authorization server offers no dynamic client registration; register a client and set oauth.clientID")
	}
	c, err := register(ctx, opts, asm.RegistrationEndpoint)
	return c, true, err
}

// preferredStyle picks how a configured client authenticates, by the methods the server lists:
// client_secret_post, then client_secret_basic, which is the default (RFC 7591).
func preferredStyle(methods []string, hasSecret bool) string {
	switch {
	case !hasSecret, slices.Contains(methods, "client_secret_post"):
		return AuthInParams
	default:
		return AuthInHeader
	}
}

// register registers a public client for the authorization code flow with refresh tokens.
func register(ctx context.Context, opts LoginOptions, endpoint string) (client, error) {
	meta := oauthex.ClientRegistrationMetadata{
		RedirectURIs:            []string{opts.Config.RedirectURL},
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		ClientName:              opts.ClientName,
		ApplicationType:         applicationType(opts.Config.RedirectURL),
	}
	payload, err := json.Marshal(&meta)
	if err != nil {
		return client{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return client{}, errors.New("the registration endpoint is not a valid URL")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return client{}, fmt.Errorf("client registration: %w", sanitizeTransport(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil || len(body) > maxResponseBytes {
		return client{}, errors.New("client registration: the answer cannot be read or is too large")
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		var e struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &e)
		msg := fmt.Sprintf("client registration: the authorization server answered %d", resp.StatusCode)
		if c := printable(e.Error, 64); c != "" {
			msg += " " + c
		}
		if d := printable(e.Description, 200); d != "" {
			msg += ": " + d
		}
		return client{}, errors.New(msg)
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "application/json" {
		return client{}, errors.New("client registration: the answer is not JSON")
	}
	var r struct {
		ClientID                string `json:"client_id"`
		ClientSecret            string `json:"client_secret"`
		TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.ClientID == "" {
		return client{}, errors.New("client registration: the answer has no client_id")
	}
	c := client{id: r.ClientID, secret: r.ClientSecret, style: AuthInParams}
	if r.ClientSecret != "" && r.TokenEndpointAuthMethod != "client_secret_post" {
		c.style = AuthInHeader // client_secret_basic is the default
	}
	return c, nil
}

func applicationType(redirect string) string {
	u, err := url.Parse(redirect)
	if err == nil && u.Scheme == "http" {
		return "native" // a loopback redirect, by validation
	}
	return "web"
}

// Complete checks the address the browser was sent to after sign-in (the whole URL, or its
// query) and exchanges its code for tokens. It checks the state, the issuer (RFC 9207) and
// that the address is the redirect URL.
func (p *Pending) Complete(ctx context.Context, pasted string) (*Grant, error) {
	q, err := p.parseRedirect(pasted)
	if err != nil {
		return nil, err
	}
	if e := q.Get("error"); e != "" {
		msg := "the authorization server refused: " + printable(e, 64)
		if d := printable(q.Get("error_description"), 200); d != "" {
			msg += ": " + d
		}
		return nil, errors.New(msg)
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(p.state)) != 1 {
		return nil, errors.New("the state does not match this login; paste the address from this login's sign-in")
	}
	if err := p.checkIssuer(q.Get("iss")); err != nil {
		return nil, err
	}
	code := q.Get("code")
	if code == "" {
		return nil, errors.New("the address has no code")
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.opts.Config.RedirectURL},
		"code_verifier": {p.verifier},
		"resource":      {p.resource},
	}
	tr, err := requestToken(ctx, p.opts.HTTPClient, p.asm.TokenEndpoint, p.client, form)
	if err != nil {
		return nil, err
	}
	now := p.opts.Now()
	g := &Grant{
		Version: GrantVersion, ServerURL: p.opts.ServerURL, Resource: p.resource, Issuer: p.asm.Issuer,
		AuthorizationEndpoint: p.asm.AuthorizationEndpoint, TokenEndpoint: p.asm.TokenEndpoint,
		ClientID: p.client.id, Registered: p.opts.Config.ClientID == "", AuthStyle: p.client.style,
		RedirectURL: p.opts.Config.RedirectURL, Scopes: p.scopes,
		AccessToken: tr.AccessToken, TokenType: "Bearer", RefreshToken: tr.RefreshToken,
		Expiry: tr.expiry(now), ObtainedAt: now,
	}
	if g.Registered {
		g.ClientSecret = p.client.secret
	}
	if tr.Scope != "" {
		g.Scopes = strings.Fields(tr.Scope)
	}
	return g, nil
}

// parseRedirect returns the query of the pasted redirect address, which must be the redirect
// URL with a query, or the query alone.
func (p *Pending) parseRedirect(pasted string) (url.Values, error) {
	pasted = strings.TrimSpace(pasted)
	if pasted == "" {
		return nil, errors.New("nothing was pasted")
	}
	if len(pasted) > maxPasteBytes {
		return nil, errors.New("the pasted address is too long")
	}
	raw := pasted
	if !strings.HasPrefix(pasted, "?") {
		u, err := url.Parse(pasted)
		if err != nil || u.Scheme == "" {
			return nil, errors.New("paste the whole address the browser was sent to, starting with " + redirectPrefix(p.opts.Config.RedirectURL))
		}
		want, _ := url.Parse(p.opts.Config.RedirectURL) // validated
		if !strings.EqualFold(u.Scheme, want.Scheme) || !strings.EqualFold(u.Host, want.Host) || u.Path != want.Path {
			return nil, errors.New("the pasted address is not the redirect URL " + redirectPrefix(p.opts.Config.RedirectURL))
		}
		raw = "?" + u.RawQuery
	}
	q, err := url.ParseQuery(strings.TrimPrefix(raw, "?"))
	if err != nil {
		return nil, errors.New("the pasted address has an invalid query")
	}
	return q, nil
}

func redirectPrefix(redirect string) string {
	u, err := url.Parse(redirect)
	if err != nil {
		return "the redirect URL"
	}
	return u.Scheme + "://" + u.Host + u.Path
}

// checkIssuer applies RFC 9207: an issuer in the answer must be the authorization server's,
// and is required when the server says it sends one.
func (p *Pending) checkIssuer(iss string) error {
	switch {
	case iss == "" && p.asm.AuthorizationResponseIssParameterSupported:
		return errors.New("the address lacks the issuer the authorization server says it sends")
	case iss != "" && iss != p.asm.Issuer:
		return errors.New("the address names another issuer than the authorization server's")
	}
	return nil
}

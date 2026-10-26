package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Limits of the requests to the authorization server.
const (
	// RequestTimeout bounds each request to the authorization server.
	RequestTimeout = 30 * time.Second
	// maxResponseBytes bounds a token or registration response.
	maxResponseBytes = 1 << 20
)

// ErrLoginRequired is returned when a server has no usable grant: nobody logged in, the
// grant is for another server or client, or the authorization server rejected it.
var ErrLoginRequired = errors.New("oauth: login required")

// NewHTTPClient returns the client for requests to the authorization server: bounded by
// RequestTimeout and following no redirects, which would carry codes and secrets elsewhere.
// It keeps no idle connections, since its requests are rare.
func NewHTTPClient() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone() //nolint:forcetypeassert // the standard library's default transport
	t.DisableKeepAlives = true
	return &http.Client{
		Transport: t,
		Timeout:   RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("the authorization server answered with a redirect, which is not followed")
		},
	}
}

// discoveryClient returns the client for metadata documents. Its transport sets no DialContext,
// so the SDK uses a clone of it that refuses private and reserved addresses (unless a proxy is
// configured) and follows redirects only to https; keep-alives are off, since that clone cannot
// be closed. The clone offers h2 in TLS, so the transport must speak HTTP/2 too: without it, a
// server that picks h2 answers in frames the HTTP/1 reader cannot parse.
func discoveryClient(c *http.Client) *http.Client {
	return &http.Client{Timeout: c.Timeout, Transport: &http.Transport{DisableKeepAlives: true, Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true}}
}

// TokenError is an error answer of the token endpoint (RFC 6749, section 5.2).
type TokenError struct {
	Status int
	// Code is the error code, such as invalid_grant; empty when the answer had none.
	Code string
	// Description is the server's description, cut and limited to printable ASCII.
	Description string
}

func (e *TokenError) Error() string {
	msg := e.summary()
	if e.Description != "" {
		msg += ": " + e.Description
	}
	return msg
}

// summary is the status and the error code, without the description.
func (e *TokenError) summary() string {
	msg := "the token endpoint answered " + strconv.Itoa(e.Status)
	if e.Code != "" {
		msg += " " + e.Code
	}
	return msg
}

// rejectsGrant reports whether the authorization server refused the grant or the client, so
// that only a new login helps.
func (e *TokenError) rejectsGrant() bool {
	return e.Code == "invalid_grant" || e.Code == "invalid_client" || e.Code == "unauthorized_client"
}

// tokenResponse is a successful token response (RFC 6749, section 5.1).
type tokenResponse struct {
	AccessToken  string          `json:"access_token"`
	TokenType    string          `json:"token_type"`
	ExpiresIn    json.RawMessage `json:"expires_in"`
	RefreshToken string          `json:"refresh_token"`
	Scope        string          `json:"scope"`
}

// client is how a grant's client authenticates to the token endpoint.
type client struct {
	id, secret string
	style      string // AuthInHeader or AuthInParams
}

// requestToken posts a token request and returns the response. Errors never carry the
// request or the response body, which hold codes and tokens.
func requestToken(ctx context.Context, hc *http.Client, endpoint string, cl client, form url.Values) (*tokenResponse, error) {
	if cl.style == AuthInParams || cl.secret == "" {
		form.Set("client_id", cl.id)
		if cl.secret != "" {
			form.Set("client_secret", cl.secret)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errors.New("the token endpoint is not a valid URL")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if cl.style == AuthInHeader && cl.secret != "" {
		req.SetBasicAuth(url.QueryEscape(cl.id), url.QueryEscape(cl.secret))
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", sanitizeTransport(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, errors.New("token request: reading the answer failed")
	}
	if len(body) > maxResponseBytes {
		return nil, errors.New("token request: the answer is too large")
	}
	if resp.StatusCode != http.StatusOK {
		te := &TokenError{Status: resp.StatusCode}
		var e struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		if json.Unmarshal(body, &e) == nil {
			te.Code, te.Description = errorCode(e.Error), printable(e.Description, 200)
		}
		return nil, te
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "application/json" {
		return nil, errors.New("token request: the answer is not JSON")
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, errors.New("token request: the answer is not a valid token response")
	}
	if tr.AccessToken == "" {
		return nil, errors.New("token request: the answer has no access_token")
	}
	if !strings.EqualFold(tr.TokenType, "bearer") {
		return nil, errors.New("token request: the token type is not Bearer")
	}
	if strings.ContainsFunc(tr.AccessToken, notToken) || strings.ContainsFunc(tr.RefreshToken, notToken) {
		return nil, errors.New("token request: a token holds characters a header cannot carry")
	}
	return &tr, nil
}

// notToken reports characters that do not belong in a bearer token header value.
func notToken(r rune) bool { return r <= ' ' || r > '~' }

// expiry returns when a token response expires, or zero when it does not say.
func (tr *tokenResponse) expiry(now time.Time) time.Time {
	raw := strings.Trim(string(tr.ExpiresIn), `"`)
	if raw == "" || raw == "null" {
		return time.Time{}
	}
	f, err := strconv.ParseFloat(raw, 64) // some servers send 3600.0 or "3600"
	if err != nil || !(f >= 1) {
		return time.Time{}
	}
	return now.Add(time.Duration(min(f, 10*365*24*3600)) * time.Second)
}

// errorCode returns an OAuth error code when it is one (RFC 6749 codes are lower-case words
// joined by _), and "unknown" otherwise: it is the server's text, and logged.
func errorCode(s string) string {
	if s == "" {
		return ""
	}
	if len(s) > 64 || strings.ContainsFunc(s, func(r rune) bool { return (r < 'a' || r > 'z') && r != '_' }) {
		return "unknown"
	}
	return s
}

// printable keeps the printable ASCII of s, cut at limit bytes.
func printable(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		if r < ' ' || r > '~' {
			return -1
		}
		return r
	}, s)
	if len(s) > limit {
		s = s[:limit] + "…"
	}
	return s
}

// sanitizeTransport keeps the cause of a failed request without its URL, whose query could
// hold a secret.
func sanitizeTransport(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		if ue.Timeout() {
			return errors.New("timed out")
		}
		return ue.Err
	}
	return err
}

package oauth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// ErrClosed is returned by a refresh after Source.Close.
var ErrClosed = errors.New("oauth: the token source is closed")

// expirySkew is how long before its expiry an access token is refreshed.
const expirySkew = time.Minute

// SourceOptions configure a Source.
type SourceOptions struct {
	// Name is the server's name in the config, which names its grant file.
	Name string
	// ServerURL is the server's URL; a grant obtained for another URL is not used.
	ServerURL string
	// ClientID and ClientSecret are the configured client, if any; a grant for another client
	// is not used.
	ClientID, ClientSecret string
	// Store holds the grant; nil means there is none.
	Store *Store
	// HTTPClient makes the token requests; see NewHTTPClient.
	HTTPClient *http.Client
	Logger     *slog.Logger
	// Now returns the time; nil is time.Now.
	Now func() time.Time
}

// Source supplies the access token of one server's grant to the SDK's streamable client
// (auth.OAuthHandler and oauth2.TokenSource). It refreshes the token shortly before it expires
// and when the server answers 401, one refresh at a time, under the store's lock so that other
// processes using the same grant do not refresh it too, and saves the refreshed grant. It never
// starts a login: a server without a usable grant fails with ErrLoginRequired until someone
// runs mcp-gate auth login, which it notices by the grant file changing.
type Source struct {
	opts   SourceOptions
	logger *slog.Logger
	// closed ends refreshes and the waits for the grant lock; Close closes it.
	closed    chan struct{}
	closeOnce sync.Once

	mu       sync.Mutex
	grant    *Grant
	loaded   bool      // the grant file was read at stamp
	stamp    stamp     // of the file grant was read from
	dead     bool      // the authorization server or the server rejected grant
	reason   string    // why there is no usable grant, for status
	forced   string    // the access token a refresh after a 401 obtained
	forcedAt time.Time // when the last 401 to it came
	forcedN  int       // refreshes after a 401 in a row, each soon after the one before
}

// A 401 to a token that a refresh after a 401 obtained, within retryWindow of the previous 401,
// is counted; the maxForced-th in a row means the server rejects the grant's tokens. A single
// one is no proof: the token may have been dropped in its turn, as a server restart does. The
// window outlasts the time between connect attempts (restart.maxBackoff, at most
// config.MaxMaxBackoff, plus the connect timeout), so a server that rejects every token is
// noticed however its attempts are spaced.
const (
	retryWindow = 10 * time.Minute
	maxForced   = 3
)

// NewSource returns the token source of a server.
func NewSource(opts SourceOptions) *Source {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	return &Source{opts: opts, logger: opts.Logger.With("server", opts.Name), reason: "not logged in", closed: make(chan struct{})}
}

// Close ends a wait for the grant lock in progress, and makes later refreshes fail at once, so
// that a supervisor that stops is not held by another process holding the lock. A token request
// already sent runs on, bounded by RequestTimeout, so that a rotated refresh token is saved.
func (s *Source) Close() { s.closeOnce.Do(func() { close(s.closed) }) }

// LoginRequired reports whether the server has no usable grant, reading the grant file again
// if it changed.
func (s *Source) LoginRequired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reloadLocked()
	return s.grant == nil || s.dead
}

// Reason says why the server has no usable grant; empty when it has one.
func (s *Source) Reason() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.grant != nil && !s.dead {
		return ""
	}
	return s.reason
}

// TokenSource implements auth.OAuthHandler.
func (s *Source) TokenSource(context.Context) (oauth2.TokenSource, error) { return s, nil }

// Token implements oauth2.TokenSource: the current access token, refreshed when it is about to
// expire. It fails with ErrLoginRequired when there is no usable grant.
func (s *Source) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reloadLocked()
	if s.grant == nil || s.dead {
		return nil, ErrLoginRequired
	}
	if !s.validLocked(s.grant) {
		// oauth2.TokenSource has no context; the refresh is bounded by RequestTimeout and Close.
		if err := s.refreshLocked(context.Background()); err != nil {
			return nil, err
		}
	}
	return s.tokenLocked(), nil
}

func (s *Source) tokenLocked() *oauth2.Token {
	return &oauth2.Token{AccessToken: s.grant.AccessToken, TokenType: "Bearer", Expiry: s.grant.Expiry}
}

// validLocked reports whether g's access token is good for a while yet: until a minute before
// its expiry, or half its lifetime for a token that lives two minutes or less.
func (s *Source) validLocked(g *Grant) bool {
	if g.Expiry.IsZero() {
		return true
	}
	issued := g.ObtainedAt
	if !g.RefreshedAt.IsZero() {
		issued = g.RefreshedAt
	}
	skew := min(expirySkew, g.Expiry.Sub(issued)/2)
	return s.opts.Now().Add(skew).Before(g.Expiry)
}

// Authorize implements auth.OAuthHandler; the SDK calls it when the server answers 401 or 403,
// and retries the request once when it returns nil. A 401 to the current token refreshes it;
// the third 401 in a row to tokens such refreshes obtained means the server rejects the grant.
func (s *Source) Authorize(ctx context.Context, req *http.Request, resp *http.Response) error {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		return errors.New("oauth: the server refused the request (" + http.StatusText(resp.StatusCode) + "); the grant's scopes may not cover it")
	}
	used, _ := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reloadLocked()
	switch {
	case s.grant == nil || s.dead:
		return ErrLoginRequired
	case used != s.grant.AccessToken:
		return nil // the token changed since the request was sent: retry with the new one
	}
	now := s.opts.Now()
	if used == s.forced && now.Sub(s.forcedAt) < retryWindow {
		s.forcedN++
	} else {
		s.forcedN = 1
	}
	if s.forcedN >= maxForced {
		s.rejectLocked("the server rejects the grant's tokens")
		return ErrLoginRequired
	}
	// A refresh cut off by the request's end could lose a rotated refresh token, so only Close
	// ends it early.
	if err := s.refreshLocked(context.WithoutCancel(ctx)); err != nil {
		return err
	}
	s.forced, s.forcedAt = s.grant.AccessToken, now
	return nil
}

// reloadLocked adopts the grant file when it changed since it was read.
func (s *Source) reloadLocked() {
	if s.opts.Store == nil {
		s.grant, s.reason = nil, "no state directory: there is nowhere to keep a grant"
		return
	}
	cur := statStamp(s.opts.Store.path(s.opts.Name))
	if s.loaded && cur.same(s.stamp) {
		return
	}
	g, st, err := s.opts.Store.load(s.opts.Name)
	if st.fi == nil {
		st = cur
	}
	s.loaded, s.stamp, s.dead, s.forced, s.forcedN = true, st, false, "", 0
	switch {
	case err != nil:
		s.grant, s.reason = nil, err.Error()
	case g == nil:
		s.grant, s.reason = nil, "not logged in"
	default:
		if why := g.Mismatch(s.opts.ServerURL, s.opts.ClientID); why != "" {
			s.grant, s.reason = nil, why+"; log in again"
		} else {
			s.grant, s.reason = g, ""
		}
	}
}

func (s *Source) rejectLocked(reason string) {
	if !s.dead {
		s.logger.Warn("the OAuth grant is no longer usable; log in again", "reason", reason)
	}
	s.dead, s.reason = true, reason+"; log in again"
}

// refreshLocked replaces the access token using the refresh token. Under the store's lock it
// first reads the grant file again, in case another process has refreshed it already.
func (s *Source) refreshLocked(ctx context.Context) error {
	// Close ends the wait for the lock, but not a token request once sent: cutting that off
	// could lose a refresh token the authorization server has already rotated.
	select {
	case <-s.closed:
		return ErrClosed
	default:
	}
	lockCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-s.closed:
			cancel()
		case <-lockCtx.Done():
		}
	}()
	unlock, err := s.opts.Store.Lock(lockCtx, s.opts.Name)
	if err != nil {
		return err
	}
	defer unlock()
	// Whatever another process wrote while this one waited for the lock (a refresh, a new
	// login, a logout) wins over the grant in memory, which is never saved over it.
	if !statStamp(s.opts.Store.path(s.opts.Name)).same(s.stamp) {
		s.loaded = false
		s.reloadLocked()
		switch {
		case s.grant == nil:
			return ErrLoginRequired
		case s.validLocked(s.grant):
			return nil
		}
	}
	if s.grant.RefreshToken == "" {
		s.rejectLocked("the access token expired and the grant has no refresh token")
		return ErrLoginRequired
	}
	cl := client{id: s.grant.ClientID, secret: s.grant.ClientSecret, style: s.grant.AuthStyle}
	if !s.grant.Registered {
		cl.secret = s.opts.ClientSecret
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {s.grant.RefreshToken}}
	if s.grant.Resource != "" {
		form.Set("resource", s.grant.Resource)
	}
	ctx, cancelReq := context.WithTimeout(ctx, RequestTimeout)
	defer cancelReq()
	tr, err := requestToken(ctx, s.opts.HTTPClient, s.grant.TokenEndpoint, cl, form)
	if err != nil {
		var te *TokenError
		if !errors.As(err, &te) {
			te = nil
		}
		if te != nil && te.rejectsGrant() {
			s.rejectLocked("the authorization server refused the refresh token (" + te.Code + ")")
			return ErrLoginRequired
		}
		msg := err.Error()
		if te != nil {
			msg = te.summary() // the description is the server's text, which could echo the token
		}
		s.logger.Warn("refreshing the OAuth access token failed", "error", msg)
		return errors.New("oauth: refreshing the access token failed: " + msg)
	}
	next := *s.grant
	now := s.opts.Now()
	next.AccessToken, next.Expiry, next.RefreshedAt = tr.AccessToken, tr.expiry(now), now
	if tr.RefreshToken != "" {
		next.RefreshToken = tr.RefreshToken
	}
	if tr.Scope != "" {
		next.Scopes = strings.Fields(tr.Scope)
	}
	s.grant = &next
	if err := s.opts.Store.Save(s.opts.Name, &next); err != nil {
		s.logger.Error("cannot save the refreshed OAuth grant; a restart may need a new login", "error", err.Error())
		return nil
	}
	s.stamp = statStamp(s.opts.Store.path(s.opts.Name))
	s.logger.Info("refreshed the OAuth access token")
	return nil
}

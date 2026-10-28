package downstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2"
)

// sseVersion is the protocol version offered to a server on the legacy HTTP+SSE transport that
// has no pin: the latest one the transport carries, with initialize and no discover.
const sseVersion = AutoPinVersion

// errForeignEndpoint is the error of a request a legacy server directed to another origin.
var errForeignEndpoint = errors.New("mcp-gate: the server's message endpoint is on another origin than its url; refused")

// pendingCalls are the requests sent on a connection and not yet answered, so that a response
// over the size limit can fail the request it answers.
type pendingCalls struct {
	mu  sync.Mutex
	ids map[jsonrpc.ID]bool
}

func newPendingCalls() *pendingCalls { return &pendingCalls{ids: map[jsonrpc.ID]bool{}} }

// sent records a call, or forgets the request a cancellation names: it may never be answered.
func (p *pendingCalls) sent(m jsonrpc.Message) {
	req, ok := m.(*jsonrpc.Request)
	if !ok {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if req.IsCall() {
		p.ids[req.ID] = true
	} else if id, ok := cancelledID(req); ok {
		delete(p.ids, id)
	}
}

// received forgets the request a response answers.
func (p *pendingCalls) received(m jsonrpc.Message) {
	if resp, ok := m.(*jsonrpc.Response); ok {
		p.forget(resp.ID)
	}
}

func (p *pendingCalls) forget(id jsonrpc.ID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.ids, id)
}

// has reports whether id names a pending request.
func (p *pendingCalls) has(id jsonrpc.ID) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ids[id]
}

// reset forgets every request, for a new connection.
func (p *pendingCalls) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	clear(p.ids)
}

// sseTransport is the SDK's legacy HTTP+SSE client transport with the requests in flight
// tracked, so that the size limiter of the event stream can tell a response to a pending request.
type sseTransport struct {
	inner   *mcp.SSEClientTransport
	pending *pendingCalls
}

// Connect opens the event stream. The SDK ties the stream's GET to the context it is given, so
// the stream gets a context of its own, which ctx cancels only until the stream is open, and
// Close cancels after.
func (t sseTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	t.pending.reset()
	streamCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(ctx, cancel)
	c, err := t.inner.Connect(streamCtx)
	if !stop() {
		err = errors.Join(ctx.Err(), err) // ctx ended the connect
	}
	if err != nil {
		if c != nil {
			_ = c.Close()
		}
		cancel()
		return nil, err
	}
	return &sseConn{Connection: c, pending: t.pending, cancel: cancel}, nil
}

type sseConn struct {
	mcp.Connection
	pending *pendingCalls
	cancel  context.CancelFunc // ends the stream's GET
}

func (c *sseConn) Close() error {
	err := c.Connection.Close()
	c.cancel()
	return err
}

func (c *sseConn) Read(ctx context.Context) (jsonrpc.Message, error) {
	m, err := c.Connection.Read(ctx)
	if err == nil {
		c.pending.received(m)
	}
	return m, err
}

// Write POSTs m to the message endpoint. A POST that fails fails only its own request, as on
// streamable HTTP: the error is marked rejected by the transport, so the session goes on.
func (c *sseConn) Write(ctx context.Context, m jsonrpc.Message) error {
	c.pending.sent(m)
	err := c.Connection.Write(ctx, m)
	if err == nil {
		return nil
	}
	if req, ok := m.(*jsonrpc.Request); ok && req.IsCall() {
		c.pending.forget(req.ID) // an unsent request is never answered
	}
	if err == io.EOF || ctx.Err() != nil { //nolint:errorlint // the SDK's sentinel for a closed connection, not an EOF wrapped in a failed POST
		return err
	}
	return fmt.Errorf("%w: %w", &jsonrpc.Error{Code: rejectedByTransport, Message: "rejected by transport"}, err)
}

// legacyTransport is the outer round tripper of a server on the legacy HTTP+SSE transport. The
// server names the endpoint messages are POSTed to, so a request to any origin but that of the
// configured URL is refused before the headers or a token are added. With OAuth, it adds the
// access token, as the SDK's streamable transport does, and after a 401 or 403 lets the
// authorizer refresh it and sends the request once more.
type legacyTransport struct {
	origin string
	auth   Authorizer
	next   http.RoundTripper
}

// originOf returns the scheme, host and port of u, lower-cased, with the default port made
// explicit and a trailing dot of the host dropped.
func originOf(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		switch scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	return scheme + "://" + net.JoinHostPort(strings.TrimSuffix(strings.ToLower(u.Hostname()), "."), port)
}

func (t *legacyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if originOf(req.URL) != t.origin {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, errForeignEndpoint
	}
	if t.auth == nil {
		return t.next.RoundTrip(req)
	}
	sent, resp, err := t.send(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		return resp, nil
	}
	if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		return resp, nil // the body cannot be sent again
	}
	// Authorize reads and closes the response's body; it compares the token sent with its own.
	if err := t.auth.Authorize(req.Context(), sent, resp); err != nil {
		return nil, err
	}
	again := req.Clone(req.Context())
	if req.GetBody != nil {
		if again.Body, err = req.GetBody(); err != nil {
			return nil, err
		}
	}
	_, resp, err = t.send(again)
	return resp, err
}

// send sends req with the current access token and returns the request as sent. Without a
// usable token it fails, unless the refresh token was rejected (invalid_grant): then the request
// goes without one, so that the server's 401 reaches Authorize, which reports the lost grant.
func (t *legacyTransport) send(req *http.Request) (*http.Request, *http.Response, error) {
	ts, err := t.auth.TokenSource(req.Context())
	if err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, nil, err
	}
	out := req.Clone(req.Context())
	if ts != nil {
		tok, err := ts.Token()
		var rerr *oauth2.RetrieveError
		switch {
		case err == nil && tok != nil:
			out.Header.Set("Authorization", "Bearer "+tok.AccessToken)
		case err != nil && (!errors.As(err, &rerr) || rerr.ErrorCode != "invalid_grant"):
			if req.Body != nil {
				_ = req.Body.Close()
			}
			return nil, nil, err
		}
	}
	resp, err := t.next.RoundTrip(out)
	return out, resp, err
}

package upstream

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Limits of the HTTP listener.
const (
	ReadHeaderTimeout = 10 * time.Second
	IdleTimeout       = 120 * time.Second
	MaxHeaderBytes    = 64 << 10
	// BodyTimeout bounds reading an MCP request body.
	BodyTimeout = 30 * time.Second
	// MaxBodyBytes is the largest MCP request body.
	MaxBodyBytes = 4 << 20
	// RetryAfter is the Retry-After, in seconds, of a route whose server has not connected yet.
	RetryAfter = "5"
	// WriteTimeout bounds each write of a response, of at most writeChunk bytes, so that a
	// client that stops reading cannot hold its handler, nor the goroutines and memory behind
	// it, while the connection stays up.
	WriteTimeout = 30 * time.Second
	writeChunk   = 64 << 10
)

// NewServer returns the HTTP server for handler with mcp-gate's limits. It has no ReadTimeout:
// net/http cancels a request's context when the read deadline passes, even after the body has
// been read, which would cancel long calls. MCP routes bound their body with ReadBody instead.
// It has no WriteTimeout either, which would bound the whole response and so the call; each
// write is bounded by BoundWrites instead.
// Its Shutdown closes the connections on which no request has arrived. It serves HTTP/1 only:
// net/http does not report an HTTP/2 connection becoming active, which the tracking relies on.
func NewServer(addr string, handler http.Handler, logger *slog.Logger) *Server {
	s := &Server{conns: &conns{open: map[net.Conn]*connState{}}}
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	s.Server = &http.Server{
		Protocols:         &protocols,
		Addr:              addr,
		Handler:           s.closeWhenDraining(BoundWrites(WriteTimeout, handler)),
		ReadHeaderTimeout: ReadHeaderTimeout,
		IdleTimeout:       IdleTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
		ConnState:         s.conns.track,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, c)
		},
	}
	s.RegisterOnShutdown(s.conns.closeUnused)
	return s
}

// Server is an http.Server whose shutdown can begin with Drain: it stops accepting, but serves
// for a while longer the requests that arrive on connections it has open, closing each one after
// its response, so that a client that sends a request just as the shutdown begins gets an answer
// rather than a closed connection. A ConnContext set in place of NewServer's must call it.
type Server struct {
	*http.Server
	conns     *conns
	draining  atomic.Bool
	mu        sync.Mutex
	listeners []net.Listener
}

// connKey is the context key of a request's connection.
type connKey struct{}

// Serve serves ln, as http.Server.Serve does; a listener that Drain closed ends it with
// http.ErrServerClosed.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.draining.Load() {
		s.mu.Unlock()
		_ = ln.Close()
		return http.ErrServerClosed
	}
	// Drain and Shutdown both close it; the second close must not fail the Shutdown.
	ln = &closeOnce{Listener: ln}
	s.listeners = append(s.listeners, ln)
	s.mu.Unlock()
	err := s.Server.Serve(ln)
	if s.draining.Load() && errors.Is(err, net.ErrClosed) {
		return http.ErrServerClosed
	}
	return err
}

// Drain closes the listeners, so that new connections are no longer accepted (on a socket
// systemd holds they wait for the next process), and from then on answers every request with
// Connection: close. It returns once every open connection is closing after its response, or
// after linger, or when ctx is done; Shutdown then closes the idle ones and waits for the rest.
func (s *Server) Drain(ctx context.Context, linger time.Duration) {
	s.mu.Lock()
	s.draining.Store(true)
	for _, ln := range s.listeners {
		_ = ln.Close()
	}
	s.mu.Unlock()
	timer := time.NewTimer(linger)
	defer timer.Stop()
	tick := time.NewTicker(drainPoll)
	defer tick.Stop()
	for s.conns.kept() > 0 {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			return
		case <-tick.C:
		}
	}
}

// closeOnce is a listener whose Close closes it once and then reports success.
type closeOnce struct {
	net.Listener
	once sync.Once
	err  error
}

func (l *closeOnce) Close() error {
	l.once.Do(func() { l.err = l.Listener.Close() })
	return l.err
}

// drainPoll is how often Drain checks the open connections.
const drainPoll = 10 * time.Millisecond

// closeWhenDraining answers with Connection: close once Drain has begun, decided when the
// response's header is written, so that a call that began before still closes its connection.
func (s *Server) closeWhenDraining(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Context().Value(connKey{}).(net.Conn)
		cw := &closingWriter{ResponseWriter: w, server: s, conn: c}
		// A handler that writes nothing has its header written after it returns.
		defer cw.mark()
		next.ServeHTTP(cw, r)
	})
}

// closingWriter adds Connection: close to a response whose header is written while draining.
type closingWriter struct {
	http.ResponseWriter
	server  *Server
	conn    net.Conn
	written bool
}

func (w *closingWriter) mark() {
	if w.written {
		return
	}
	w.written = true
	if w.server.draining.Load() {
		w.Header().Set("Connection", "close")
		w.server.conns.closing(w.conn)
	}
}

func (w *closingWriter) WriteHeader(code int) {
	if code >= http.StatusOK || code == http.StatusSwitchingProtocols {
		w.mark()
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *closingWriter) Write(p []byte) (int, error) {
	w.mark()
	return w.ResponseWriter.Write(p)
}

func (w *closingWriter) FlushError() error {
	w.mark()
	return http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *closingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// conns tracks the open connections. http.Server.Shutdown waits until a connection on which no
// request has arrived is 5 seconds old, and HTTP clients open spare ones that they may never
// use, so a shutdown closes those instead: they carry no call. A request whose headers are still
// arriving when the shutdown begins is refused with them.
type conns struct {
	mu       sync.Mutex
	shutdown bool
	open     map[net.Conn]*connState
}

type connState struct {
	state http.ConnState
	// closes is set when the connection's current response says Connection: close.
	closes bool
}

func (u *conns) track(c net.Conn, st http.ConnState) {
	u.mu.Lock()
	defer u.mu.Unlock()
	switch {
	case st == http.StateClosed || st == http.StateHijacked:
		delete(u.open, c)
	case st == http.StateNew && u.shutdown:
		_ = c.Close()
	case u.open[c] == nil:
		u.open[c] = &connState{state: st}
	default:
		u.open[c].state = st
	}
}

// closing records that c closes after its current response.
func (u *conns) closing(c net.Conn) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if cs := u.open[c]; cs != nil {
		cs.closes = true
	}
}

// kept counts the open connections that do not close after their current response: unused,
// idle, or busy with a response whose header was written before Drain.
func (u *conns) kept() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	n := 0
	for _, cs := range u.open {
		if !cs.closes {
			n++
		}
	}
	return n
}

// closeUnused closes the connections on which no request has arrived; http.Server.Shutdown
// closes the idle ones itself.
func (u *conns) closeUnused() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.shutdown = true
	for c, cs := range u.open {
		if cs.state == http.StateNew {
			_ = c.Close()
			delete(u.open, c)
		}
	}
}

// BoundWrites gives every write of a response, cut into pieces of at most writeChunk bytes, and
// every flush a write deadline of timeout from its start, so that a response that makes no
// progress for that long fails. net/http then closes the connection and cancels the request's
// context, which ends the call behind it. The deadline is cleared when a request starts, since
// one left by the previous request on the connection would fail it, and set once more when the
// handler returns, for the flush that net/http does then.
func BoundWrites(timeout time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bw := &boundedWriter{ResponseWriter: w, rc: http.NewResponseController(w), timeout: timeout}
		_ = bw.rc.SetWriteDeadline(time.Time{})
		defer bw.arm()
		next.ServeHTTP(bw, r)
	})
}

// boundedWriter sets the write deadline before each write. Unwrap lets
// http.ResponseController reach the connection through it.
type boundedWriter struct {
	http.ResponseWriter
	rc      *http.ResponseController
	timeout time.Duration
}

func (w *boundedWriter) arm() { _ = w.rc.SetWriteDeadline(time.Now().Add(w.timeout)) }

func (w *boundedWriter) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		w.arm()
		m, err := w.ResponseWriter.Write(p[:min(len(p), writeChunk)])
		n += m
		if err != nil {
			return n, err
		}
		p = p[m:]
	}
	return n, nil
}

func (w *boundedWriter) Flush() { _ = w.FlushError() }

func (w *boundedWriter) FlushError() error {
	w.arm()
	return w.rc.Flush()
}

func (w *boundedWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// ReadBody reads the request body, up to maxBytes within timeout, before next runs, and then
// clears the read deadline, so that the body is bounded but a long call is not. Handlers after it
// get the bytes read with BodyBytes.
func ReadBody(maxBytes int64, timeout time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil || r.Body == http.NoBody {
			next.ServeHTTP(w, r)
			return
		}
		rc := http.NewResponseController(w)
		_ = rc.SetReadDeadline(time.Now().Add(timeout))
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBytes))
		_ = rc.SetReadDeadline(time.Time{})
		if err != nil {
			var tooLarge *http.MaxBytesError
			var netErr net.Error
			switch {
			case errors.As(err, &tooLarge):
				http.Error(w, fmt.Sprintf("request body exceeds %d bytes", maxBytes), http.StatusRequestEntityTooLarge)
			case errors.As(err, &netErr) && netErr.Timeout():
				http.Error(w, "request body too slow", http.StatusRequestTimeout)
			default:
				http.Error(w, "cannot read the request body", http.StatusBadRequest)
			}
			return
		}
		r.Body = &readBody{Reader: bytes.NewReader(body), data: body}
		next.ServeHTTP(w, r)
	})
}

// readBody is a body that ReadBody has read into memory.
type readBody struct {
	*bytes.Reader
	data []byte
}

func (*readBody) Close() error { return nil }

// BodyBytes returns the body ReadBody read for r, if it did. The bytes are shared with the body
// and must not be changed.
func BodyBytes(r *http.Request) ([]byte, bool) {
	b, ok := r.Body.(*readBody)
	if !ok {
		return nil, false
	}
	return b.data, true
}

// Recover answers a request whose handler panics with 500 and logs the panic without its value,
// which may hold request data.
func Recover(logger *slog.Logger, route string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler { //nolint:errorlint // the sentinel is compared as net/http does
					panic(v)
				}
				logger.Error("handler panicked", "route", route, "type", fmt.Sprintf("%T", v))
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// RemoteFunc returns the address a request comes from, for logs.
type RemoteFunc func(*http.Request) string

// NewRemote returns the RemoteFunc of a listener. Behind a proxy, a request whose peer is in
// trusted is attributed to the right-most X-Forwarded-For entry outside trusted; the entries to
// its left are written by the client and can say anything. Otherwise the peer address is used.
func NewRemote(behindProxy bool, trusted []netip.Prefix) RemoteFunc {
	isTrusted := func(a netip.Addr) bool {
		for _, p := range trusted {
			if p.Contains(a.Unmap()) {
				return true
			}
		}
		return false
	}
	return func(r *http.Request) string {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		peer, err := netip.ParseAddr(host)
		if !behindProxy || err != nil || !isTrusted(peer) {
			return host
		}
		hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
		for i := len(hops) - 1; i >= 0; i-- {
			a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
			if err != nil {
				return host // a malformed entry: nothing to its left can be believed
			}
			if !isTrusted(a) {
				return a.Unmap().String()
			}
		}
		return host
	}
}

// AllowHosts rejects with 403 a request whose Host is not in hosts. An entry without a port
// matches any port. An empty list allows every Host.
func AllowHosts(hosts []string, next http.Handler) http.Handler {
	if len(hosts) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			name = h
		}
		for _, allowed := range hosts {
			if strings.EqualFold(allowed, r.Host) || strings.EqualFold(strings.Trim(allowed, "[]"), name) {
				next.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "Forbidden: invalid Host header", http.StatusForbidden)
	})
}

// LogRequests logs one line per request to a route: method, status, duration and remote
// address. The path, query and headers are never logged.
func LogRequests(logger *slog.Logger, route string, remote RemoteFunc, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		logger.Info("request", "server", route, "method", r.Method, "status", sw.status,
			"durMs", time.Since(start).Milliseconds(), "remote", remote(r))
	})
}

// statusWriter records the status code. Unwrap lets http.ResponseController reach the
// underlying writer for flushes and deadlines.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status, w.wroteHeader = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	w.wroteHeader = true
	return w.ResponseWriter.Write(p)
}

func (w *statusWriter) Flush() {
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// SDKLogger returns the logger to give the SDK's server and HTTP handler: it logs their info
// lines, written for every session and so for every stateless request, at debug level.
func SDKLogger(logger *slog.Logger) *slog.Logger {
	return slog.New(demote{logger.Handler()})
}

// demote logs info records at debug level.
type demote struct{ next slog.Handler }

func (d demote) level(l slog.Level) slog.Level {
	if l == slog.LevelInfo {
		return slog.LevelDebug
	}
	return l
}

func (d demote) Enabled(ctx context.Context, l slog.Level) bool {
	return d.next.Enabled(ctx, d.level(l))
}

func (d demote) Handle(ctx context.Context, r slog.Record) error {
	r.Level = d.level(r.Level)
	return d.next.Handle(ctx, r)
}

func (d demote) WithAttrs(attrs []slog.Attr) slog.Handler { return demote{d.next.WithAttrs(attrs)} }

func (d demote) WithGroup(name string) slog.Handler { return demote{d.next.WithGroup(name)} }

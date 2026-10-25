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
)

// NewServer returns the HTTP server for handler with mcp-gate's limits. It has no ReadTimeout:
// net/http cancels a request's context when the read deadline passes, even after the body has
// been read, which would cancel long calls. MCP routes bound their body with ReadBody instead.
func NewServer(addr string, handler http.Handler, logger *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: ReadHeaderTimeout,
		IdleTimeout:       IdleTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
}

// ReadBody reads the request body, up to maxBytes within timeout, before next runs, and then
// clears the read deadline, so that the body is bounded but a long call is not.
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
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
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

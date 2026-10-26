// Package gate assembles mcp-gate from its config: a supervisor and a mirror for every server,
// the HTTP routes in front of them, readiness after the startup grace period, and shutdown.
package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/downstream"
	"github.com/vsem-azamat/mcp-gate/internal/escrow"
	"github.com/vsem-azamat/mcp-gate/internal/filescan"
	"github.com/vsem-azamat/mcp-gate/internal/oauth"
	"github.com/vsem-azamat/mcp-gate/internal/policy"
	"github.com/vsem-azamat/mcp-gate/internal/proxy"
	"github.com/vsem-azamat/mcp-gate/internal/redact"
	"github.com/vsem-azamat/mcp-gate/internal/upstream"
)

// Shutdown budget.
const (
	// ShutdownGrace is how long calls in flight may finish once shutdown begins.
	ShutdownGrace = 10 * time.Second
	// stopTimeout bounds stopping one server.
	stopTimeout = 15 * time.Second
	// readyPoll is how often startup checks whether every server has connected.
	readyPoll = 100 * time.Millisecond
)

// Options configure a Gate.
type Options struct {
	Config *config.Config
	// Environ is the gate's environment, which stdio servers inherit from.
	Environ []string
	// StateDir, if set, is where learned protocol pins are kept.
	StateDir string
	Version  string
	Logger   *slog.Logger
	// EscrowKey, if set, is the SHA-256 of the escrow API key and where it came from: the escrow
	// is on, the findings of servers with redact.escrow are kept in it and /_escrow/ serves them.
	EscrowKey *escrow.Key
	// Replacer, if set, returns the replacer for the findings in one call's result, in place of
	// the escrow's or the [REDACTED:<kind>] marker; for tests.
	Replacer func(server string, req proxy.Request) redact.Replacer
	// Tune, if set, adjusts each server's supervisor options; for tests.
	Tune func(*downstream.Options)
}

// Gate is a configured mcp-gate.
type Gate struct {
	opts    Options
	cfg     *config.Config
	logger  *slog.Logger
	names   []string // enabled servers, sorted
	servers map[string]*server
	escrow  *escrow.Escrow // nil when off
	mux     *http.ServeMux
	srv     *http.Server
	pins    *pinStore
	started atomic.Bool
	// drain is closed when shutdown begins; it ends the subscriptions/listen streams, which
	// would otherwise hold the shutdown for its whole grace.
	drain     chan struct{}
	drainOnce sync.Once
}

type server struct {
	name   string
	cfg    *config.Server
	sup    *downstream.Supervisor
	mirror *proxy.Mirror
}

// New builds a gate from its config. It starts nothing.
func New(opts Options) (*Gate, error) {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	cfg := opts.Config
	g := &Gate{opts: opts, cfg: cfg, logger: opts.Logger, servers: map[string]*server{}, mux: http.NewServeMux()}
	g.drain = make(chan struct{})
	var err error
	if g.pins, err = loadPins(opts.StateDir); err != nil {
		g.logger.Warn("cannot read the learned protocol pins; starting without them", "error", err.Error())
	}
	trusted := make([]netip.Prefix, 0, len(cfg.Listen.TrustedProxies))
	for _, p := range cfg.Listen.TrustedProxies {
		if pp, err := netip.ParsePrefix(p); err == nil {
			trusted = append(trusted, pp)
		}
	}
	remote := upstream.NewRemote(cfg.Listen.BehindProxy, trusted)
	if cfg.Listen.BehindProxy && len(cfg.Listen.AllowedHosts) == 0 {
		g.logger.Warn("listen.behindProxy is set without listen.allowedHosts: no Host is checked, so the proxy must check it")
	}
	if cfg.FileRootsUnchecked {
		g.logger.Warn("$HOME is unset or relative, so redact.files.roots were not checked against the home directory")
	}
	if opts.EscrowKey != nil {
		// The API answers on the listener ahead of every MCP route check (Host, tokens), as the
		// contract it keeps was served; its own key and failed-auth limit guard it.
		g.escrow = escrow.New(escrow.Options{
			KeyHash: opts.EscrowKey.Hash, MaxEntries: cfg.Escrow.MaxEntries, SourceArguments: cfg.Escrow.SourceArguments,
			Remote: remote, Logger: g.logger,
		})
		g.mux.Handle(escrow.Route, upstream.Recover(g.logger, "_escrow", g.escrow.Handler()))
		g.logger.Info("secret escrow enabled", "route", escrow.Route, "maxEntries", g.escrow.MaxEntries(), "keySource", opts.EscrowKey.Source)
	} else {
		g.logger.Info("secret escrow disabled", "reason", "no key hash in the config or the environment")
	}
	all := make([]string, 0, len(cfg.Servers))
	for name := range cfg.Servers {
		all = append(all, name)
	}
	sort.Strings(all)
	for _, name := range all {
		s := cfg.Servers[name]
		if s.Disabled {
			g.logger.Info("server disabled", "server", name)
			continue
		}
		srv, err := g.newServer(name, s)
		if err != nil {
			return nil, fmt.Errorf("servers.%s: %w", name, err)
		}
		g.servers[name] = srv
		g.names = append(g.names, name)
		g.mux.Handle("/"+name+"/mcp", g.route(srv, remote))
	}
	info := upstream.HealthInfo{Name: cfg.Name, Version: opts.Version, ServerCount: len(g.names)}
	g.mux.Handle("GET /_healthz", upstream.Recover(g.logger, "_healthz", upstream.HealthHandler(info, nil)))
	g.mux.Handle("GET /_readyz", upstream.Recover(g.logger, "_readyz", upstream.HealthHandler(info, g.Readiness)))
	if len(cfg.Admin.Tokens) > 0 {
		admin := upstream.NewTokens(cfg.Admin.Tokens)
		g.mux.Handle("GET /_status", upstream.Recover(g.logger, "_status",
			upstream.StatusHandler(admin, func() any { return g.Status() })))
	}
	g.srv = upstream.NewServer(cfg.Listen.Addr, g.mux, g.logger)
	g.srv.RegisterOnShutdown(func() { g.drainOnce.Do(func() { close(g.drain) }) })
	return g, nil
}

func (g *Gate) newServer(name string, s *config.Server) (*server, error) {
	var redaction *proxy.Redaction
	var engine *redact.Engine
	if *s.Redact.Enabled {
		var err error
		engine, err = redact.New(redact.Options{Russian: s.Redact.RU, HighEntropy: s.Redact.HighEntropy, DisableRules: s.Redact.DisableRules})
		if err != nil {
			return nil, err
		}
		redaction = proxy.NewRedaction(engine, g.replacer(name, s), int(*s.MaxMessageBytes))
	}
	var files proxy.FileScanner
	if f := s.Redact.Files; f != nil && engine != nil {
		o := filescan.Options{
			Server: name, Tools: f.Tools, Roots: f.Roots, MaxBytes: int64(*f.MaxBytes),
			TTL: s.Redact.EscrowTTL.D(), Engine: engine, Logger: g.logger.With("server", name),
		}
		if g.escrowFor(s) {
			o.Keep = g.escrow.KeepFile
		}
		sc := filescan.New(o)
		if missing := sc.MissingRoots(); len(missing) > 0 {
			g.logger.Warn("file roots do not exist yet; files written elsewhere are not scanned", "server", name, "roots", len(missing))
		}
		files = sc
	}
	mirror := proxy.New(proxy.Options{
		Name: name, Version: g.opts.Version, Policy: policy.New(s), ForwardMeta: s.ForwardMeta,
		Redaction: redaction, Files: files, Logger: g.logger,
	})
	o := DownstreamOptions(g.cfg, name, s, g.opts.Environ, g.opts.Version, oauth.NewStore(g.opts.StateDir), g.logger)
	o.Redactor = engine
	o.Notifications = mirror.Notifications()
	o.OnSession = mirror.OnSession
	o.LearnedPin = g.pins.get(name)
	o.OnPinLearned = func(v string) {
		if err := g.pins.set(name, v); err != nil {
			g.logger.Warn("cannot store the learned protocol pin", "server", name, "error", err.Error())
		}
	}
	if g.opts.Tune != nil {
		g.opts.Tune(&o)
	}
	sup, err := downstream.New(o)
	if err != nil {
		return nil, err
	}
	mirror.Attach(sup)
	return &server{name: name, cfg: s, sup: sup, mirror: mirror}, nil
}

// replacer returns what replaces the findings in a server's results: the test hook, the escrow's
// markers when the escrow is on for the server, or nil for the plain marker.
func (g *Gate) replacer(name string, s *config.Server) proxy.ReplacerFunc {
	switch {
	case g.opts.Replacer != nil:
		return func(r proxy.Request) redact.Replacer {
			if rep := g.opts.Replacer(name, r); rep != nil {
				return rep
			}
			return redact.Marker{}
		}
	case g.escrowFor(s):
		ttl := s.Redact.EscrowTTL.D()
		return func(r proxy.Request) redact.Replacer {
			return g.escrow.Replacer(escrow.Source{Server: name, Tool: r.Name, TTL: ttl, Arguments: r.Arguments})
		}
	}
	return nil
}

// escrowFor reports whether a server's findings and files are kept in the escrow.
func (g *Gate) escrowFor(s *config.Server) bool {
	return g.escrow != nil && *s.Redact.Escrow
}

// DownstreamOptions turns a server's config into supervisor options. An OAuth server takes its
// grant from store; with a nil store it has none.
func DownstreamOptions(cfg *config.Config, name string, s *config.Server, environ []string, version string, store *oauth.Store, logger *slog.Logger) downstream.Options {
	o := downstream.Options{
		Name:            name,
		Disabled:        s.Disabled,
		ClientName:      cfg.Name,
		ClientVersion:   version,
		CallTimeout:     s.CallTimeout.D(),
		MaxMessageBytes: int(*s.MaxMessageBytes),
		ProtocolVersion: s.ProtocolVersion,
		ProbeInterval:   s.ProbeInterval.D(),
		MaxBackoff:      s.Restart.MaxBackoff.D(),
		Logger:          logger,
	}
	if st := s.Stdio; st != nil {
		o.Stdio = &downstream.Stdio{
			Command: st.Command, Args: st.Args, Dir: st.Cwd, Env: st.Env,
			InheritEnv: st.InheritEnv, ParentEnv: environ,
		}
	} else {
		o.HTTP = &downstream.HTTP{URL: s.HTTP.URL, Headers: s.HTTP.Headers}
		if oc := s.HTTP.OAuth; oc != nil {
			o.HTTP.OAuth = oauth.NewSource(oauth.SourceOptions{
				Name: name, ServerURL: s.HTTP.URL, ClientID: oc.ClientID, ClientSecret: oc.ClientSecret,
				Store: store, HTTPClient: oauth.NewHTTPClient(), Logger: logger,
			})
		}
	}
	return o
}

// route builds the handler chain of a server's /<name>/mcp: recover, the request log, the Host
// check, the token check, cross-origin protection, 503 until the server has connected once, the
// body limit, and the SDK's stateless streamable handler.
func (g *Gate) route(s *server, remote upstream.RemoteFunc) http.Handler {
	mirror := s.mirror
	var h http.Handler = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mirror.Server() },
		&mcp.StreamableHTTPOptions{
			Stateless:                    true,
			PropagateRequestCancellation: true,
			DisableLocalhostProtection:   g.cfg.Listen.BehindProxy,
			MaxRequestBodyBytes:          upstream.MaxBodyBytes,
			Logger:                       upstream.SDKLogger(g.logger.With("server", s.name)),
		})
	h = upstream.ReadBody(upstream.MaxBodyBytes, upstream.BodyTimeout, g.endListenOnDrain(h))
	inner := h
	h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !mirror.Ready() {
			w.Header().Set("Retry-After", upstream.RetryAfter)
			http.Error(w, "Service Unavailable: the server has not connected yet", http.StatusServiceUnavailable)
			return
		}
		inner.ServeHTTP(w, r)
	})
	h = http.NewCrossOriginProtection().Handler(h)
	if tokens := g.cfg.EffectiveTokens(s.name); tokens != nil {
		h = upstream.RequireToken(upstream.NewTokens(tokens), h)
	}
	h = upstream.AllowHosts(g.cfg.Listen.AllowedHosts, h)
	if s.cfg.Log.Requests {
		h = upstream.LogRequests(g.logger, s.name, remote, h)
	}
	return upstream.Recover(g.logger, s.name, h)
}

// endListenOnDrain cancels a subscriptions/listen request when shutdown begins. The body has
// been read into memory by ReadBody.
func (g *Gate) endListenOnDrain(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && r.Body != http.NoBody {
			body, err := io.ReadAll(r.Body)
			if err == nil && isListen(body) {
				ctx, cancel := context.WithCancel(r.Context())
				defer cancel()
				go func() {
					select {
					case <-g.drain:
						cancel()
					case <-ctx.Done():
					}
				}()
				r = r.WithContext(ctx)
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		next.ServeHTTP(w, r)
	})
}

// isListen reports whether a request body is a subscriptions/listen request.
func isListen(body []byte) bool {
	if !bytes.Contains(body, []byte("subscriptions/listen")) {
		return false
	}
	var req struct {
		Method string `json:"method"`
	}
	return json.Unmarshal(body, &req) == nil && req.Method == "subscriptions/listen"
}

// Handler is the gate's HTTP handler.
func (g *Gate) Handler() http.Handler { return g.mux }

// Listen opens the configured listen address.
func (g *Gate) Listen(ctx context.Context) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(ctx, "tcp", g.cfg.Listen.Addr)
}

// Run starts every server and serves ln until ctx is done, then shuts down: it stops accepting,
// lets calls in flight finish for ShutdownGrace, and stops the servers in parallel.
func (g *Gate) Run(ctx context.Context, ln net.Listener) error {
	for _, name := range g.names {
		s := g.servers[name]
		// The mirror outlives ctx: calls finishing during the shutdown grace still get their
		// progress. shutdown closes it.
		s.mirror.Start(context.WithoutCancel(ctx))
		s.sup.Start(ctx)
	}
	var sweeper sync.WaitGroup
	defer sweeper.Wait()
	sweep, stopSweep := context.WithCancel(ctx)
	defer stopSweep()
	if g.escrow != nil {
		sweeper.Go(func() { g.escrow.Run(sweep) })
	}
	served := make(chan error, 1)
	go func() { served <- g.srv.Serve(ln) }()
	g.logger.Info("listening", "addr", ln.Addr().String(), "servers", len(g.names))

	startup, cancelStartup := context.WithTimeout(ctx, g.cfg.StartupGracePeriod.D())
	defer cancelStartup()
	startupDone := make(chan struct{})
	go func() {
		defer close(startupDone)
		g.awaitStartup(startup)
	}()

	var err error
	select {
	case <-ctx.Done():
		g.logger.Info("shutting down")
	case err = <-served:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	}
	cancelStartup()
	<-startupDone
	return errors.Join(err, g.shutdown(context.WithoutCancel(ctx)))
}

// awaitStartup marks the gate started once every server has connected, or when ctx ends.
func (g *Gate) awaitStartup(ctx context.Context) {
	t := time.NewTicker(readyPoll)
	defer t.Stop()
	for {
		all := true
		for _, name := range g.names {
			s := g.servers[name]
			// A server waiting for a login does not connect without someone; it does not hold
			// the startup.
			all = all && (s.mirror.Ready() || s.sup.Status().State == downstream.NeedsLogin)
		}
		if all {
			g.started.Store(true)
			g.logger.Info("every server connected")
			return
		}
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				g.started.Store(true)
				g.logger.Warn("reporting ready while servers are still connecting", "grace", g.cfg.StartupGracePeriod.D().String())
			}
			return
		case <-t.C:
		}
	}
}

// shutdown stops the listener and the servers; parent carries values only, it is never cancelled.
// It returns only the listener's errors.
func (g *Gate) shutdown(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, ShutdownGrace)
	defer cancel()
	var errs []error
	if err := g.srv.Shutdown(ctx); err != nil {
		g.logger.Warn("calls still running at shutdown are cut off", "error", err.Error())
		if err := g.srv.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs = append(errs, err)
		}
	}
	// A server that does not stop in time is logged; it does not fail the shutdown, which the
	// signal asked for.
	var wg sync.WaitGroup
	for _, name := range g.names {
		s := g.servers[name]
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(parent, stopTimeout)
			defer cancel()
			if err := s.sup.Stop(ctx); err != nil {
				g.logger.Error("server did not stop", "server", s.name, "error", err.Error())
			}
			s.mirror.Close()
		})
	}
	wg.Wait()
	return errors.Join(errs...)
}

// Readiness reports the state /_readyz serves. A server is mounted once its catalog was listed;
// it is unhealthy when it was mounted and has lost its connection since. A server waiting for
// an OAuth login is reported whether or not it was mounted.
func (g *Gate) Readiness() upstream.Readiness {
	r := upstream.Readiness{Started: g.started.Load()}
	if !r.Started {
		return r
	}
	for _, name := range g.names {
		s := g.servers[name]
		st := s.sup.Status().State
		if st == downstream.NeedsLogin {
			r.NeedsLogin = append(r.NeedsLogin, name)
		}
		if !s.mirror.Ready() {
			continue
		}
		r.Mounted++
		if st != downstream.Ready && st != downstream.Degraded {
			r.Unhealthy = append(r.Unhealthy, name)
		}
	}
	return r
}

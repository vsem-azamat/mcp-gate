// Package gate assembles mcp-gate from its config: a supervisor and a mirror for every server,
// the HTTP routes in front of them, readiness after the startup grace period, reloads of the
// config, and shutdown.
package gate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vsem-azamat/mcp-gate/internal/approval"
	"github.com/vsem-azamat/mcp-gate/internal/audit"
	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/downstream"
	"github.com/vsem-azamat/mcp-gate/internal/escrow"
	"github.com/vsem-azamat/mcp-gate/internal/metrics"
	"github.com/vsem-azamat/mcp-gate/internal/oauth"
	"github.com/vsem-azamat/mcp-gate/internal/proxy"
	"github.com/vsem-azamat/mcp-gate/internal/redact"
	"github.com/vsem-azamat/mcp-gate/internal/systemd"
	"github.com/vsem-azamat/mcp-gate/internal/toolpins"
	"github.com/vsem-azamat/mcp-gate/internal/upstream"
)

// Shutdown budget.
const (
	// ShutdownGrace is how long calls in flight may finish once shutdown begins.
	ShutdownGrace = 10 * time.Second
	// drainLinger is how long, at the start of the shutdown grace, requests that arrive on open
	// connections are still served, each connection closed after its response, before the
	// connections that are idle are closed.
	drainLinger = time.Second
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
	// StateDir, if set, is where learned protocol pins and tool pins are kept; without one, tool
	// pins are kept in memory and no server can hold its tools.
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
	// Notify, if set, is told the gate's state in sd_notify form: systemd.Ready once startup is
	// over, systemd.Stopping when shutdown begins.
	Notify func(state string)
	// Level, if set, is the level of Logger's handler, which a reload sets from logLevel.
	Level *slog.LevelVar
}

// Gate is a configured mcp-gate. What a reload can change is in an immutable snapshot that every
// request takes once, when it arrives; the rest is fixed at the start.
type Gate struct {
	opts Options
	// boot is the config the gate started with: listen.addr, the escrow and startupGracePeriod
	// stay as it says until a restart.
	boot   *config.Config
	logger *slog.Logger
	escrow *escrow.Escrow // nil when off
	// escrowAPI is the escrow API that every snapshot mounts at /_escrow/; nil when the escrow
	// is off or not served on the listener.
	escrowAPI http.Handler
	srv       *upstream.Server
	sock      *upstream.Server // serves the escrow socket; nil without one
	// metrics counts for the life of the process; audit is the sink of every mirror and of the
	// aggregate: the call lines and the metrics. metricsSrv serves /_metrics on metrics.addr,
	// nil without one.
	metrics    *metrics.Registry
	audit      audit.Sink
	metricsSrv *upstream.Server
	pins       *pinStore
	toolPins   *toolpins.Store
	// approvals holds the tool calls waiting for the owner, under every snapshot; defaultRules
	// redacts the arguments shown of a server whose results are not redacted.
	approvals *approval.Store
	// adminLimit bounds guessing of the admin tokens, across reloads.
	adminLimit   *escrow.AuthLimit
	defaultRules *redact.Engine
	// startedAt is when the gate was built; file scanning keeps in the escrow only files written
	// since then, across reloads.
	startedAt time.Time
	started   atomic.Bool
	// startupOver is closed when the startup watcher returns: started, or shutting down first.
	startupOver chan struct{}
	// drain is closed when shutdown begins; it ends the subscriptions/listen streams, which
	// would otherwise hold the shutdown for its whole grace.
	drain     chan struct{}
	drainOnce sync.Once

	snap atomic.Pointer[snapshot]

	// notifyMu orders the notifications; stopSent is set once STOPPING=1 was sent.
	notifyMu sync.Mutex
	stopSent bool
	// served is the address of the listener Run serves; guarded by mu.
	served string
	// running is closed once Run has started the servers.
	running chan struct{}
	// mu serializes reloads with the start and the shutdown, and guards closing and retired.
	mu      sync.Mutex
	closing bool
	// retired are the routes that reloads replaced and that still have requests in flight.
	retired []*route
	// leftover are servers that reloads replaced and did not stop: the shutdown began first, or
	// the old process did not end in time. The shutdown stops them.
	leftover []*server
	// stopping are the old processes of replaced servers whose stop timed out; a runtime with
	// the same downstream settings starts only once they have ended.
	stopping []*pendingStop
	// retireCtx is cancelled when shutdown begins, which ends the waits of reloads for calls in
	// flight; drained is closed once the shutdown has drained the listener, after which the
	// mirrors of replaced routes are closed; retiring counts those not closed yet.
	retireCtx    context.Context
	stopRetiring context.CancelFunc
	drained      chan struct{}
	drainedOnce  sync.Once
	retiring     sync.WaitGroup
}

// New builds a gate from its config. It starts nothing.
func New(opts Options) (*Gate, error) {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	cfg := opts.Config
	g := &Gate{
		opts: opts, boot: cfg, logger: opts.Logger, drain: make(chan struct{}), startupOver: make(chan struct{}),
		running: make(chan struct{}), drained: make(chan struct{}), startedAt: time.Now(),
	}
	g.retireCtx, g.stopRetiring = context.WithCancel(context.Background())
	g.metrics = metrics.New()
	g.audit = audit.Tee(audit.Log(g.logger), g.metrics)
	g.toolPins = toolpins.New(opts.StateDir)
	g.approvals = approval.NewStore(g.logger)
	g.adminLimit = escrow.NewAuthLimit()
	var err error
	if g.defaultRules, err = redact.New(redact.Options{}); err != nil {
		return nil, err
	}
	g.audit = audit.Tee(audit.Log(g.logger), g.metrics)
	if g.pins, err = loadPins(opts.StateDir); err != nil {
		g.logger.Warn("cannot read the learned protocol pins; starting without them", "error", err.Error())
	}
	if opts.EscrowKey != nil {
		// The API answers on the listener ahead of every MCP route check (Host, tokens), as the
		// contract it keeps was served; its own key and failed-auth limit guard it.
		g.escrow = escrow.New(escrow.Options{
			KeyHash: opts.EscrowKey.Hash, MaxEntries: cfg.Escrow.MaxEntries, SourceArguments: cfg.Escrow.SourceArguments,
			AllowUIDs: socketUIDs(cfg.Escrow.Socket), Logger: g.logger,
			// The client address under the current listen settings, which a reload may change.
			Remote: func(r *http.Request) string { return g.snap.Load().remote(r) },
		})
		api := upstream.Recover(g.logger, "_escrow", g.escrow.Handler())
		if *cfg.Escrow.TCP {
			g.escrowAPI = api
		}
		if cfg.Escrow.Socket != nil {
			if slices.Contains(cfg.Escrow.Socket.AllowUIDs, os.Geteuid()) {
				g.logger.Warn("escrow.socket.allowUIDs lists the gate's own user",
					"risk", "the stdio servers run as that user and can start processes outside the gate's tree "+
						"(through systemd-run, tmux, ssh or ptrace) that read secrets without the key")
			}
			if len(cfg.Escrow.Socket.AllowUIDs) > 0 && !escrow.OthersProcVisible() {
				g.logger.Warn("escrow socket: other users' /proc entries are hidden (ProtectProc= or hidepid), so the process-tree check "+
					"cannot place most peers and keyless access fails closed: they need the key", "allowUIDs", cfg.Escrow.Socket.AllowUIDs)
			}
			mux := http.NewServeMux()
			mux.Handle(escrow.Route, api)
			g.sock = upstream.NewServer("", mux, g.logger)
			connContext := g.sock.ConnContext
			g.sock.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
				return escrow.ConnContext(connContext(ctx, c), c)
			}
		}
		g.logger.Info("secret escrow enabled", "route", escrow.Route, "tcp", *cfg.Escrow.TCP,
			"maxEntries", g.escrow.MaxEntries(), "keySource", opts.EscrowKey.Source)
	} else {
		g.logger.Info("secret escrow disabled", "reason", "no key hash in the config or the environment")
		if cfg.Escrow.Socket != nil {
			g.logger.Warn("escrow.socket is set but the escrow is off: no socket is opened")
		}
	}
	sn, err := g.build(cfg, nil)
	if err != nil {
		return nil, err
	}
	g.snap.Store(sn)
	g.prunePins(cfg)
	if cfg.Metrics.Addr != "" {
		mux := http.NewServeMux()
		mux.Handle("GET "+metricsRoute, g.metricsHandler())
		// No token guards it, so a page a browser on this host opens must not reach it through
		// a name that resolves to the loopback address (DNS rebinding): only loopback Hosts.
		g.metricsSrv = upstream.NewServer(cfg.Metrics.Addr, upstream.Recover(g.logger, "_metrics", upstream.AllowLoopbackHosts(mux)), g.logger)
	}
	g.srv = upstream.NewServer(cfg.Listen.Addr, http.HandlerFunc(g.serveHTTP), g.logger)
	g.srv.RegisterOnShutdown(func() { g.drainOnce.Do(func() { close(g.drain) }) })
	return g, nil
}

// prunePins drops the learned pins that no longer apply under cfg.
func (g *Gate) prunePins(cfg *config.Config) {
	if err := g.pins.prune(cfg); err != nil {
		g.logger.Warn("cannot store the learned protocol pins", "error", err.Error())
	}
}

// remoteOf returns how the client address of a request is read under a listen config.
func remoteOf(l config.Listen) upstream.RemoteFunc {
	trusted := make([]netip.Prefix, 0, len(l.TrustedProxies))
	for _, p := range l.TrustedProxies {
		if pp, err := netip.ParsePrefix(p); err == nil {
			trusted = append(trusted, pp)
		}
	}
	return upstream.NewRemote(l.BehindProxy, trusted)
}

// serveHTTP serves a request from the current snapshot.
func (g *Gate) serveHTTP(w http.ResponseWriter, r *http.Request) {
	g.snap.Load().mux.ServeHTTP(w, r)
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

// socketUIDs returns the user IDs the escrow socket serves without a key: only those listed.
func socketUIDs(s *config.EscrowSocket) []int {
	if s == nil || s.AllowUIDs == nil {
		return []int{}
	}
	return s.AllowUIDs
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
		o.HTTP = &downstream.HTTP{URL: s.HTTP.URL, Headers: s.HTTP.Headers, SSE: s.HTTP.SSE()}
		if oc := s.HTTP.OAuth; oc != nil {
			o.HTTP.OAuth = oauth.NewSource(oauth.SourceOptions{
				Name: name, ServerURL: s.HTTP.URL, ClientID: oc.ClientID, ClientSecret: oc.ClientSecret,
				Store: store, HTTPClient: oauth.NewHTTPClient(s.HTTP.URL), Logger: logger,
			})
		}
	}
	return o
}

// Handler is the gate's HTTP handler.
func (g *Gate) Handler() http.Handler { return http.HandlerFunc(g.serveHTTP) }

// Listen opens the configured listen address.
func (g *Gate) Listen(ctx context.Context) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(ctx, "tcp", g.boot.Listen.Addr)
}

// Run starts every server and serves ln, and the escrow socket when there is one, until ctx is
// done, then shuts down: it stops accepting, lets calls in flight finish for ShutdownGrace, and
// stops the servers in parallel. The socket file is removed on the way out.
func (g *Gate) Run(ctx context.Context, ln net.Listener) error {
	var metricsServed chan error
	var ml net.Listener
	if g.metricsSrv != nil {
		var lc net.ListenConfig
		var err error
		if ml, err = lc.Listen(ctx, "tcp", g.boot.Metrics.Addr); err != nil {
			_ = ln.Close()
			return fmt.Errorf("metrics.addr: %w", err)
		}
	}
	var sockServed chan error
	if g.sock != nil {
		s := g.boot.Escrow.Socket
		sl, err := escrow.ListenSocket(ctx, s.Path, fs.FileMode(*s.Mode))
		if err != nil {
			_ = ln.Close()
			if ml != nil {
				_ = ml.Close()
			}
			return err
		}
		sockServed = make(chan error, 1)
		go func() { sockServed <- g.sock.Serve(sl) }()
		g.logger.Info("escrow socket listening", "path", s.Path, "allowUIDs", socketUIDs(s))
	}
	if ml != nil {
		metricsServed = make(chan error, 1)
		go func() { metricsServed <- g.metricsSrv.Serve(ml) }()
		g.logger.Info("metrics listening", "addr", ml.Addr().String())
	}
	g.mu.Lock()
	g.served = ln.Addr().String()
	sn := g.snap.Load()
	// On the address served, which a socket systemd passed may set rather than listen.addr.
	if g.escrowAPI != nil && !sn.cfg.Listen.BehindProxy && config.LoopbackAddr(g.served) {
		g.logger.Warn("the escrow API is on a loopback listener without listen.behindProxy: behind a reverse proxy " +
			"on this host every client is 127.0.0.1 and shares one failed-auth budget; set behindProxy and trustedProxies")
	}
	for _, name := range sn.names {
		sn.servers[name].rt.start(ctx, g.boot.StartupGracePeriod.D())
	}
	close(g.running)
	g.mu.Unlock()
	var sweeper sync.WaitGroup
	defer sweeper.Wait()
	sweep, stopSweep := context.WithCancel(ctx)
	defer stopSweep()
	if g.escrow != nil {
		sweeper.Go(func() { g.escrow.Run(sweep) })
	}
	served := make(chan error, 1)
	go func() { served <- g.srv.Serve(ln) }()
	g.logger.Info("listening", "addr", ln.Addr().String(), "servers", len(sn.names))

	startup, cancelStartup := context.WithTimeout(ctx, g.boot.StartupGracePeriod.D())
	defer cancelStartup()
	startupDone := make(chan struct{})
	go func() {
		defer close(startupDone)
		defer close(g.startupOver)
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
	// After the startup watcher, so that READY=1 never follows it.
	g.notify(systemd.Stopping)
	err = errors.Join(err, g.shutdown(context.WithoutCancel(ctx)))
	for _, c := range []chan error{sockServed, metricsServed} {
		if c == nil {
			continue
		}
		if serr := <-c; !errors.Is(serr, http.ErrServerClosed) {
			err = errors.Join(err, serr)
		}
	}
	return err
}

// awaitStartup marks the gate started once every server has connected, or when ctx ends.
func (g *Gate) awaitStartup(ctx context.Context) {
	t := time.NewTicker(readyPoll)
	defer t.Stop()
	for {
		all := true
		sn := g.snap.Load()
		for _, name := range sn.names {
			s := sn.servers[name]
			// A server waiting for a login does not connect without someone; it does not hold
			// the startup.
			all = all && (s.mirror.Ready() || s.sup.Status().AwaitsLogin())
		}
		if all {
			g.markStarted()
			g.logger.Info("every server connected")
			return
		}
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				g.markStarted()
				g.logger.Warn("reporting ready while servers are still connecting", "grace", g.boot.StartupGracePeriod.D().String())
			}
			return
		case <-t.C:
		}
	}
}

// markStarted ends the startup and tells systemd the gate is ready.
func (g *Gate) markStarted() {
	g.started.Store(true)
	g.notify(systemd.Ready)
}

// notify passes a state notification to Options.Notify.
// Once STOPPING=1 is sent, nothing else is: a reload that ends during the shutdown does not
// report READY=1.
func (g *Gate) notify(state string) {
	if g.opts.Notify == nil {
		return
	}
	g.notifyMu.Lock()
	defer g.notifyMu.Unlock()
	if g.stopSent {
		return
	}
	g.stopSent = state == systemd.Stopping
	g.opts.Notify(state)
}

// awaitReady holds a request that ready refuses while ready says it is pending (the gate is
// starting, or the server restarts after a reload), until ready takes it or no longer says it is
// pending, at most startupGracePeriod, and reports whether ready took it. A gate that was just
// restarted, or a server a reload restarts, thus answers calls once the server is back instead of
// refusing them while it reconnects.
func (g *Gate) awaitReady(r *http.Request, ready func(*http.Request) (ok, pending bool)) bool {
	ok, pending := ready(r)
	if ok || !pending {
		return ok
	}
	limit := time.NewTimer(g.boot.StartupGracePeriod.D())
	defer limit.Stop()
	t := time.NewTicker(readyPoll)
	defer t.Stop()
	for {
		select {
		case <-limit.C:
			ok, _ = ready(r)
			return ok
		case <-r.Context().Done():
			return false
		case <-g.drain:
			// The shutdown began: refuse at once rather than hold the grace.
			return false
		case <-g.startupOver:
		case <-t.C:
		}
		if ok, pending = ready(r); ok || !pending {
			return ok
		}
	}
}

// shutdown stops the listener and the servers; parent carries values only, it is never cancelled.
// It returns only the listener's errors.
func (g *Gate) shutdown(parent context.Context) error {
	// A reload waiting for calls in flight stops waiting, and so do the calls held for approval.
	g.stopRetiring()
	g.approvals.Close()
	ctx, cancel := context.WithTimeout(parent, ShutdownGrace)
	defer cancel()
	var errs []error
	// The socket server and the metrics listener shut down alongside the listener, so that a slow
	// client of theirs does not take the grace from the calls in flight; closing the socket server
	// also removes the socket file.
	var sockDone sync.WaitGroup
	for _, s := range []*upstream.Server{g.sock, g.metricsSrv} {
		if s == nil {
			continue
		}
		sockDone.Go(func() {
			if err := s.Shutdown(ctx); err != nil {
				_ = s.Close()
			}
		})
	}
	defer sockDone.Wait()
	g.drainOnce.Do(func() { close(g.drain) })
	g.srv.Drain(ctx, drainLinger)
	if err := g.srv.Shutdown(ctx); err != nil {
		g.logger.Warn("calls still running at shutdown are cut off", "error", err.Error())
		if err := g.srv.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs = append(errs, err)
		}
	}
	g.drainedOnce.Do(func() { close(g.drained) })
	g.mu.Lock()
	g.closing = true
	sn := g.snap.Load()
	servers := make([]*server, 0, len(sn.names)+len(g.leftover))
	for _, name := range sn.names {
		servers = append(servers, sn.servers[name])
	}
	servers = append(servers, g.leftover...)
	g.mu.Unlock()
	// A server that does not stop in time is logged; it does not fail the shutdown, which the
	// signal asked for.
	var wg sync.WaitGroup
	for _, s := range servers {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(parent, stopTimeout)
			defer cancel()
			if err := s.sup.Stop(ctx); err != nil {
				g.logger.Error("server did not stop", "server", s.name, "error", err.Error())
			}
			s.rt.src.Close()
		})
	}
	wg.Wait()
	g.retiring.Wait()
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
	sn := g.snap.Load()
	for _, name := range sn.names {
		s := sn.servers[name]
		st := s.sup.Status()
		if st.AwaitsLogin() {
			r.NeedsLogin = append(r.NeedsLogin, name)
		}
		if !s.mirror.Ready() {
			continue
		}
		r.Mounted++
		if !st.Connected() {
			r.Unhealthy = append(r.Unhealthy, name)
		}
	}
	return r
}

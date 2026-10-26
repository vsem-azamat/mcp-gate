package gate

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
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

// snapshot is what one config makes of the gate: the enabled servers, each with the mirror that
// applies the config's policy and redaction to it, and the routes. It does not change once built.
// A reload builds the next one and swaps it in. A request takes the snapshot once, when it
// arrives, and then the route it was matched to, which it keeps until it ends, so that it never
// sees part of one config and part of another.
type snapshot struct {
	cfg     *config.Config
	names   []string // enabled servers, sorted
	servers map[string]*server
	routes  map[string]*route // by pattern
	remote  upstream.RemoteFunc
	mux     *http.ServeMux
}

// server is one enabled server in a snapshot.
type server struct {
	name   string
	cfg    *config.Server
	rt     *serverRuntime
	sup    *downstream.Supervisor // rt.sup
	mirror *proxy.Mirror
	// mkey is what the mirror was built from; a snapshot whose server has the same key and
	// runtime keeps the mirror.
	mkey map[string]any
	// engine is the server's redaction engine, nil with redaction off; the supervisor scrubs its
	// errors and the child's stderr with it.
	engine *redact.Engine
}

// serverRuntime is what lasts of a server across reloads that leave its downstream settings as they
// are: its supervisor and its source, which keeps the server's listed catalog, its counters and
// its progress routing.
type serverRuntime struct {
	key map[string]any // what the supervisor was built from
	sup *downstream.Supervisor
	src *proxy.Source
	// restarting is set for a runtime that replaces one a reload changed, until it has
	// connected or the hold limit has passed; its route holds requests meanwhile.
	restarting atomic.Bool
}

// start starts the source and the supervisor. The source outlives ctx: calls finishing during
// the shutdown grace still get their progress. A restarting runtime stops holding requests once
// the server has connected, needs a login or stopped, or after hold.
func (rt *serverRuntime) start(ctx context.Context, hold time.Duration) {
	rt.src.Start(context.WithoutCancel(ctx))
	rt.sup.Start(ctx)
	if rt.restarting.Load() {
		go func() {
			defer rt.restarting.Store(false)
			wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), hold)
			defer cancel()
			settled := []downstream.State{downstream.Ready, downstream.Degraded, downstream.NeedsLogin, downstream.Stopped}
			_ = rt.sup.Wait(wctx, func(st downstream.Status) bool { return slices.Contains(settled, st.State) })
		}()
	}
}

// route is the handler of one pattern of a snapshot. A reload keeps a route whose inputs are
// unchanged, with its listen streams; it retires one it replaces, which ends them.
type route struct {
	key     map[string]any
	handler http.Handler
	mirrors []*proxy.Mirror
	agg     *proxy.Aggregate // the aggregate route's
	again   http.Handler     // serves a request that arrives once the route is retired
	// ended is closed when the route is retired; it ends the subscriptions/listen streams it
	// serves, which would otherwise keep it for good.
	ended chan struct{}

	mu      sync.Mutex
	active  int
	retired bool
	idle    chan struct{} // closed once retired with no request in flight
}

// arrived is a request as it reached a route: its context before the route's handlers added to
// it, and the Authorization header the client sent.
type arrived struct {
	ctx  context.Context
	auth []string
}

type arrivedKey struct{}

func newRoute(key map[string]any, again http.Handler) *route {
	return &route{key: key, again: again, ended: make(chan struct{}), idle: make(chan struct{})}
}

func (rt *route) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rt.mu.Lock()
	if rt.retired {
		rt.mu.Unlock()
		// Replaced since the request took its snapshot: the current snapshot serves it.
		rt.again.ServeHTTP(w, r)
		return
	}
	rt.active++
	rt.mu.Unlock()
	// A request handed back starts again as it arrived: the aggregate's token check rewrites the
	// header, and the token checks put what they found in the context.
	r = r.WithContext(context.WithValue(r.Context(), arrivedKey{}, &arrived{ctx: r.Context(), auth: r.Header.Values("Authorization")}))
	defer func() {
		rt.mu.Lock()
		rt.active--
		if rt.retired && rt.active == 0 {
			close(rt.idle)
		}
		rt.mu.Unlock()
	}()
	rt.handler.ServeHTTP(w, r)
}

// retire marks the route replaced: its listen streams end, and idle is closed once its requests
// in flight have ended.
func (rt *route) retire() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.retired {
		return
	}
	rt.retired = true
	close(rt.ended)
	if rt.active == 0 {
		close(rt.idle)
	}
}

func (rt *route) isIdle() bool {
	select {
	case <-rt.idle:
		return true
	default:
		return false
	}
}

// keeps reports whether a route built from key and mirrors would be rt: the same mirrors, by
// identity, and an equal key, which holds config values only.
func (rt *route) keeps(key map[string]any, mirrors []*proxy.Mirror) bool {
	return rt != nil && slices.Equal(rt.mirrors, mirrors) && reflect.DeepEqual(rt.key, key)
}

// uses reports whether the route serves a mirror of src.
func (rt *route) uses(src *proxy.Source) bool {
	return slices.ContainsFunc(rt.mirrors, func(m *proxy.Mirror) bool { return m.Source() == src })
}

// build makes the snapshot of cfg, keeping from prev the runtimes of servers whose downstream
// settings are unchanged, the mirrors whose inputs are unchanged, and the routes whose inputs
// are. New runtimes are not started. The new mirrors are attached to their sources and serve at
// once what those have listed; when build fails it closes them, and nothing else has changed.
func (g *Gate) build(cfg *config.Config, prev *snapshot) (sn *snapshot, err error) {
	sn = &snapshot{cfg: cfg, servers: map[string]*server{}, routes: map[string]*route{}, remote: remoteOf(cfg.Listen)}
	var fresh []*proxy.Mirror
	defer func() {
		if err != nil {
			for _, m := range fresh {
				m.Close()
			}
		}
	}()
	if cfg.Listen.BehindProxy && len(cfg.Listen.AllowedHosts) == 0 {
		g.logger.Warn("listen.behindProxy is set without listen.allowedHosts: no Host is checked, so the proxy must check it")
	}
	for _, w := range cfg.Warnings {
		g.logger.Warn("config: " + w)
	}
	if cfg.FileRootsUnchecked {
		g.logger.Warn("$HOME is unset or relative, so redact.files.roots were not checked against the home directory")
	}
	all := slices.Sorted(maps.Keys(cfg.Servers))
	for _, name := range all {
		s := cfg.Servers[name]
		if s.Disabled {
			g.logger.Info("server disabled", "server", name)
			continue
		}
		var old *server
		if prev != nil {
			old = prev.servers[name]
		}
		srv, made, err := g.newServer(cfg, name, s, old)
		if made {
			fresh = append(fresh, srv.mirror)
		}
		if err != nil {
			return nil, fmt.Errorf("servers.%s: %w", name, err)
		}
		sn.servers[name] = srv
		sn.names = append(sn.names, name)
	}
	mux := http.NewServeMux()
	if g.escrowAPI != nil {
		mux.Handle(escrow.Route, g.escrowAPI)
	}
	again := http.HandlerFunc(g.serveHTTP)
	for _, name := range sn.names {
		pattern := "/" + name + "/mcp"
		rt := g.serverRoute(sn, sn.servers[name], prev.route(pattern), again)
		sn.routes[pattern] = rt
		mux.Handle(pattern, rt)
	}
	if cfg.Aggregate != nil {
		rt, err := g.aggregateRoute(sn, prev.route(config.AggregatePath), again)
		if err != nil {
			return nil, fmt.Errorf("aggregate: %w", err)
		}
		sn.routes[config.AggregatePath] = rt
		mux.Handle(config.AggregatePath, rt)
	}
	info := upstream.HealthInfo{Name: cfg.Name, Version: g.opts.Version, ServerCount: len(sn.names)}
	mux.Handle("GET /_healthz", upstream.Recover(g.logger, "_healthz", upstream.HealthHandler(info, nil)))
	mux.Handle("GET /_readyz", upstream.Recover(g.logger, "_readyz", upstream.HealthHandler(info, g.Readiness)))
	if len(cfg.Admin.Tokens) > 0 {
		admin := upstream.NewTokens(cfg.Admin.Tokens)
		mux.Handle("GET /_status", upstream.Recover(g.logger, "_status",
			upstream.StatusHandler(admin, func() any { return g.Status() })))
	}
	sn.mux = mux
	return sn, nil
}

// route returns the route of a pattern, nil without one; sn may be nil.
func (sn *snapshot) route(pattern string) *route {
	if sn == nil {
		return nil
	}
	return sn.routes[pattern]
}

// newServer returns a server of the snapshot being built. It keeps the runtime of old, the
// server of the same name being replaced, when the downstream settings are unchanged, and then
// its mirror too when the mirror's inputs are; made reports a mirror it made.
func (g *Gate) newServer(cfg *config.Config, name string, s *config.Server, old *server) (srv *server, made bool, err error) {
	dkey, mkey := downstreamKey(cfg, s), mirrorKey(cfg, name, s)
	var rt *serverRuntime
	if old != nil && reflect.DeepEqual(old.rt.key, dkey) {
		rt = old.rt
		if reflect.DeepEqual(old.mkey, mkey) {
			return &server{name: name, cfg: s, rt: rt, sup: rt.sup, mirror: old.mirror, mkey: mkey, engine: old.engine}, false, nil
		}
	}
	var redaction *proxy.Redaction
	var engine *redact.Engine
	if *s.Redact.Enabled {
		if engine, err = redact.New(redact.Options{Russian: s.Redact.RU, HighEntropy: s.Redact.HighEntropy, DisableRules: s.Redact.DisableRules}); err != nil {
			return nil, false, err
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
	if rt == nil {
		if rt, err = g.newRuntime(cfg, name, s, dkey, engine); err != nil {
			return nil, false, err
		}
		if old != nil {
			rt.src.Inherit(old.rt.src)
			rt.restarting.Store(true)
		}
	}
	mirror := proxy.New(proxy.Options{
		Name: name, Version: g.opts.Version, Policy: policy.New(s), Tokens: policy.NewTokens(cfg, name), ForwardMeta: s.ForwardMeta,
		Redaction: redaction, Files: files, Logger: g.logger, Source: rt.src,
	})
	return &server{name: name, cfg: s, rt: rt, sup: rt.sup, mirror: mirror, mkey: mkey, engine: engine}, true, nil
}

// newRuntime builds the supervisor and the source of a server, not started.
func (g *Gate) newRuntime(cfg *config.Config, name string, s *config.Server, key map[string]any, engine *redact.Engine) (*serverRuntime, error) {
	src := proxy.NewSource(name, g.logger)
	o := DownstreamOptions(cfg, name, s, g.opts.Environ, g.opts.Version, oauth.NewStore(g.opts.StateDir), g.logger)
	o.Redactor = engine
	o.Notifications = src.Notifications()
	o.OnSession = src.OnSession
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
	src.Attach(sup)
	return &serverRuntime{key: key, sup: sup, src: src}, nil
}

// serverRoute returns the route of a server's /<name>/mcp: prev, the route of the snapshot being
// replaced, when its inputs are unchanged, else a new one (see chain).
func (g *Gate) serverRoute(sn *snapshot, s *server, prev *route, again http.Handler) *route {
	tokens := sn.cfg.EffectiveTokens(s.name)
	key := routeKey(sn.cfg, s.cfg)
	mirrors := []*proxy.Mirror{s.mirror}
	if prev.keeps(key, mirrors) {
		return prev
	}
	rt := newRoute(key, again)
	rt.mirrors = mirrors
	mirror := s.mirror
	var authorize func(http.Handler) http.Handler
	if tokens != nil {
		t := upstream.NewTokens(tokens)
		authorize = func(h http.Handler) http.Handler { return upstream.RequireToken(t, h) }
	}
	rt.handler = g.chain(sn, rt, s.name, s.cfg.Log.Requests, authorize,
		func(*http.Request) (bool, bool) {
			// Held while the gate starts or the server restarts after a reload; a server waiting
			// for a login does not connect without someone.
			restarting := s.rt.restarting.Load()
			return mirror.Ready() && !restarting,
				(!g.started.Load() || restarting) && s.sup.Status().State != downstream.NeedsLogin
		},
		func(r *http.Request) *mcp.Server {
			return mirror.ServerFor(upstream.Principal(auth.TokenInfoFromContext(r.Context())))
		})
	return rt
}

// chain builds the handler of a route around the SDK's stateless streamable handlers for the
// servers getServer returns: recover, the request log when logRequests, the Host check,
// authorize when set, cross-origin protection, 503 while ready is false (see awaitReady), the
// body limit, and respond choosing between an event stream and plain JSON.
func (g *Gate) chain(sn *snapshot, rt *route, name string, logRequests bool, authorize func(http.Handler) http.Handler,
	ready func(*http.Request) (ok, pending bool), getServer func(*http.Request) *mcp.Server,
) http.Handler {
	opts := mcp.StreamableHTTPOptions{
		Stateless:                    true,
		PropagateRequestCancellation: true,
		DisableLocalhostProtection:   sn.cfg.Listen.BehindProxy,
		MaxRequestBodyBytes:          upstream.MaxBodyBytes,
		Logger:                       upstream.SDKLogger(g.logger.With("server", name)),
	}
	plainOpts := opts
	plainOpts.JSONResponse = true
	stream := mcp.NewStreamableHTTPHandler(getServer, &opts)
	plain := mcp.NewStreamableHTTPHandler(getServer, &plainOpts)
	served := g.respond(stream, plain, rt.ended)
	h := upstream.ReadBody(upstream.MaxBodyBytes, upstream.BodyTimeout, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The token was checked when the headers arrived. A request whose body was still arriving,
		// or that was held during startup, when a reload replaced the route is served by the
		// current snapshot, which checks it again: a token the reload revoked runs nothing.
		select {
		case <-rt.ended:
			upstream.MarkHandedOn(r.Context())
			first, _ := r.Context().Value(arrivedKey{}).(*arrived)
			again := r.Clone(first.ctx) //nolint:contextcheck // the request's own context as it reached the route, an ancestor of r.Context(): only what the old route added is dropped
			if body, ok := upstream.BodyBytes(r); ok {
				again.Body = io.NopCloser(bytes.NewReader(body))
			}
			again.Header.Del("Authorization")
			if first.auth != nil {
				again.Header["Authorization"] = first.auth
			}
			rt.again.ServeHTTP(w, again)
			return
		default:
		}
		served.ServeHTTP(w, r)
	}))
	inner := h
	h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.awaitReady(r, ready) {
			w.Header().Set("Retry-After", upstream.RetryAfter)
			http.Error(w, "Service Unavailable: the server has not connected yet", http.StatusServiceUnavailable)
			return
		}
		inner.ServeHTTP(w, r)
	})
	h = http.NewCrossOriginProtection().Handler(h)
	if authorize != nil {
		h = authorize(h)
	}
	h = upstream.AllowHosts(sn.cfg.Listen.AllowedHosts, h)
	if logRequests {
		h = upstream.LogRequests(g.logger, name, sn.remote, h)
	}
	return upstream.Recover(g.logger, name, h)
}

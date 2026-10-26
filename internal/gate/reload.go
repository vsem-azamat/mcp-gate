package gate

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/proxy"
	"github.com/vsem-azamat/mcp-gate/internal/systemd"
)

// errClosing is returned by Reload once the shutdown has begun.
var errClosing = errors.New("the gate is shutting down")

// Reload loads a config with load and applies it to the running gate; before Run has started
// the gate it waits for that, or for ctx. Once startup is over it tells systemd, through
// Options.Notify, that a reload runs, and that it is over, whatever its outcome.
//
// A config that does not load, or whose snapshot cannot be built, is returned as an error and
// the gate keeps the one it has. Otherwise the next snapshot is swapped in at once: requests that
// arrive from then on get the new tokens, filters, redaction and request logging, and those in
// flight finish on the route they arrived on. What a field's change does is set in configFields
// and serverFields: a server whose downstream settings are unchanged keeps running, and keeps its
// mirror and routes when their inputs are unchanged too, with their listen streams. Servers whose
// downstream settings changed, and removed or disabled ones, are stopped once the requests in
// flight on the routes that reach them have ended, at most ShutdownGrace after the swap or until
// ctx is done; new and changed servers are started after that, so that two processes of a stdio
// server never run together. Reload returns then.
func (g *Gate) Reload(ctx context.Context, load func() (*config.Config, error)) error {
	select {
	case <-g.running:
	case <-ctx.Done():
		return ctx.Err()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closing || g.retireCtx.Err() != nil {
		return errClosing
	}
	if g.started.Load() {
		g.notify(systemd.Reloading())
		defer g.notify(systemd.Ready)
	}
	cfg, err := load()
	if err != nil {
		return err
	}
	return g.apply(ctx, cfg)
}

// apply swaps in the snapshot of cfg; see Reload. The caller holds mu.
func (g *Gate) apply(ctx context.Context, cfg *config.Config) error {
	prev := g.snap.Load()
	sn, err := g.build(cfg, prev)
	if err != nil {
		return err
	}
	keys := bootChanges(g.boot, cfg)
	if slices.Contains(keys, "Listen.Addr") && g.served != g.boot.Listen.Addr {
		// The gate serves another address than listen.addr, a socket systemd passed: the
		// socket unit decides what it serves, not listen.addr.
		keys = slices.DeleteFunc(keys, func(k string) bool { return k == "Listen.Addr" })
		g.logger.Info("listen.addr changed; the gate serves the address of the socket it was given, which a restart keeps", "served", g.served)
	}
	if len(keys) > 0 {
		slices.Sort(keys)
		g.logger.Warn("these settings changed but take effect only at the next restart", "keys", keys)
	}
	var added, kept, restarted, removed []string
	var fresh []*serverRuntime // runtimes to start
	for _, name := range sn.names {
		s := sn.servers[name]
		switch old := prev.servers[name]; {
		case old == nil:
			added = append(added, name)
			fresh = append(fresh, s.rt)
		case old.rt == s.rt:
			kept = append(kept, name)
			if old.mirror != s.mirror {
				if err := s.sup.SetRedactor(s.engine); err != nil {
					g.logger.Warn("cannot update the redaction of the server's errors and stderr", "server", name, "error", err.Error())
				}
			}
		default:
			restarted = append(restarted, name)
			fresh = append(fresh, s.rt)
		}
	}
	var stale []*server // servers of prev whose runtime the new snapshot does not use
	for _, name := range prev.names {
		old := prev.servers[name]
		if s := sn.servers[name]; s == nil || s.rt != old.rt {
			stale = append(stale, old)
			if s == nil {
				removed = append(removed, name)
			}
		}
	}
	var replaced []*route // routes of prev that the new snapshot does not keep
	for pattern, rt := range prev.routes {
		if sn.routes[pattern] != rt {
			replaced = append(replaced, rt)
		}
	}
	var dropped []*proxy.Mirror // mirrors of prev that the new snapshot does not keep
	for _, name := range prev.names {
		old := prev.servers[name]
		if s := sn.servers[name]; s == nil || s.mirror != old.mirror {
			dropped = append(dropped, old.mirror)
		}
	}
	if g.opts.Level != nil {
		var level slog.Level
		_ = level.UnmarshalText([]byte(cfg.LogLevel)) // validated
		g.opts.Level.Set(level)
	}

	g.snap.Store(sn)
	for _, rt := range replaced {
		rt.retire()
	}
	g.retired = append(slices.DeleteFunc(g.retired, (*route).isIdle), replaced...)
	g.logger.Info("config reloaded", "added", added, "restarted", restarted, "removed", removed, "kept", kept)

	// The swap is done: whatever ctx says now, the stale servers get the grace for their calls,
	// and the new ones must run. Only the shutdown changes that; it stops what is left.
	ctx = context.WithoutCancel(ctx)
	shutdown := false
	if len(stale) > 0 {
		shutdown = !g.awaitRoutes(func(rt *route) bool {
			return slices.ContainsFunc(stale, func(s *server) bool { return rt.uses(s.rt.src) })
		})
	}
	if shutdown {
		// The shutdown stops them once its own grace for calls in flight is over.
		g.leftover = append(g.leftover, stale...)
		return nil
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, s := range stale {
		wg.Go(func() {
			sctx, cancel := context.WithTimeout(ctx, stopTimeout)
			defer cancel()
			if err := s.sup.Stop(sctx); err == nil {
				s.rt.src.Close()
				return
			}
			// The old process has not ended: a runtime with the same downstream settings, whatever
			// its server's name, waits for it.
			g.logger.Error("server did not stop; its replacement starts once it has", "server", s.name)
			mu.Lock()
			defer mu.Unlock()
			g.leftover = append(g.leftover, s)
			p := &pendingStop{key: s.rt.key, done: make(chan struct{})}
			g.stopping = append(g.stopping, p)
			g.retiring.Go(func() {
				// Ends early with the shutdown, which stops it in turn; done then stays open, and
				// nothing is started.
				if s.sup.Stop(g.retireCtx) == nil {
					s.rt.src.Close()
					close(p.done)
				}
			})
		})
	}
	wg.Wait()
	for _, rt := range fresh {
		g.startRuntime(ctx, rt)
	}
	// A dropped mirror goes on taking listings while the retired routes that hold it serve
	// requests, at most ShutdownGrace; a call in flight needs only its source.
	if len(dropped) > 0 || len(replaced) > 0 {
		holders := slices.DeleteFunc(slices.Clone(g.retired), func(rt *route) bool {
			return !slices.ContainsFunc(dropped, func(m *proxy.Mirror) bool { return slices.Contains(rt.mirrors, m) })
		})
		g.retiring.Go(func() {
			timer := time.NewTimer(ShutdownGrace)
			defer timer.Stop()
		wait:
			for _, rt := range holders {
				select {
				case <-rt.idle:
				case <-timer.C:
					break wait
				case <-g.drained:
					break wait
				}
			}
			for _, m := range dropped {
				m.Close()
			}
			for _, rt := range replaced {
				if rt.agg != nil {
					rt.agg.Close()
				}
			}
		})
	}
	return nil
}

// awaitRoutes waits until the retired routes that match have no request in flight, at most
// ShutdownGrace, and reports false when the shutdown began first.
func (g *Gate) awaitRoutes(match func(*route) bool) bool {
	timer := time.NewTimer(ShutdownGrace)
	defer timer.Stop()
	for _, rt := range g.retired {
		if !match(rt) {
			continue
		}
		select {
		case <-rt.idle:
		case <-timer.C:
			return true
		case <-g.retireCtx.Done():
			return false
		}
	}
	return g.retireCtx.Err() == nil
}

// pendingStop is the old process of a replaced server that had not ended when its stop timed
// out; done is closed once it has.
type pendingStop struct {
	key  map[string]any
	done chan struct{}
}

// startRuntime starts a runtime of the current snapshot at once, or, when an old process with the same downstream
// settings has not ended yet, once it has, as long as the runtime is still in the current
// snapshot and the gate is not shutting down. The caller holds mu.
func (g *Gate) startRuntime(ctx context.Context, rt *serverRuntime) {
	hold := g.boot.StartupGracePeriod.D()
	g.stopping = slices.DeleteFunc(g.stopping, func(p *pendingStop) bool {
		select {
		case <-p.done:
			return true
		default:
			return false
		}
	})
	var waits []chan struct{}
	for _, p := range g.stopping {
		if reflect.DeepEqual(p.key, rt.key) {
			waits = append(waits, p.done)
		}
	}
	if len(waits) == 0 {
		rt.start(ctx, hold)
		return
	}
	g.retiring.Go(func() {
		for _, done := range waits {
			select {
			case <-done:
			case <-g.retireCtx.Done():
				return
			}
		}
		g.mu.Lock()
		defer g.mu.Unlock()
		current := false
		for _, s := range g.snap.Load().servers {
			current = current || s.rt == rt
		}
		if g.closing || g.retireCtx.Err() != nil || !current {
			return
		}
		g.logger.Info("the old process has stopped; starting its replacement", "server", rt.src.Name())
		rt.start(ctx, hold)
	})
}

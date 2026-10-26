package gate

import (
	"context"
	"errors"
	"log/slog"
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
	if keys := bootChanges(g.boot, cfg); len(keys) > 0 {
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

	if len(stale) > 0 {
		g.awaitRoutes(ctx, func(rt *route) bool {
			return slices.ContainsFunc(stale, func(s *server) bool { return rt.uses(s.rt.src) })
		})
		var wg sync.WaitGroup
		for _, s := range stale {
			wg.Go(func() {
				ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), stopTimeout)
				defer cancel()
				if err := s.sup.Stop(ctx); err != nil {
					g.logger.Error("server did not stop", "server", s.name, "error", err.Error())
				}
				s.rt.src.Close()
			})
		}
		wg.Wait()
	}
	// Not on ctx: the snapshot is swapped, and its servers must run. Only the shutdown, which
	// stops them, skips this.
	if g.retireCtx.Err() == nil {
		for _, rt := range fresh {
			rt.start(ctx)
		}
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
// ShutdownGrace, or until ctx is done or the shutdown begins.
func (g *Gate) awaitRoutes(ctx context.Context, match func(*route) bool) {
	timer := time.NewTimer(ShutdownGrace)
	defer timer.Stop()
	for _, rt := range g.retired {
		if !match(rt) {
			continue
		}
		select {
		case <-rt.idle:
		case <-timer.C:
			return
		case <-ctx.Done():
			return
		case <-g.retireCtx.Done():
			return
		}
	}
}

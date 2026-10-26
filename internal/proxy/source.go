package proxy

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/downstream"
)

// Source is what lasts of one downstream server while the config changes: the supervisor calls go
// to, the catalog as the server last listed it (before any policy), the counters, the routing of
// progress notifications to the calls they belong to, and the worker that delivers them. Mirrors
// are views of a Source under one config; a Source tells each mirror it serves of every listing.
type Source struct {
	name   string
	logger *slog.Logger
	down   Downstream

	ready atomic.Bool // the tools were listed once

	// applyMu orders listings and the attaching of mirrors, so that a mirror never applies a
	// listing older than one it has already applied.
	applyMu sync.Mutex

	mu       sync.Mutex
	dirty    int
	raw      listing // the last listing of each kind in listed
	listed   int
	skipped  int // kinds left out of the last listing because no mirror shows them
	lastSync time.Time
	mirrors  []*Mirror
	kick     chan struct{}

	progress *progressTable
	events   chan event
	stats    stats

	cancel context.CancelFunc // set by Start; ends the workers and the listings
	wg     sync.WaitGroup
}

// NewSource returns the source of the server named name. Attach connects it to its supervisor and
// Start starts its workers.
func NewSource(name string, logger *slog.Logger) *Source {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Source{
		name: name, logger: logger.With("server", name),
		kick: make(chan struct{}, 1), progress: newProgressTable(), events: make(chan event, eventQueue),
	}
}

// Attach sets the supervisor calls go to. The supervisor takes the source's Notifications and
// OnSession, so it is built after the source; Attach is called once, before Start.
func (s *Source) Attach(d Downstream) { s.down = d }

// Inherit takes over the listing and the counters of prev, the source of a server whose
// settings changed, so that the server keeps its catalog listed while it restarts, as after a
// crash. It is called before any mirror attaches and before Start.
func (s *Source) Inherit(prev *Source) {
	prev.mu.Lock()
	raw, listed, skipped, lastSync := prev.raw, prev.listed, prev.skipped, prev.lastSync
	prev.mu.Unlock()
	s.mu.Lock()
	s.raw, s.listed, s.skipped, s.lastSync = raw, listed, skipped, lastSync
	s.mu.Unlock()
	s.ready.Store(prev.ready.Load())
	s.stats.calls.Store(prev.stats.calls.Load())
	s.stats.failed.Store(prev.stats.failed.Load())
	s.stats.dropped.Store(prev.stats.dropped.Load())
}

// Name is the server's name in the config.
func (s *Source) Name() string { return s.name }

// Ready reports whether the catalog was listed once.
func (s *Source) Ready() bool { return s.ready.Load() }

// Notifications are the handlers to give the supervisor.
func (s *Source) Notifications() downstream.Notifications {
	return downstream.Notifications{
		ToolsChanged:     func() { s.markDirty(kindTools) },
		PromptsChanged:   func() { s.markDirty(kindPrompts) },
		ResourcesChanged: func() { s.markDirty(kindResources) },
		Progress:         func(p *mcp.ProgressNotificationParams) { s.enqueue(event{progress: p}) },
		Log:              func(p *mcp.LoggingMessageParams) { s.enqueue(event{log: p}) }, //nolint:staticcheck // servers of older protocol versions still send log messages
	}
}

// OnSession is the supervisor's OnSession hook: a new session lists the whole catalog again.
func (s *Source) OnSession(*mcp.ClientSession) { s.markDirty(kindAll) }

// Start starts the catalog sync and the notification worker. They run until ctx ends or Close is
// called.
func (s *Source) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)
	s.wg.Add(2)
	go s.syncLoop(ctx)
	go s.notifyLoop(ctx)
}

// Close stops the workers. Calls in flight are not affected, but their progress is no longer
// delivered.
func (s *Source) Close() {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
}

func (s *Source) markDirty(kinds int) {
	s.mu.Lock()
	s.dirty |= kinds
	s.mu.Unlock()
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// attach adds a mirror and applies to it what the source has listed, then lists the kinds the
// mirror shows that were left out so far because no mirror showed them.
func (s *Source) attach(m *Mirror) {
	s.applyMu.Lock()
	s.mu.Lock()
	s.mirrors = append(s.mirrors, m)
	raw, listed, lastSync := s.raw, s.listed, s.lastSync
	missing := s.skipped & m.shows()
	s.mu.Unlock()
	m.apply(listed, &raw, lastSync)
	s.applyMu.Unlock()
	if missing != 0 {
		s.markDirty(missing)
	}
}

// detach removes a mirror; it is no longer told of listings.
func (s *Source) detach(m *Mirror) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mirrors = slices.DeleteFunc(s.mirrors, func(x *Mirror) bool { return x == m })
}

// shows returns the kinds some mirror shows; tools always.
func (s *Source) shows() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	kinds := kindTools
	for _, m := range s.mirrors {
		kinds |= m.shows()
	}
	return kinds
}

// current is the mirror attached last, whose scrubbing the server's log messages get.
func (s *Source) current() *Mirror {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.mirrors) == 0 {
		return nil
	}
	return s.mirrors[len(s.mirrors)-1]
}

// syncLoop lists what is dirty whenever it is kicked, and retries failed listings with backoff
// while the session lasts.
func (s *Source) syncLoop(ctx context.Context) {
	defer s.wg.Done()
	retry := retryFirst
	var timer *time.Timer
	var timerC <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-s.kick:
		case <-timerC:
			timerC = nil
		}
		s.mu.Lock()
		kinds := s.dirty
		s.dirty = 0
		s.mu.Unlock()
		if kinds == 0 {
			continue
		}
		failed, notReady := s.sync(ctx, kinds)
		if failed == 0 || notReady {
			// Without a session the next one marks everything dirty again.
			retry = retryFirst
			continue
		}
		s.mu.Lock()
		s.dirty |= failed
		s.mu.Unlock()
		if timer == nil {
			timer = time.NewTimer(retry)
		} else {
			timer.Reset(retry)
		}
		timerC = timer.C
		retry = min(retry*2, retryLast)
	}
}

// sync lists the given kinds and applies them to every mirror. It returns the kinds that failed,
// and whether the server had no session.
func (s *Source) sync(ctx context.Context, kinds int) (failed int, notReady bool) {
	ctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	shows := s.shows()
	var l listing
	err := s.down.Call(ctx, func(ctx context.Context, cs *mcp.ClientSession) error {
		l = s.list(ctx, cs, kinds, shows)
		return nil
	})
	var nr *downstream.NotReadyError
	if errors.As(err, &nr) {
		return kinds, true
	}
	if err != nil {
		return kinds, false
	}
	applied := kinds &^ l.failed
	if applied == 0 {
		return l.failed, false
	}
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	now := time.Now()
	s.mu.Lock()
	if applied&kindTools != 0 {
		s.raw.tools = l.tools
	}
	if applied&kindPrompts != 0 {
		s.raw.prompts = l.prompts
	}
	if applied&kindResources != 0 {
		s.raw.resources, s.raw.templates = l.resources, l.templates
	}
	s.listed |= applied
	s.skipped = s.skipped&^applied | applied&^shows
	s.lastSync = now
	mirrors := slices.Clone(s.mirrors)
	nowShows := kindTools
	for _, m := range mirrors {
		nowShows |= m.shows()
	}
	s.mu.Unlock()
	for _, m := range mirrors {
		m.apply(applied, &l, now)
	}
	// After the mirrors have the tools, so that a route that waits for Ready finds them.
	if applied&kindTools != 0 {
		s.ready.Store(true)
	}
	// A mirror that attached during the listing may show a kind it left out.
	if missing := applied &^ shows & nowShows; missing != 0 {
		s.markDirty(missing)
	}
	return l.failed, false
}

// list reads the kinds the server advertises and some mirror shows; a kind it does not
// advertise is empty.
func (s *Source) list(ctx context.Context, cs *mcp.ClientSession, kinds, shows int) listing {
	caps := cs.InitializeResult().Capabilities
	if caps == nil {
		caps = &mcp.ServerCapabilities{}
	}
	var l listing
	fail := func(kind int, what string, err error) {
		l.failed |= kind
		s.logger.Warn("listing the catalog failed; keeping the last one", "list", what, "error", s.down.ErrorText(err))
	}
	var err error
	if kinds&kindTools != 0 && caps.Tools != nil {
		if l.tools, err = collect(cs.Tools(ctx, nil)); err != nil {
			fail(kindTools, "tools", err)
		}
	}
	if kinds&kindPrompts != 0 && caps.Prompts != nil && shows&kindPrompts != 0 {
		if l.prompts, err = collect(cs.Prompts(ctx, nil)); err != nil {
			fail(kindPrompts, "prompts", err)
		}
	}
	if kinds&kindResources != 0 && caps.Resources != nil && shows&kindResources != 0 {
		if l.resources, err = collect(cs.Resources(ctx, nil)); err != nil {
			fail(kindResources, "resources", err)
		} else if l.templates, err = collect(cs.ResourceTemplates(ctx, nil)); err != nil && !methodNotFound(err) {
			fail(kindResources, "resource templates", err)
		}
	}
	return l
}

// SourceStats are a source's counters, kept across reloads.
type SourceStats struct {
	Ready                               bool
	LastSync                            time.Time
	Calls, Failed, DroppedNotifications int64
}

// Stats returns the source's counters.
func (s *Source) Stats() SourceStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return SourceStats{
		Ready: s.ready.Load(), LastSync: s.lastSync,
		Calls: s.stats.calls.Load(), Failed: s.stats.failed.Load(), DroppedNotifications: s.stats.dropped.Load(),
	}
}

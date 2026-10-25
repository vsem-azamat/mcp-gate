// Package proxy mirrors one downstream server's catalog into an upstream-facing MCP server and
// forwards calls to it.
//
// A Mirror keeps the last catalog it listed, filtered by the server's policy, registered on its
// *mcp.Server; a restart or a failed listing leaves it in place. It resyncs on every new session
// and on list-changed notifications, and changes only the entries that differ. Calls go through
// the server's supervisor with a downstream _meta built from an allow-list, progress remapped to
// the upstream request, and results redacted, failing closed. Every call is logged as one audit
// line.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/downstream"
	"github.com/vsem-azamat/mcp-gate/internal/policy"
	"github.com/vsem-azamat/mcp-gate/internal/upstream"
)

// Tuning of the catalog sync.
const (
	// listTimeout bounds one catalog listing.
	listTimeout = 60 * time.Second
	// The delay before a failed listing is tried again, doubling up to the maximum.
	retryFirst = 2 * time.Second
	retryLast  = time.Minute
)

// Downstream is the supervisor of the mirrored server.
type Downstream interface {
	// Call runs fn with the current session, as downstream.Supervisor.Call does.
	Call(ctx context.Context, fn func(context.Context, *mcp.ClientSession) error) error
	// ErrorText returns an error's message fit for logs and clients.
	ErrorText(err error) string
}

// Options configure a Mirror.
type Options struct {
	// Name is the server's name in the config.
	Name string
	// Version is reported as the server version to clients.
	Version string
	Policy  *policy.Policy
	// Redaction redacts results; nil passes them unchanged.
	Redaction *Redaction
	Logger    *slog.Logger
}

// kinds of catalog entries, as bits.
const (
	kindTools = 1 << iota
	kindPrompts
	kindResources
	kindAll = kindTools | kindPrompts | kindResources
)

// Mirror is the upstream face of one downstream server.
type Mirror struct {
	opts   Options
	logger *slog.Logger
	server *mcp.Server
	down   Downstream

	ready atomic.Bool // the tools were listed once

	mu        sync.Mutex
	dirty     int
	tools     map[string]*mcp.Tool
	prompts   map[string]*mcp.Prompt
	resources map[string]*mcp.Resource
	templates map[string]*mcp.ResourceTemplate
	lastSync  time.Time
	kick      chan struct{}

	progress *progressTable
	events   chan event
	stats    stats

	cancel context.CancelFunc // set by Start; ends the workers and the listings
	wg     sync.WaitGroup
}

type stats struct {
	calls, failed, dropped atomic.Int64
}

// New returns a mirror. Attach connects it to its supervisor and Start starts its workers.
func New(opts Options) *Mirror {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	logger := opts.Logger.With("server", opts.Name)
	m := &Mirror{
		opts: opts, logger: logger,
		tools: map[string]*mcp.Tool{}, prompts: map[string]*mcp.Prompt{},
		resources: map[string]*mcp.Resource{}, templates: map[string]*mcp.ResourceTemplate{},
		kick:     make(chan struct{}, 1),
		progress: newProgressTable(),
		events:   make(chan event, eventQueue),
	}
	m.server = mcp.NewServer(&mcp.Implementation{Name: opts.Name, Version: opts.Version}, &mcp.ServerOptions{
		Logger:       upstream.SDKLogger(logger),
		Capabilities: Capabilities(opts.Policy),
	})
	return m
}

// Capabilities are what a mirror advertises: tools always, prompts and resources unless the
// policy exposes none of them, all with list-changed notifications, and nothing else. They do
// not depend on the catalog, so a client that connects while the server is down sees them too.
func Capabilities(p *policy.Policy) *mcp.ServerCapabilities {
	caps := &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{ListChanged: true}}
	if !p.Prompts.ExposesNothing() {
		caps.Prompts = &mcp.PromptCapabilities{ListChanged: true}
	}
	if !p.Resources.ExposesNothing() {
		caps.Resources = &mcp.ResourceCapabilities{ListChanged: true}
	}
	return caps
}

// Server is the upstream-facing MCP server.
func (m *Mirror) Server() *mcp.Server { return m.server }

// Ready reports whether the catalog was listed once, so the route can serve.
func (m *Mirror) Ready() bool { return m.ready.Load() }

// Attach sets the supervisor calls go to. It is called once, before Start.
func (m *Mirror) Attach(d Downstream) { m.down = d }

// Notifications are the handlers to give the supervisor.
func (m *Mirror) Notifications() downstream.Notifications {
	return downstream.Notifications{
		ToolsChanged:     func() { m.markDirty(kindTools) },
		PromptsChanged:   func() { m.markDirty(kindPrompts) },
		ResourcesChanged: func() { m.markDirty(kindResources) },
		Progress:         func(p *mcp.ProgressNotificationParams) { m.enqueue(event{progress: p}) },
		Log:              func(p *mcp.LoggingMessageParams) { m.enqueue(event{log: p}) }, //nolint:staticcheck // servers of older protocol versions still send log messages
	}
}

// OnSession is the supervisor's OnSession hook: a new session lists the whole catalog again.
func (m *Mirror) OnSession(*mcp.ClientSession) { m.markDirty(kindAll) }

// Start starts the catalog sync and the notification worker. They run until ctx ends or Close
// is called.
func (m *Mirror) Start(ctx context.Context) {
	ctx, m.cancel = context.WithCancel(ctx)
	m.wg.Add(2)
	go m.syncLoop(ctx)
	go m.notifyLoop(ctx)
}

// Close stops the workers. Calls in flight are not affected.
func (m *Mirror) Close() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
}

func (m *Mirror) markDirty(kinds int) {
	m.mu.Lock()
	m.dirty |= kinds
	m.mu.Unlock()
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

// syncLoop lists what is dirty whenever it is kicked, and retries failed listings with backoff
// while the session lasts.
func (m *Mirror) syncLoop(ctx context.Context) {
	defer m.wg.Done()
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
		case <-m.kick:
		case <-timerC:
			timerC = nil
		}
		m.mu.Lock()
		kinds := m.dirty
		m.dirty = 0
		m.mu.Unlock()
		if kinds == 0 {
			continue
		}
		failed, notReady := m.sync(ctx, kinds)
		if failed == 0 || notReady {
			// Without a session the next one marks everything dirty again.
			retry = retryFirst
			continue
		}
		m.mu.Lock()
		m.dirty |= failed
		m.mu.Unlock()
		if timer == nil {
			timer = time.NewTimer(retry)
		} else {
			timer.Reset(retry)
		}
		timerC = timer.C
		retry = min(retry*2, retryLast)
	}
}

// listing is one catalog read.
type listing struct {
	tools     []*mcp.Tool
	prompts   []*mcp.Prompt
	resources []*mcp.Resource
	templates []*mcp.ResourceTemplate
	failed    int
}

// sync lists the given kinds and applies them. It returns the kinds that failed, and whether the
// server had no session.
func (m *Mirror) sync(ctx context.Context, kinds int) (failed int, notReady bool) {
	ctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	var l listing
	err := m.down.Call(ctx, func(ctx context.Context, cs *mcp.ClientSession) error {
		l = m.list(ctx, cs, kinds)
		return nil
	})
	var nr *downstream.NotReadyError
	if errors.As(err, &nr) {
		return kinds, true
	}
	if err != nil {
		return kinds, false
	}
	m.apply(kinds&^l.failed, &l)
	return l.failed, false
}

// list reads the kinds the server advertises; a kind it does not advertise is empty.
func (m *Mirror) list(ctx context.Context, cs *mcp.ClientSession, kinds int) listing {
	caps := cs.InitializeResult().Capabilities
	if caps == nil {
		caps = &mcp.ServerCapabilities{}
	}
	var l listing
	fail := func(kind int, what string, err error) {
		l.failed |= kind
		m.logger.Warn("listing the catalog failed; keeping the last one", "list", what, "error", m.down.ErrorText(err))
	}
	var err error
	if kinds&kindTools != 0 && caps.Tools != nil {
		if l.tools, err = collect(cs.Tools(ctx, nil)); err != nil {
			fail(kindTools, "tools", err)
		}
	}
	if kinds&kindPrompts != 0 && caps.Prompts != nil && !m.opts.Policy.Prompts.ExposesNothing() {
		if l.prompts, err = collect(cs.Prompts(ctx, nil)); err != nil {
			fail(kindPrompts, "prompts", err)
		}
	}
	if kinds&kindResources != 0 && caps.Resources != nil && !m.opts.Policy.Resources.ExposesNothing() {
		if l.resources, err = collect(cs.Resources(ctx, nil)); err != nil {
			fail(kindResources, "resources", err)
		} else if l.templates, err = collect(cs.ResourceTemplates(ctx, nil)); err != nil {
			fail(kindResources, "resource templates", err)
		}
	}
	return l
}

func collect[T any](seq func(func(*T, error) bool)) ([]*T, error) {
	var out []*T
	for item, err := range seq {
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}

// apply registers the listed kinds, changing only the entries that differ from the mirrored
// ones.
func (m *Mirror) apply(kinds int, l *listing) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if kinds&kindTools != 0 {
		m.tools = m.applyTools(l.tools)
		m.ready.Store(true)
	}
	if kinds&kindPrompts != 0 {
		m.prompts = m.applyPrompts(l.prompts)
	}
	if kinds&kindResources != 0 {
		var hidden []string
		m.resources, hidden = m.applyResources(l.resources)
		m.templates = m.applyTemplates(l.templates)
		m.opts.Policy.SetHiddenResources(hidden)
	}
	if kinds != 0 {
		m.lastSync = time.Now()
	}
}

// guard runs an SDK registration, which panics on data it rejects, and reports the panic as
// an error.
func guard(fn func()) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("%v", v)
		}
	}()
	fn()
	return nil
}

// same reports whether two catalog entries encode to the same JSON.
func same(a, b any) bool {
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(ja) == string(jb)
}

// syncSet updates the entries of one kind. want maps keys to the entries to register; add
// registers one entry and reports an error for an entry the SDK rejects; remove drops keys.
// It returns the entries now registered: an entry that fails keeps its previous version.
func syncSet[T any](logger *slog.Logger, what string, have, want map[string]*T, add func(*T) error, remove func(...string)) map[string]*T {
	var gone []string
	for k := range have {
		if _, ok := want[k]; !ok {
			gone = append(gone, k)
		}
	}
	if len(gone) > 0 {
		remove(gone...)
	}
	out := make(map[string]*T, len(want))
	for k, v := range want {
		if old, ok := have[k]; ok && same(old, v) {
			out[k] = old
			continue
		}
		if err := add(v); err != nil {
			logger.Warn("skipping a catalog entry the SDK rejects", "kind", what, "key", k, "error", err.Error())
			if old, ok := have[k]; ok {
				out[k] = old
			}
			continue
		}
		out[k] = v
	}
	return out
}

func (m *Mirror) applyTools(list []*mcp.Tool) map[string]*mcp.Tool {
	want := map[string]*mcp.Tool{}
	for _, t := range list {
		if t == nil || !m.opts.Policy.Tools.Allows(t.Name) {
			continue
		}
		if err := validTool(t); err != nil {
			m.logger.Warn("skipping an invalid tool", "tool", t.Name, "error", err.Error())
			continue
		}
		want[t.Name] = t
	}
	return syncSet(m.logger, "tool", m.tools, want, func(t *mcp.Tool) error {
		return guard(func() { m.server.AddTool(t, m.callTool) })
	}, m.server.RemoveTools)
}

// validTool checks what the SDK's AddTool panics on, so that the reason can be logged.
func validTool(t *mcp.Tool) error {
	if t.Name == "" {
		return errors.New("no name")
	}
	var schema map[string]any
	data, err := json.Marshal(t.InputSchema)
	if err != nil || json.Unmarshal(data, &schema) != nil {
		return errors.New("the input schema is not a JSON object")
	}
	if schema["type"] != "object" {
		return errors.New(`the input schema's type is not "object"`)
	}
	return nil
}

func (m *Mirror) applyPrompts(list []*mcp.Prompt) map[string]*mcp.Prompt {
	want := map[string]*mcp.Prompt{}
	for _, p := range list {
		if p != nil && p.Name != "" && m.opts.Policy.Prompts.Allows(p.Name) {
			want[p.Name] = p
		}
	}
	return syncSet(m.logger, "prompt", m.prompts, want, func(p *mcp.Prompt) error {
		return guard(func() { m.server.AddPrompt(p, m.getPrompt) })
	}, m.server.RemovePrompts)
}

// applyResources also returns the URIs the policy hides.
func (m *Mirror) applyResources(list []*mcp.Resource) (map[string]*mcp.Resource, []string) {
	want := map[string]*mcp.Resource{}
	var hidden []string
	for _, r := range list {
		if r == nil || r.URI == "" {
			continue
		}
		if !m.opts.Policy.Resources.Allows(r.URI, r.Name) {
			hidden = append(hidden, r.URI)
			continue
		}
		if _, err := url.Parse(r.URI); err != nil {
			m.logger.Warn("skipping a resource with an invalid URI", "resource", r.Name)
			continue
		}
		want[r.URI] = r
	}
	return syncSet(m.logger, "resource", m.resources, want, func(r *mcp.Resource) error {
		return guard(func() { m.server.AddResource(r, m.readResource) })
	}, m.server.RemoveResources), hidden
}

func (m *Mirror) applyTemplates(list []*mcp.ResourceTemplate) map[string]*mcp.ResourceTemplate {
	want := map[string]*mcp.ResourceTemplate{}
	for _, t := range list {
		if t == nil || t.URITemplate == "" {
			continue
		}
		if m.opts.Policy.Resources.Allows(t.URITemplate, t.Name) {
			want[t.URITemplate] = t
		}
	}
	return syncSet(m.logger, "resource template", m.templates, want, func(t *mcp.ResourceTemplate) error {
		return guard(func() { m.server.AddResourceTemplate(t, m.readResource) })
	}, m.server.RemoveResourceTemplates)
}

// Stats is a snapshot of a mirror for status.
type Stats struct {
	Ready                                bool
	Tools, Prompts, Resources, Templates int
	LastSync                             time.Time
	Calls, Failed, DroppedNotifications  int64
}

// Stats returns a snapshot.
func (m *Mirror) Stats() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Stats{
		Ready: m.ready.Load(), Tools: len(m.tools), Prompts: len(m.prompts),
		Resources: len(m.resources), Templates: len(m.templates), LastSync: m.lastSync,
		Calls: m.stats.calls.Load(), Failed: m.stats.failed.Load(), DroppedNotifications: m.stats.dropped.Load(),
	}
}

// Package proxy mirrors one downstream server's catalog into an upstream-facing MCP server and
// forwards calls to it.
//
// A Source lists the server's catalog on every new session and on list-changed notifications,
// and keeps the last listing; a restart or a failed listing leaves it in place. A Mirror is the
// server under one config: it registers the Source's catalog, filtered by the server's policy, on
// its *mcp.Server, changing only the entries that differ. Calls go through
// the server's supervisor with a downstream _meta holding only the keys in the server's
// forwardMeta, progress remapped to the upstream request, and results redacted, failing closed.
// A token with a policy on the server is served an *mcp.Server of its own that holds only what
// the policy passes, so an entry it hides is unknown there. Every call is logged as one audit
// line.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yosida95/uritemplate/v3"

	"github.com/vsem-azamat/mcp-gate/internal/audit"
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

// Downstream is what a mirror's calls go to: the supervisor of the mirrored server, as
// downstream.Supervisor implements it. A call fails with a *downstream.NotReadyError while the
// server has no session.
type Downstream interface {
	CallTool(ctx context.Context, p *mcp.CallToolParams) (*mcp.CallToolResult, error)
	GetPrompt(ctx context.Context, p *mcp.GetPromptParams) (*mcp.GetPromptResult, error)
	ReadResource(ctx context.Context, p *mcp.ReadResourceParams) (*mcp.ReadResourceResult, error)
	// ErrorText returns an error's message fit for logs and clients.
	ErrorText(err error) string
	// HideURL returns a text with the server's URL replaced by its config path.
	HideURL(text string) string
}

// Supervisor is what a Source is attached to: the calls of its mirrors, and the session the
// catalog is listed on.
type Supervisor interface {
	Downstream
	// Call runs fn with the current session, as downstream.Supervisor.Call does.
	Call(ctx context.Context, fn func(context.Context, *mcp.ClientSession) error) error
}

// Options configure a Mirror.
type Options struct {
	// Name is the server's name in the config.
	Name string
	// Version is reported as the server version to clients.
	Version string
	Policy  *policy.Policy
	// Tokens are the token policies on the server, applied on top of Policy.
	Tokens policy.Tokens
	// ForwardMeta are the _meta keys of a request passed downstream.
	ForwardMeta []string
	// Redaction redacts results; nil passes them unchanged.
	Redaction *Redaction
	// Files, if set, scans the files tool calls write, after their results are redacted.
	Files  FileScanner
	Logger *slog.Logger
	// Audit receives the audit record of every request; nil writes them as call lines to
	// Logger.
	Audit audit.Sink
	// Source is the server's source, which the mirror serves the catalog of and sends calls
	// through.
	Source *Source
	// OnChange, if set, is called, outside the mirror's lock, after a listing was applied.
	OnChange func()
}

// Mirror is the upstream face of one downstream server under one config.
type Mirror struct {
	opts   Options
	logger *slog.Logger
	audit  audit.Sink
	server *mcp.Server
	src    *Source

	// mu guards the registered catalog, served and the views' maps. Lock order: a Source's
	// applyMu, then an Aggregate's mu, then mu, then the server filter's policy.Policy mu (a
	// leaf); the watchers are called without mu.
	mu        sync.Mutex
	tools     map[string]*mcp.Tool
	prompts   map[string]*mcp.Prompt
	resources map[string]*mcp.Resource
	templates map[string]*mcp.ResourceTemplate
	lastSync  time.Time

	watchMu  sync.Mutex
	watchers map[int]func()
	nextW    int

	served served // what reads reach; guarded by mu

	// The token policies and the server of each token that has one; fixed by New.
	tokens policy.Tokens
	views  map[string]*tokenView // by token name
}

// served is what the mirrored catalog serves to reads, compiled once per listing: the listed
// URIs, their comparison keys, and the templates' patterns.
type served struct {
	uris      map[string]bool
	keys      map[string]bool
	templates []*regexp.Regexp
}

// tokenView is the upstream server of a token with a policy on the server: the mirrored catalog
// without what the policy hides. Its maps are guarded by the mirror's mu.
type tokenView struct {
	policy    *policy.Token
	server    *mcp.Server
	reads     *policy.Reads // what the policy lets the token read of the mirrored catalog
	tools     map[string]*mcp.Tool
	prompts   map[string]*mcp.Prompt
	resources map[string]*mcp.Resource
	templates map[string]*mcp.ResourceTemplate
}

type stats struct {
	calls, failed, dropped atomic.Int64
}

// New returns a mirror of opts.Source, which it serves at once with what the source has listed.
// Close detaches it.
func New(opts Options) *Mirror {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Audit == nil {
		opts.Audit = audit.Log(opts.Logger)
	}
	logger := opts.Logger.With("server", opts.Name)
	m := &Mirror{
		opts: opts, logger: logger, audit: opts.Audit, src: opts.Source,
		tools: map[string]*mcp.Tool{}, prompts: map[string]*mcp.Prompt{},
		resources: map[string]*mcp.Resource{}, templates: map[string]*mcp.ResourceTemplate{},
		watchers: map[int]func(){},
	}
	// The mirror's own server serves tokens without a policy; while any token has one, the
	// lists depend on the token, so its results are private too.
	var setCacheable func(context.Context, mcp.Request, *mcp.Cacheable)
	if len(opts.Tokens) > 0 {
		setCacheable = privateCache
	}
	m.server = m.newServer(setCacheable)
	m.tokens = opts.Tokens
	m.views = make(map[string]*tokenView, len(opts.Tokens))
	for name, p := range opts.Tokens {
		m.views[name] = &tokenView{
			policy: p, server: m.newServer(privateCache), reads: p.Reads(nil, nil),
			tools: map[string]*mcp.Tool{}, prompts: map[string]*mcp.Prompt{},
			resources: map[string]*mcp.Resource{}, templates: map[string]*mcp.ResourceTemplate{},
		}
	}
	if opts.OnChange != nil {
		m.Watch(opts.OnChange)
	}
	m.src.attach(m)
	return m
}

// newServer returns an upstream server for the mirror, whose results setCacheable marks.
func (m *Mirror) newServer(setCacheable func(context.Context, mcp.Request, *mcp.Cacheable)) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: m.opts.Name, Version: m.opts.Version}, &mcp.ServerOptions{
		Logger: upstream.SDKLogger(m.logger), Capabilities: Capabilities(m.opts.Policy), SetCacheable: setCacheable,
	})
	s.AddReceivingMiddleware(m.receive)
	return s
}

// privateCache marks a result for the caller's own client only.
func privateCache(_ context.Context, _ mcp.Request, c *mcp.Cacheable) { c.CacheScope = cachePrivate }

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

// cachePrivate is the cache scope of a result that depends on the caller's token, which only
// the caller's own client may cache.
const cachePrivate = "private"

// TokenPolicy returns the policy of the token named token on the server; nil when it has none.
func (m *Mirror) TokenPolicy(token string) *policy.Token { return m.tokens.For(token) }

// HasTokenPolicies reports whether any token has a policy on the server.
func (m *Mirror) HasTokenPolicies() bool { return len(m.tokens) > 0 }

// ServerFor returns the upstream server for the token named token: its own when it has a
// policy on the server, else the mirror's.
func (m *Mirror) ServerFor(token string) *mcp.Server {
	if v := m.views[token]; v != nil && token != "" {
		return v.server
	}
	return m.server
}

// shows returns the kinds the mirror's policy lets through.
func (m *Mirror) shows() kindSet {
	kinds := kindSet(audit.Tool)
	if !m.opts.Policy.Prompts.ExposesNothing() {
		kinds |= kindSet(audit.Prompt)
	}
	if !m.opts.Policy.Resources.ExposesNothing() {
		kinds |= kindSet(audit.Resource)
	}
	return kinds
}

// Ready reports whether the catalog was listed once, so the route can serve.
func (m *Mirror) Ready() bool { return m.src.Ready() }

// Source is the source the mirror serves.
func (m *Mirror) Source() *Source { return m.src }

// Close detaches the mirror from its source. Calls in flight are not affected.
func (m *Mirror) Close() { m.src.detach(m) }

// listing is one catalog read.
type listing struct {
	tools     []*mcp.Tool
	prompts   []*mcp.Prompt
	resources []*mcp.Resource
	templates []*mcp.ResourceTemplate
	failed    kindSet
}

// Watch registers fn to be called, outside the mirror's lock, after a listing was applied to the
// catalog, and returns the function that unregisters it.
func (m *Mirror) Watch(fn func()) (cancel func()) {
	m.watchMu.Lock()
	defer m.watchMu.Unlock()
	id := m.nextW
	m.nextW++
	m.watchers[id] = fn
	return func() {
		m.watchMu.Lock()
		defer m.watchMu.Unlock()
		delete(m.watchers, id)
	}
}

func (m *Mirror) notifyWatchers() {
	m.watchMu.Lock()
	fns := make([]func(), 0, len(m.watchers))
	for _, fn := range m.watchers {
		fns = append(fns, fn)
	}
	m.watchMu.Unlock()
	for _, fn := range fns {
		fn()
	}
}

// Catalog is a snapshot of the entries a mirror serves, keyed as registered: tools and prompts
// by name, resources by URI, templates by URI template. The entries are shared and read-only.
type Catalog struct {
	Tools     map[string]*mcp.Tool
	Prompts   map[string]*mcp.Prompt
	Resources map[string]*mcp.Resource
	Templates map[string]*mcp.ResourceTemplate
}

// Catalogs returns the entries the mirror serves now: all of them, as tokens without a policy
// see them, and those each token with a policy sees, by token name.
func (m *Mirror) Catalogs() (all Catalog, byToken map[string]Catalog) {
	m.mu.Lock()
	defer m.mu.Unlock()
	byToken = make(map[string]Catalog, len(m.views))
	for name, v := range m.views {
		byToken[name] = Catalog{Tools: maps.Clone(v.tools), Prompts: maps.Clone(v.prompts), Resources: maps.Clone(v.resources), Templates: maps.Clone(v.templates)}
	}
	all = Catalog{Tools: maps.Clone(m.tools), Prompts: maps.Clone(m.prompts), Resources: maps.Clone(m.resources), Templates: maps.Clone(m.templates)}
	return all, byToken
}

// Name is the server's name in the config.
func (m *Mirror) Name() string { return m.opts.Name }

// methodNotFound reports whether a server answered that it has no such method, as servers that
// list resources but implement no templates answer resources/templates/list.
func methodNotFound(err error) bool {
	var we *jsonrpc.Error
	return errors.As(err, &we) && we.Code == jsonrpc.CodeMethodNotFound
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

// The catalog pipeline. A listing reaches the clients in these steps, in order:
//
//   - listing: the source lists the kinds that are dirty and keeps them as the server sent them
//     (Source.sync), then hands them to each mirror's apply;
//   - server filter: the entries the server's filter passes, checked outside the mirror's lock,
//     with the tools the SDK would reject marked invalid and the resources whose URI does not
//     parse left out (filter);
//   - register: they are registered on the mirror's own server, changing only the entries that
//     differ from the registered ones, with the server's resource filter and what reads reach
//     compiled from them (register);
//   - per-token projection: each token with a policy gets, on its own server, what the policy
//     passes of the registered entries (syncView);
//   - aggregate naming: the watchers are told, and an aggregate the mirror is a member of names
//     its tools and prompts <server>__<name> for /mcp and syncs its views (Aggregate.rebuild).
//
// Register and the projection run under m.mu, so that a token's server never lags the catalog
// its handlers check against.

// apply runs the mirror's steps of the catalog pipeline for the listed kinds, then tells the
// watchers.
func (m *Mirror) apply(kinds kindSet, l *listing, at time.Time) {
	if kinds == 0 {
		return
	}
	f := m.filter(kinds, l)
	m.mu.Lock()
	m.register(kinds, f, at)
	for _, v := range m.views {
		m.syncView(v, kinds)
	}
	m.mu.Unlock()
	m.notifyWatchers()
}

// filtered is a listing after the server's filter: of each listed kind, the entries the mirror's
// own server is to hold, and of resources and templates everything the server lists, which the
// server's resource filter is compiled from.
type filtered struct {
	tools     []candidate
	prompts   map[string]*mcp.Prompt
	resources map[string]*mcp.Resource
	templates map[string]*mcp.ResourceTemplate
	listed    []policy.Entry // every listed resource
	listedT   []policy.Entry // every listed template
}

// candidate is a listed tool the server's filter passes; one the SDK cannot take is invalid, and
// keeps its previous version.
type candidate struct {
	tool    *mcp.Tool
	invalid bool
}

// filter is the server filter step: it needs no lock, and logs the invalid tools and resources.
func (m *Mirror) filter(kinds kindSet, l *listing) *filtered {
	f := &filtered{}
	if kinds.has(audit.Tool) {
		f.tools = m.filterTools(l.tools)
	}
	if kinds.has(audit.Prompt) {
		f.prompts = m.filterPrompts(l.prompts)
	}
	if kinds.has(audit.Resource) {
		f.resources = m.filterResources(l.resources)
		f.templates = m.filterTemplates(l.templates)
		f.listed, f.listedT = entries(l.resources, resourceEntry), entries(l.templates, templateEntry)
	}
	return f
}

// register is the register step for the kinds of a filtered listing. The caller holds m.mu.
func (m *Mirror) register(kinds kindSet, f *filtered, at time.Time) {
	if kinds.has(audit.Tool) {
		m.tools = m.registerTools(f.tools)
	}
	if kinds.has(audit.Prompt) {
		m.prompts = m.registerPrompts(f.prompts)
	}
	if kinds.has(audit.Resource) {
		// Before the entries are registered, so that no new template reaches a newly hidden
		// resource.
		m.opts.Policy.SetCatalog(f.listed, f.listedT)
		m.resources = m.registerResources(f.resources)
		m.templates = m.registerTemplates(f.templates)
		m.served = newServed(m.resources, m.templates)
	}
	m.lastSync = at
}

func resourceEntry(r *mcp.Resource) policy.Entry { return policy.Entry{Key: r.URI, Name: r.Name} }

func templateEntry(t *mcp.ResourceTemplate) policy.Entry {
	return policy.Entry{Key: t.URITemplate, Name: t.Name}
}

// entries returns the policy entries of resources or templates.
func entries[T any](in []*T, entry func(*T) policy.Entry) []policy.Entry {
	out := make([]policy.Entry, 0, len(in))
	for _, e := range in {
		if e != nil {
			out = append(out, entry(e))
		}
	}
	return out
}

// newServed compiles what the mirrored resources and templates serve.
func newServed(resources map[string]*mcp.Resource, templates map[string]*mcp.ResourceTemplate) served {
	s := served{uris: make(map[string]bool, len(resources)), keys: make(map[string]bool, len(resources))}
	for uri := range resources {
		s.uris[uri] = true
		s.keys[policy.NormalizeURI(uri)] = true
	}
	for ut := range templates {
		if t, err := uritemplate.New(ut); err == nil {
			s.templates = append(s.templates, t.Regexp())
		}
	}
	return s
}

// syncView registers on a token's server the mirrored entries of the given kinds that its policy
// passes. Every token's server holds its own registrations of the shared, read-only entries,
// changed only where they differ, under m.mu like the mirror's own, so that a view never lags
// the catalog its handlers check against. An entry the SDK rejects was logged when the mirror's
// own server rejected it, so it is not logged again here. The caller holds m.mu.
func (m *Mirror) syncView(v *tokenView, kinds kindSet) {
	quiet := slog.New(slog.DiscardHandler)
	if kinds.has(audit.Tool) {
		want := passed(m.tools, func(t *mcp.Tool) bool { return v.policy.Tools.Allows(t.Name) })
		v.tools = syncSet(quiet, m.logText, entryTool, v.tools, want, func(t *mcp.Tool) error {
			return guard(func() { v.server.AddTool(t, m.callTool) })
		}, v.server.RemoveTools)
	}
	if kinds.has(audit.Prompt) {
		want := passed(m.prompts, func(p *mcp.Prompt) bool { return v.policy.Prompts.Allows(p.Name) })
		v.prompts = syncSet(quiet, m.logText, entryPrompt, v.prompts, want, func(p *mcp.Prompt) error {
			return guard(func() { v.server.AddPrompt(p, m.getPrompt) })
		}, v.server.RemovePrompts)
	}
	if kinds.has(audit.Resource) {
		v.reads = v.policy.Reads(entries(slices.Collect(maps.Values(m.resources)), resourceEntry),
			entries(slices.Collect(maps.Values(m.templates)), templateEntry))
		want := passed(m.resources, func(r *mcp.Resource) bool { return v.policy.Resources.Allows(r.URI, r.Name) })
		v.resources = syncSet(quiet, m.logText, entryResource, v.resources, want, func(r *mcp.Resource) error {
			return guard(func() { v.server.AddResource(r, m.readResource) })
		}, v.server.RemoveResources)
		wantT := passed(m.templates, func(t *mcp.ResourceTemplate) bool {
			return v.policy.Resources.Allows(t.URITemplate, t.Name)
		})
		v.templates = syncSet(quiet, m.logText, entryTemplate, v.templates, wantT, func(t *mcp.ResourceTemplate) error {
			return guard(func() { v.server.AddResourceTemplate(t, m.readResource) })
		}, v.server.RemoveResourceTemplates)
	}
}

// passed returns the entries of in that ok passes.
func passed[T any](in map[string]*T, ok func(*T) bool) map[string]*T {
	out := make(map[string]*T, len(in))
	for k, e := range in {
		if ok(e) {
			out[k] = e
		}
	}
	return out
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
// It returns the entries now registered: an entry that fails keeps its previous version. A
// rejection is logged with its key and error made fit for the log by logText.
func syncSet[T any](logger *slog.Logger, logText func(string) string, what entryKind, have, want map[string]*T, add func(*T) error, remove func(...string)) map[string]*T {
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
			logger.Warn("skipping a catalog entry the SDK rejects", "kind", string(what), "key", logText(k), "error", logText(err.Error()))
			if old, ok := have[k]; ok {
				out[k] = old
			}
			continue
		}
		out[k] = v
	}
	return out
}

// filterTools returns the listed tools the server's filter passes, in the order listed, and logs
// the invalid ones.
func (m *Mirror) filterTools(list []*mcp.Tool) []candidate {
	out := make([]candidate, 0, len(list))
	for _, t := range list {
		if t == nil || !m.opts.Policy.Tools.Allows(t.Name) {
			continue
		}
		if err := validTool(t); err != nil {
			m.logger.Warn("skipping an invalid tool", "tool", t.Name, "error", err.Error())
			out = append(out, candidate{tool: t, invalid: true})
			continue
		}
		out = append(out, candidate{tool: t})
	}
	return out
}

// registerTools registers the filtered tools; an invalid one keeps its previous version. The
// caller holds m.mu.
func (m *Mirror) registerTools(list []candidate) map[string]*mcp.Tool {
	want := map[string]*mcp.Tool{}
	for _, c := range list {
		if !c.invalid {
			want[c.tool.Name] = c.tool
		} else if old, ok := m.tools[c.tool.Name]; ok {
			want[c.tool.Name] = old // keep the previous version
		}
	}
	return syncSet(m.logger, m.logText, entryTool, m.tools, want, func(t *mcp.Tool) error {
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

// filterPrompts returns the listed prompts the server's filter passes, by name.
func (m *Mirror) filterPrompts(list []*mcp.Prompt) map[string]*mcp.Prompt {
	want := map[string]*mcp.Prompt{}
	for _, p := range list {
		if p != nil && p.Name != "" && m.opts.Policy.Prompts.Allows(p.Name) {
			want[p.Name] = p
		}
	}
	return want
}

// registerPrompts registers the filtered prompts. The caller holds m.mu.
func (m *Mirror) registerPrompts(want map[string]*mcp.Prompt) map[string]*mcp.Prompt {
	return syncSet(m.logger, m.logText, entryPrompt, m.prompts, want, func(p *mcp.Prompt) error {
		return guard(func() { m.server.AddPrompt(p, m.getPrompt) })
	}, m.server.RemovePrompts)
}

// filterResources returns the listed resources the server's filter passes, by URI, and logs
// those whose URI does not parse.
func (m *Mirror) filterResources(list []*mcp.Resource) map[string]*mcp.Resource {
	want := map[string]*mcp.Resource{}
	for _, r := range list {
		if r == nil || r.URI == "" || !m.opts.Policy.Resources.Allows(r.URI, r.Name) {
			continue
		}
		if _, err := url.Parse(r.URI); err != nil {
			m.logger.Warn("skipping a resource with an invalid URI", "resource", r.Name)
			continue
		}
		want[r.URI] = r
	}
	return want
}

// registerResources registers the filtered resources. The caller holds m.mu.
func (m *Mirror) registerResources(want map[string]*mcp.Resource) map[string]*mcp.Resource {
	return syncSet(m.logger, m.logText, entryResource, m.resources, want, func(r *mcp.Resource) error {
		return guard(func() { m.server.AddResource(r, m.readResource) })
	}, m.server.RemoveResources)
}

// filterTemplates returns the listed resource templates the server's filter passes, by URI
// template.
func (m *Mirror) filterTemplates(list []*mcp.ResourceTemplate) map[string]*mcp.ResourceTemplate {
	want := map[string]*mcp.ResourceTemplate{}
	for _, t := range list {
		if t == nil || t.URITemplate == "" {
			continue
		}
		if m.opts.Policy.Resources.Allows(t.URITemplate, t.Name) {
			want[t.URITemplate] = t
		}
	}
	return want
}

// registerTemplates registers the filtered templates. The caller holds m.mu.
func (m *Mirror) registerTemplates(want map[string]*mcp.ResourceTemplate) map[string]*mcp.ResourceTemplate {
	return syncSet(m.logger, m.logText, entryTemplate, m.templates, want, func(t *mcp.ResourceTemplate) error {
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

// Stats returns a snapshot: the counts of the mirror's catalog and the source's counters.
func (m *Mirror) Stats() Stats {
	src := m.src.Stats()
	m.mu.Lock()
	defer m.mu.Unlock()
	return Stats{
		Ready: src.Ready, Tools: len(m.tools), Prompts: len(m.prompts),
		Resources: len(m.resources), Templates: len(m.templates), LastSync: src.LastSync,
		Calls: src.Calls, Failed: src.Failed, DroppedNotifications: src.DroppedNotifications,
	}
}

package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yosida95/uritemplate/v3"

	"github.com/vsem-azamat/mcp-gate/internal/audit"
	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/policy"
	"github.com/vsem-azamat/mcp-gate/internal/redact"
	"github.com/vsem-azamat/mcp-gate/internal/upstream"
)

// separator joins a server's name and a tool or prompt name in the aggregate catalog.
const separator = config.AggregateSeparator

// aggregateNameRE is what an aggregate name may hold: the characters the MCP specification
// allows in tool names.
var aggregateNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// validAggregateName reports whether a prefixed name fits the aggregate catalog.
func validAggregateName(name string) bool {
	return len(name) <= config.AggregateMaxName && aggregateNameRE.MatchString(name)
}

// accessKey is the TokenInfo.Extra key under which the aggregate route passes what a request may
// reach: a map from each server it may reach to the token name that server knows it by.
const accessKey = "mcp-gate/access"

// AccessInfo returns the TokenInfo of a request to the aggregate route that may reach the
// servers in access, each mapped to the token name it accepted ("" for a public server).
// principal names the caller where no single server does.
func AccessInfo(principal string, access map[string]string) *auth.TokenInfo {
	return &auth.TokenInfo{UserID: principal, Extra: map[string]any{accessKey: access}}
}

// accessOf returns what a request may reach; nothing when its TokenInfo was not made by
// AccessInfo.
func accessOf(extra *mcp.RequestExtra) map[string]string {
	if extra == nil || extra.TokenInfo == nil {
		return nil
	}
	a, _ := extra.TokenInfo.Extra[accessKey].(map[string]string)
	return a
}

// AggregateOptions configure an Aggregate.
type AggregateOptions struct {
	// Name and Version are reported as the implementation to clients.
	Name    string
	Version string
	// Members are the mirrors served together.
	Members []*Mirror
	Logger  *slog.Logger
	// Audit receives the audit records of the requests the aggregate refuses itself; nil writes
	// them as call lines to Logger.
	Audit audit.Sink
}

// Aggregate serves the catalogs of several mirrors at one route. Tools and prompts are named
// <server>__<name>; resources and templates keep their URIs. Each set of servers a caller may
// reach has its own View, an upstream MCP server holding only those servers' entries. Calls are
// handed to the mirror of the server an entry came from, which filters, forwards, redacts and
// audits them as on its own route.
//
// Lock order: a.mu before a member's Mirror.mu. A member's listing reaches the aggregate through
// its watchers, which run outside the member's lock, and rebuild then reads the member's
// catalog under a.mu; nothing takes a.mu while it holds a Mirror.mu.
type Aggregate struct {
	opts    AggregateOptions
	logger  *slog.Logger
	audit   audit.Sink
	engine  *redact.Engine // scrubs logged names that belong to no member, with every rule
	members map[string]*Mirror

	mu      sync.Mutex
	tools   map[string]routed[mcp.Tool]
	prompts map[string]routed[mcp.Prompt]
	cats    map[string]Catalog
	// tokenCats holds, by member, what each token with a policy on it sees.
	tokenCats map[string]map[string]Catalog
	listed    map[string]bool // the members whose listed catalog the views hold
	skipped   map[named]bool  // tools and prompts left out for their names
	views     []*View
	unwatch   []func()
}

// routed is an entry of the aggregate catalog and where it came from.
type routed[T any] struct {
	server, name string
	entry        *T
}

// NewAggregate returns an aggregate of opts.Members, which it follows until Close.
func NewAggregate(opts AggregateOptions) (*Aggregate, error) {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Audit == nil {
		opts.Audit = audit.Log(opts.Logger)
	}
	// Names no member scrubs are logged under every rule there is, at least as strict as any
	// member's own.
	engine, err := redact.New(redact.Options{Russian: true, HighEntropy: true})
	if err != nil {
		return nil, err
	}
	a := &Aggregate{
		opts: opts, logger: opts.Logger, audit: opts.Audit, engine: engine, members: map[string]*Mirror{},
		skipped: map[named]bool{},
	}
	for _, m := range opts.Members {
		a.members[m.Name()] = m
		a.unwatch = append(a.unwatch, m.Watch(a.refresh))
	}
	a.mu.Lock()
	a.rebuild()
	a.mu.Unlock()
	return a, nil
}

// Close stops following the members' catalogs.
func (a *Aggregate) Close() {
	for _, f := range a.unwatch {
		f()
	}
}

// Listed reports whether the views hold a listed catalog of the member server. A mirror reports
// itself ready before its watchers run, so the aggregate's own record is what tells that its
// entries reached the views.
func (a *Aggregate) Listed(server string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.listed[server]
}

// splitName splits an aggregate tool or prompt name into the server and the server's own name.
// Server names in the aggregate hold no separator, so the first one ends the server's name.
func splitName(name string) (server, rest string, ok bool) {
	return strings.Cut(name, separator)
}

// refresh rebuilds the catalog after a member's changed and updates every view.
func (a *Aggregate) refresh() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rebuild()
	for _, v := range a.views {
		v.sync()
	}
}

// rebuild is the aggregate naming step of the catalog pipeline: it reads what each member serves
// (Mirror.Catalogs, what each token with a policy there sees included) and names the members'
// tools and prompts (named). The caller holds a.mu.
func (a *Aggregate) rebuild() {
	a.cats = make(map[string]Catalog, len(a.members))
	a.tokenCats = make(map[string]map[string]Catalog, len(a.members))
	a.listed = make(map[string]bool, len(a.members))
	a.tools = map[string]routed[mcp.Tool]{}
	a.prompts = map[string]routed[mcp.Prompt]{}
	skipped := map[named]bool{}
	for _, server := range slices.Sorted(maps.Keys(a.members)) {
		m := a.members[server]
		// Read before the catalog: a mirror is ready only once its tools were applied.
		a.listed[server] = m.Ready()
		c, byToken := m.Catalogs()
		a.cats[server] = c
		a.tokenCats[server] = byToken
		nameEntries(a, m, audit.Tool, c.Tools, a.tools, skipped)
		nameEntries(a, m, audit.Prompt, c.Prompts, a.prompts, skipped)
	}
	a.skipped = skipped
}

// nameEntries adds the tools or prompts of member m to out under their aggregate names,
// <server>__<name>. A name that is too long or holds characters the MCP specification does not
// allow is left out, recorded in skipped and logged once. Config validation keeps member names
// free of a trailing '_' and of the separator, so a name splits one way only; one that would
// split to another server is still dropped rather than routed by chance.
func nameEntries[T any](a *Aggregate, m *Mirror, kind audit.Kind, entries map[string]*T, out map[string]routed[T], skipped map[named]bool) {
	server := m.Name()
	for name, e := range entries {
		full := server + separator + name
		if !validAggregateName(full) {
			skipped[named{kind, full}] = true
			a.logSkipped(m, kind, full)
			continue
		}
		if s, _, _ := splitName(full); s != server {
			continue
		}
		out[full] = routed[T]{server: server, name: name, entry: e}
	}
}

func (a *Aggregate) logSkipped(m *Mirror, kind audit.Kind, full string) {
	if a.skipped[named{kind, full}] {
		return
	}
	a.logger.Warn(fmt.Sprintf("left out of the aggregate catalog: the prefixed name is longer than %d characters or holds characters outside A-Z a-z 0-9 _ . -", config.AggregateMaxName),
		"server", m.Name(), "kind", kind.String(), "name", m.logText(full))
}

// View returns the view of the given members, which a caller who may reach exactly those
// servers is served. principals maps a server to the name of the caller's token there when the
// token has a policy on it; the view then holds what that token sees on the server.
func (a *Aggregate) View(servers []string, principals map[string]string) *View {
	v := &View{
		a: a, servers: map[string]bool{}, principals: principals,
		tools: map[string]*mcp.Tool{}, prompts: map[string]*mcp.Prompt{},
		resources: map[string]*mcp.Resource{}, templates: map[string]*mcp.ResourceTemplate{},
	}
	caps := &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{ListChanged: true}}
	for _, s := range servers {
		m := a.members[s]
		if m == nil {
			continue
		}
		v.servers[s] = true
		mc := Capabilities(m.opts.Policy)
		if mc.Prompts != nil {
			caps.Prompts = &mcp.PromptCapabilities{ListChanged: true}
		}
		if mc.Resources != nil {
			caps.Resources = &mcp.ResourceCapabilities{ListChanged: true}
		}
	}
	sopts := &mcp.ServerOptions{Logger: upstream.SDKLogger(a.logger), Capabilities: caps}
	for s := range v.servers {
		if a.members[s].HasTokenPolicies() {
			// The view's lists depend on the token whenever any token has a policy on a member.
			sopts.SetCacheable = privateCache
			break
		}
	}
	v.server = mcp.NewServer(&mcp.Implementation{Name: a.opts.Name, Version: a.opts.Version}, sopts)
	v.server.AddReceivingMiddleware(v.receive)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.views = append(a.views, v)
	v.sync()
	return v
}

// View is the aggregate catalog of one set of servers.
type View struct {
	a       *Aggregate
	servers map[string]bool
	// principals maps a server to the name of the caller's token there, when it has a policy.
	principals map[string]string
	server     *mcp.Server

	// Guarded by a.mu.
	tools     map[string]*mcp.Tool
	prompts   map[string]*mcp.Prompt
	resources map[string]*mcp.Resource
	templates map[string]*mcp.ResourceTemplate
	claims    map[string]claim
	dropped   map[listedKey]bool // resources and templates left out as listed twice
}

// claim is what a server's catalog says it serves, for routing a resource read.
type claim struct {
	uris      map[string]bool
	templates []*uritemplate.Template
}

// Server is the upstream-facing MCP server of the view.
func (v *View) Server() *mcp.Server { return v.server }

// catalog returns what the view's caller sees of a member: the member's catalog for its token
// when it has a policy there, else the whole. The caller holds a.mu.
func (v *View) catalog(server string) Catalog {
	if p := v.principals[server]; p != "" {
		return v.a.tokenCats[server][p]
	}
	return v.a.cats[server]
}

// sync registers the view's share of the aggregate catalog: of each member, what the member
// serves the caller's token. A resource URI or a template that more than one of the view's servers
// lists is left out, since a read could not tell which server it is for; hidden entries count
// there too, and still route a read to their server, which refuses it, so that a policy does
// not change where a read goes. The caller holds a.mu.
func (v *View) sync() {
	a := v.a
	tools := map[string]*mcp.Tool{}
	for full, r := range a.tools {
		if _, ok := v.catalog(r.server).Tools[r.name]; ok && v.servers[r.server] {
			t := *r.entry
			t.Name = full
			tools[full] = &t
		}
	}
	v.tools = syncSet(a.logger, a.logText, entryTool, v.tools, tools, func(t *mcp.Tool) error {
		r := a.tools[t.Name]
		return guard(func() { v.server.AddTool(t, v.callTool(r.server, r.name)) })
	}, v.server.RemoveTools)

	prompts := map[string]*mcp.Prompt{}
	for full, r := range a.prompts {
		if _, ok := v.catalog(r.server).Prompts[r.name]; ok && v.servers[r.server] {
			p := *r.entry
			p.Name = full
			prompts[full] = &p
		}
	}
	v.prompts = syncSet(a.logger, a.logText, entryPrompt, v.prompts, prompts, func(p *mcp.Prompt) error {
		r := a.prompts[p.Name]
		return guard(func() { v.server.AddPrompt(p, v.getPrompt(r.server, r.name)) })
	}, v.server.RemovePrompts)

	resources := map[string]*mcp.Resource{}
	templates := map[string]*mcp.ResourceTemplate{}
	seenURI := map[string]int{}
	seenTemplate := map[string]int{}
	v.claims = map[string]claim{}
	for server := range v.servers {
		c, seen := a.cats[server], v.catalog(server)
		cl := claim{uris: map[string]bool{}}
		for uri, r := range c.Resources {
			cl.uris[uri] = true
			seenURI[uri]++
			if _, ok := seen.Resources[uri]; ok {
				resources[uri] = r
			}
		}
		for ut, t := range c.Templates {
			if tmpl, err := uritemplate.New(ut); err == nil {
				cl.templates = append(cl.templates, tmpl)
			}
			seenTemplate[ut]++
			if _, ok := seen.Templates[ut]; ok {
				templates[ut] = t
			}
		}
		v.claims[server] = cl
	}
	dropped := map[listedKey]bool{}
	for uri, n := range seenURI {
		if n > 1 {
			delete(resources, uri)
			v.logDropped(dropped, entryResource, uri)
		}
	}
	for ut, n := range seenTemplate {
		if n > 1 {
			delete(templates, ut)
			v.logDropped(dropped, entryTemplate, ut)
		}
	}
	v.dropped = dropped
	v.resources = syncSet(a.logger, a.logText, entryResource, v.resources, resources, func(r *mcp.Resource) error {
		return guard(func() { v.server.AddResource(r, v.readResource) })
	}, v.server.RemoveResources)
	v.templates = syncSet(a.logger, a.logText, entryTemplate, v.templates, templates, func(t *mcp.ResourceTemplate) error {
		return guard(func() { v.server.AddResourceTemplate(t, v.readResource) })
	}, v.server.RemoveResourceTemplates)
}

// logDropped records a resource or template left out because two of the view's servers list it,
// and logs it the first time.
func (v *View) logDropped(dropped map[listedKey]bool, kind entryKind, key string) {
	dropped[listedKey{kind, key}] = true
	if v.dropped[listedKey{kind, key}] {
		return
	}
	v.a.logger.Warn("left out of the aggregate catalog: more than one server lists it, so a read could not tell which is meant",
		"kind", string(kind), "key", v.a.logText(key), "servers", len(v.servers))
}

// logText makes a name for the log as a mirror does, with every rule.
func (a *Aggregate) logText(s string) string {
	return redact.Cut(a.engine.RedactText(s, redact.Marker{}), 256)
}

// admit checks a request against the server it is for: the server must be in the view and the
// request's access must name it. It returns the request's extra as the server's own route would
// see it, with the token name the server accepted.
func (v *View) admit(extra *mcp.RequestExtra, server string) (*mcp.RequestExtra, *Mirror, bool) {
	principal, ok := accessOf(extra)[server]
	m := v.a.members[server]
	if !ok || !v.servers[server] || m == nil {
		return nil, nil, false
	}
	out := *extra
	out.TokenInfo = &auth.TokenInfo{UserID: principal}
	return &out, m, true
}

func (v *View) callTool(server, name string) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		extra, m, ok := v.admit(req.Extra, server)
		if !ok {
			v.a.deny(ctx, req.Extra, audit.Tool, req.Params.Name)
			return nil, errUnknownTool(req.Params.Name)
		}
		if !m.mirrored(audit.Tool, name) {
			// Gone from the mirror but not yet from the view: refused as on the server's route.
			m.refused(ctx, extra, audit.Tool, name, true)
			return nil, errUnknownTool(req.Params.Name)
		}
		params := *req.Params
		params.Name = name
		return m.callToolAs(ctx, &mcp.CallToolRequest{Session: req.Session, Params: &params, Extra: extra}, req.Params.Name)
	}
}

func (v *View) getPrompt(server, name string) mcp.PromptHandler {
	return func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		extra, m, ok := v.admit(req.Extra, server)
		if !ok {
			v.a.deny(ctx, req.Extra, audit.Prompt, req.Params.Name)
			return nil, errUnknownPrompt(req.Params.Name)
		}
		if !m.mirrored(audit.Prompt, name) {
			m.refused(ctx, extra, audit.Prompt, name, true)
			return nil, errUnknownPrompt(req.Params.Name)
		}
		params := *req.Params
		params.Name = name
		return m.getPromptAs(ctx, &mcp.GetPromptRequest{Session: req.Session, Params: &params, Extra: extra}, req.Params.Name)
	}
}

// readResource routes a read to the one server of the view that lists the URI, or else to the
// one whose template matches it. A URI no server or more than one claims is not found.
func (v *View) readResource(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	uri := req.Params.URI
	server, ok := v.route(uri)
	if ok {
		var extra *mcp.RequestExtra
		var m *Mirror
		if extra, m, ok = v.admit(req.Extra, server); ok {
			if !m.serves(uri) {
				// Gone from the mirror but not yet from the view: refused as on the server's route.
				m.refused(ctx, extra, audit.Resource, uri, true)
				return nil, errUnknownResource(uri)
			}
			return m.readResource(ctx, &mcp.ReadResourceRequest{Session: req.Session, Params: req.Params, Extra: extra})
		}
	}
	v.a.deny(ctx, req.Extra, audit.Resource, uri)
	return nil, errUnknownResource(uri)
}

// route returns the server a resource URI belongs to.
func (v *View) route(uri string) (string, bool) {
	v.a.mu.Lock()
	defer v.a.mu.Unlock()
	var listed, matched []string
	for server, c := range v.claims {
		if c.uris[uri] {
			listed = append(listed, server)
		}
		for _, t := range c.templates {
			if t.Regexp().MatchString(uri) {
				matched = append(matched, server)
				break
			}
		}
	}
	switch {
	case len(listed) == 1:
		return listed[0], true
	case len(listed) == 0 && len(matched) == 1:
		return matched[0], true
	}
	return "", false
}

// deny writes the audit record of a request the aggregate refuses before any server sees it, with
// no server named.
func (a *Aggregate) deny(ctx context.Context, extra *mcp.RequestExtra, kind audit.Kind, name string) {
	if reached, ok := ctx.Value(reachedKey{}).(*bool); ok {
		*reached = true
	}
	a.audit.Write(audit.Record{
		Principal: principalOf(extra), Kind: kind, Name: a.logText(name), Outcome: audit.Denied, TokenPolicy: policy.NoPolicy,
	})
}

// receive is the view's receiving middleware (see receiving). A refused name whose server the
// caller may reach is audited by that server's mirror, as on the server's route; a tool call or
// prompt get of any other name by the aggregate, and a read of a URI no member the caller may
// reach serves not at all.
func (v *View) receive(next mcp.MethodHandler) mcp.MethodHandler {
	return receiving(v.a.logger, func(ctx context.Context, extra *mcp.RequestExtra, kind audit.Kind, name string) {
		if kind == audit.Resource {
			if server, ok := v.route(name); ok {
				if extra, m, ok := v.admit(extra, server); ok {
					m.refusedEarly(ctx, extra, kind, name, false)
				}
			}
			return
		}
		if server, rest, ok := splitName(name); ok {
			if extra, m, ok := v.admit(extra, server); ok {
				v.a.mu.Lock()
				skipped := v.a.skipped[named{kind, name}]
				v.a.mu.Unlock()
				m.refusedEarly(ctx, extra, kind, rest, skipped)
				return
			}
		}
		v.a.deny(ctx, extra, kind, name)
	})(next)
}

package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yosida95/uritemplate/v3"

	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/redact"
	"github.com/vsem-azamat/mcp-gate/internal/upstream"
)

// Separator joins a server's name and a tool or prompt name in the aggregate catalog.
const Separator = config.AggregateSeparator

// MaxAggregateName is the longest tool or prompt name the aggregate catalog serves: the limit
// many clients put on tool names.
const MaxAggregateName = 64

// aggregateNameRE is what an aggregate name may hold: the characters the MCP specification
// allows in tool names, up to MaxAggregateName.
var aggregateNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

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
}

// Aggregate serves the catalogs of several mirrors at one route. Tools and prompts are named
// <server>__<name>; resources and templates keep their URIs. Each set of servers a caller may
// reach has its own View, an upstream MCP server holding only those servers' entries. Calls are
// handed to the mirror of the server an entry came from, which filters, forwards, redacts and
// audits them as on its own route.
type Aggregate struct {
	opts    AggregateOptions
	logger  *slog.Logger
	engine  *redact.Engine // scrubs logged names that belong to no member, with every rule
	members map[string]*Mirror

	mu      sync.Mutex
	tools   map[string]routed[mcp.Tool]
	prompts map[string]routed[mcp.Prompt]
	cats    map[string]Catalog
	listed  map[string]bool // the members whose listed catalog the views hold
	skipped map[string]bool
	views   []*View
}

// routed is an entry of the aggregate catalog and where it came from.
type routed[T any] struct {
	server, name string
	entry        *T
}

// NewAggregate returns an aggregate of opts.Members. It must be made before the members start.
func NewAggregate(opts AggregateOptions) (*Aggregate, error) {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	// Names no member scrubs are logged under every rule there is, at least as strict as any
	// member's own.
	engine, err := redact.New(redact.Options{Russian: true, HighEntropy: true})
	if err != nil {
		return nil, err
	}
	a := &Aggregate{
		opts: opts, logger: opts.Logger, engine: engine, members: map[string]*Mirror{},
		skipped: map[string]bool{},
	}
	for _, m := range opts.Members {
		a.members[m.Name()] = m
		m.Watch(a.refresh)
	}
	a.mu.Lock()
	a.rebuild()
	a.mu.Unlock()
	return a, nil
}

// Listed reports whether the views hold a listed catalog of the member server. A mirror reports
// itself ready before its watchers run, so the aggregate's own record is what tells that its
// entries reached the views.
func (a *Aggregate) Listed(server string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.listed[server]
}

// SplitName splits an aggregate tool or prompt name into the server and the server's own name.
// Server names in the aggregate hold no Separator, so the first one ends the server's name.
func SplitName(name string) (server, rest string, ok bool) {
	return strings.Cut(name, Separator)
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

// rebuild reads the members' catalogs and names their tools and prompts. A name that is too long
// or holds characters the MCP specification does not allow is left out, and logged once.
func (a *Aggregate) rebuild() {
	a.cats = make(map[string]Catalog, len(a.members))
	a.listed = make(map[string]bool, len(a.members))
	a.tools = map[string]routed[mcp.Tool]{}
	a.prompts = map[string]routed[mcp.Prompt]{}
	skipped := map[string]bool{}
	names := make([]string, 0, len(a.members))
	for name := range a.members {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, server := range names {
		m := a.members[server]
		// Read before the catalog: a mirror is ready only once its tools were applied.
		a.listed[server] = m.Ready()
		c := m.Catalog()
		a.cats[server] = c
		for name, t := range c.Tools {
			full := server + Separator + name
			if !aggregateNameRE.MatchString(full) {
				skipped["tool\x00"+full] = true
				a.logSkipped(m, "tool", full)
				continue
			}
			a.tools[full] = routed[mcp.Tool]{server: server, name: name, entry: t}
		}
		for name, p := range c.Prompts {
			full := server + Separator + name
			if !aggregateNameRE.MatchString(full) {
				skipped["prompt\x00"+full] = true
				a.logSkipped(m, "prompt", full)
				continue
			}
			a.prompts[full] = routed[mcp.Prompt]{server: server, name: name, entry: p}
		}
	}
	// Config validation keeps member names free of a trailing '_' and of the separator, so a
	// name splits one way only; a clash would still be dropped rather than routed by chance.
	for full, r := range a.tools {
		if server, _, _ := SplitName(full); server != r.server {
			delete(a.tools, full)
		}
	}
	for full, r := range a.prompts {
		if server, _, _ := SplitName(full); server != r.server {
			delete(a.prompts, full)
		}
	}
	a.skipped = skipped
}

func (a *Aggregate) logSkipped(m *Mirror, kind, full string) {
	if a.skipped[kind+"\x00"+full] {
		return
	}
	a.logger.Warn("left out of the aggregate catalog: the prefixed name is longer than 64 characters or holds characters outside A-Z a-z 0-9 _ . -",
		"server", m.Name(), "kind", kind, "name", m.logText(full))
}

// View returns the view of the given members, which a caller who may reach exactly those
// servers is served.
func (a *Aggregate) View(servers []string) *View {
	v := &View{
		a: a, servers: map[string]bool{},
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
	v.server = mcp.NewServer(&mcp.Implementation{Name: a.opts.Name, Version: a.opts.Version}, &mcp.ServerOptions{
		Logger:       upstream.SDKLogger(a.logger),
		Capabilities: caps,
	})
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
	server  *mcp.Server

	// Guarded by a.mu.
	tools     map[string]*mcp.Tool
	prompts   map[string]*mcp.Prompt
	resources map[string]*mcp.Resource
	templates map[string]*mcp.ResourceTemplate
	claims    map[string]claim
}

// claim is what a server's catalog says it serves, for routing a resource read.
type claim struct {
	uris      map[string]bool
	templates []*uritemplate.Template
}

// Server is the upstream-facing MCP server of the view.
func (v *View) Server() *mcp.Server { return v.server }

// sync registers the view's share of the aggregate catalog. A resource URI or a template that
// more than one of the view's servers lists is left out, since a read could not tell which
// server it is for. The caller holds a.mu.
func (v *View) sync() {
	a := v.a
	tools := map[string]*mcp.Tool{}
	for full, r := range a.tools {
		if v.servers[r.server] {
			t := *r.entry
			t.Name = full
			tools[full] = &t
		}
	}
	v.tools = syncSet(a.logger, a.logText, "tool", v.tools, tools, func(t *mcp.Tool) error {
		r := a.tools[t.Name]
		return guard(func() { v.server.AddTool(t, v.callTool(r.server, r.name)) })
	}, v.server.RemoveTools)

	prompts := map[string]*mcp.Prompt{}
	for full, r := range a.prompts {
		if v.servers[r.server] {
			p := *r.entry
			p.Name = full
			prompts[full] = &p
		}
	}
	v.prompts = syncSet(a.logger, a.logText, "prompt", v.prompts, prompts, func(p *mcp.Prompt) error {
		r := a.prompts[p.Name]
		return guard(func() { v.server.AddPrompt(p, v.getPrompt(r.server, r.name)) })
	}, v.server.RemovePrompts)

	resources := map[string]*mcp.Resource{}
	templates := map[string]*mcp.ResourceTemplate{}
	seenURI := map[string]int{}
	seenTemplate := map[string]int{}
	v.claims = map[string]claim{}
	for server := range v.servers {
		c := a.cats[server]
		cl := claim{uris: map[string]bool{}}
		for uri, r := range c.Resources {
			cl.uris[uri] = true
			seenURI[uri]++
			resources[uri] = r
		}
		for ut, t := range c.Templates {
			if tmpl, err := uritemplate.New(ut); err == nil {
				cl.templates = append(cl.templates, tmpl)
			}
			seenTemplate[ut]++
			templates[ut] = t
		}
		v.claims[server] = cl
	}
	for uri, n := range seenURI {
		if n > 1 {
			delete(resources, uri)
		}
	}
	for ut, n := range seenTemplate {
		if n > 1 {
			delete(templates, ut)
		}
	}
	v.resources = syncSet(a.logger, a.logText, "resource", v.resources, resources, func(r *mcp.Resource) error {
		return guard(func() { v.server.AddResource(r, v.readResource) })
	}, v.server.RemoveResources)
	v.templates = syncSet(a.logger, a.logText, "resource template", v.templates, templates, func(t *mcp.ResourceTemplate) error {
		return guard(func() { v.server.AddResourceTemplate(t, v.readResource) })
	}, v.server.RemoveResourceTemplates)
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
			v.a.deny(ctx, "tools/call", req.Extra, "tool", req.Params.Name)
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: fmt.Sprintf("unknown tool %q", req.Params.Name)}
		}
		if !m.mirrored("tool", name) {
			// Gone from the mirror but not yet from the view: refused as on the server's route.
			m.refused(ctx, "tools/call", extra, "tool", name, true)
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: fmt.Sprintf("unknown tool %q", req.Params.Name)}
		}
		params := *req.Params
		params.Name = name
		return m.callTool(ctx, &mcp.CallToolRequest{Session: req.Session, Params: &params, Extra: extra})
	}
}

func (v *View) getPrompt(server, name string) mcp.PromptHandler {
	return func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		extra, m, ok := v.admit(req.Extra, server)
		if !ok {
			v.a.deny(ctx, "prompts/get", req.Extra, "prompt", req.Params.Name)
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: fmt.Sprintf("unknown prompt %q", req.Params.Name)}
		}
		if !m.mirrored("prompt", name) {
			m.refused(ctx, "prompts/get", extra, "prompt", name, true)
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: fmt.Sprintf("unknown prompt %q", req.Params.Name)}
		}
		params := *req.Params
		params.Name = name
		return m.getPrompt(ctx, &mcp.GetPromptRequest{Session: req.Session, Params: &params, Extra: extra})
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
				m.refused(ctx, "resources/read", extra, "uri", uri, true)
				return nil, mcp.ResourceNotFoundError(uri)
			}
			return m.readResource(ctx, &mcp.ReadResourceRequest{Session: req.Session, Params: req.Params, Extra: extra})
		}
	}
	v.a.deny(ctx, "resources/read", req.Extra, "uri", uri)
	return nil, mcp.ResourceNotFoundError(uri)
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

// deny writes the audit line of a request the aggregate refuses before any server sees it, with
// no server named.
func (a *Aggregate) deny(ctx context.Context, method string, extra *mcp.RequestExtra, key, name string) {
	if reached, ok := ctx.Value(reachedKey{}).(*bool); ok {
		*reached = true
	}
	principal := ""
	if extra != nil {
		principal = upstream.Principal(extra.TokenInfo)
	}
	a.logger.Info("call", "server", "", "principal", principal, "method", method, key, a.logText(name),
		"durMs", int64(0), "outcome", outcomeDenied, "redactions", 0)
}

// receive is the view's receiving middleware, as a mirror's: it answers a panic with an internal
// error, and writes the audit line of a tool call or prompt get the SDK refuses before a handler
// runs. A name whose server the caller may reach is audited by that server's mirror.
func (v *View) receive(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (res mcp.Result, err error) {
		defer func() {
			if p := recover(); p != nil {
				v.a.logger.Error("request handler panicked", "method", method, "type", fmt.Sprintf("%T", p))
				res, err = nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "mcp-gate: internal error"}
			}
		}()
		var key, name string
		switch r := req.(type) {
		case *mcp.CallToolRequest:
			if r.Params != nil {
				key, name = "tool", r.Params.Name
			}
		case *mcp.GetPromptRequest:
			if r.Params != nil {
				key, name = "prompt", r.Params.Name
			}
		}
		if key == "" {
			return next(ctx, method, req)
		}
		reached := new(bool)
		res, err = next(context.WithValue(ctx, reachedKey{}, reached), method, req)
		if err != nil && !*reached {
			if server, rest, ok := SplitName(name); ok {
				if extra, m, ok := v.admit(req.GetExtra(), server); ok {
					v.a.mu.Lock()
					skipped := v.a.skipped[key+"\x00"+name]
					v.a.mu.Unlock()
					m.refused(ctx, method, extra, key, rest, skipped)
					return res, err
				}
			}
			v.a.deny(ctx, method, req.GetExtra(), key, name)
		}
		return res, err
	}
}

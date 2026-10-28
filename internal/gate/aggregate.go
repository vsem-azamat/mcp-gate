package gate

import (
	"context"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/proxy"
	"github.com/vsem-azamat/mcp-gate/internal/upstream"
)

// aggregate is the access control of the aggregate route. A request may reach a member server
// exactly when that server's own route would take its Authorization header: a public member
// always, any other when the token is one the member accepts. The servers a request may reach,
// and the token policies it has on them, select the view it is served, which holds only the
// entries of those servers that the policies pass.
type aggregate struct {
	members []string                    // sorted
	tokens  map[string]*upstream.Tokens // by member; nil for a public one
	mirrors map[string]*proxy.Mirror    // by member
	views   map[string]*proxy.View      // by viewKey of the access it serves
	// rejected, if set, counts a request refused with 401.
	rejected func()
}

// grant is what one request to the aggregate route may reach.
type grant struct {
	access    map[string]string // member → the token name it accepted, "" when public
	principal string            // the token names, joined, for lines that name no server
	view      *proxy.View
}

type grantKey struct{}

// policyTokens returns, for the servers of an access on which its token has a policy, the
// token's name there.
func (a *aggregate) policyTokens(access map[string]string) map[string]string {
	out := map[string]string{}
	for server, principal := range access {
		if a.mirrors[server].TokenPolicy(principal) != nil {
			out[server] = principal
		}
	}
	return out
}

// viewKey identifies the view of an access: the servers it reaches, each with the name of the
// token whose policy narrows it there, if any.
func (a *aggregate) viewKey(access map[string]string) string {
	parts := make([]string, 0, len(access))
	tokens := a.policyTokens(access)
	for _, server := range slices.Sorted(maps.Keys(access)) {
		part := server
		if token, ok := tokens[server]; ok {
			part += viewKeyToken + token
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, viewKeyServer)
}

// The separators of a view key: between servers, and between a server and its token name.
// Neither can occur in a server or token name.
const (
	viewKeyServer = "\x00"
	viewKeyToken  = "\x01"
)

// aggregateRoute returns the aggregate route of sn: prev, the route of the snapshot being
// replaced, when its members' mirrors and its config values are unchanged, else a new one with a
// view for every access a token, or no token, has. The tokens and policies of a snapshot do not
// change, so the accesses are known here.
func (g *Gate) aggregateRoute(sn *snapshot, prev *route, again http.Handler) (*route, error) {
	members := sn.cfg.AggregateMembers()
	mirrors := make([]*proxy.Mirror, 0, len(members))
	tokens := map[string]map[string]string{}
	configs := make([]*config.Server, 0, len(members))
	for _, name := range members {
		mirrors = append(mirrors, sn.servers[name].mirror)
		tokens[name] = sn.cfg.EffectiveTokens(name)
		configs = append(configs, sn.servers[name].cfg)
	}
	key := routeKey(sn.cfg, configs...)
	key["members"] = members
	if prev.keeps(key, mirrors) {
		return prev, nil
	}
	a := &aggregate{
		members: members, tokens: map[string]*upstream.Tokens{}, mirrors: map[string]*proxy.Mirror{}, views: map[string]*proxy.View{},
		rejected: g.rejected(config.AggregatePath),
	}
	for _, name := range members {
		a.mirrors[name] = sn.servers[name].mirror
		if t := tokens[name]; t != nil {
			a.tokens[name] = upstream.NewTokens(t)
		}
	}
	if len(members) == 0 {
		g.logger.Warn("the aggregate endpoint serves no server: every server it would serve is disabled")
	}
	agg, err := proxy.NewAggregate(proxy.AggregateOptions{Name: sn.cfg.Name, Version: g.opts.Version, Members: mirrors, Logger: g.logger, Audit: g.audit})
	if err != nil {
		return nil, err
	}
	secrets := []string{""} // no token
	for _, name := range members {
		for _, secret := range tokens[name] {
			secrets = append(secrets, secret)
		}
	}
	for _, secret := range secrets {
		header := ""
		if secret != "" {
			header = "Bearer " + secret
		}
		access, ok := a.access(header)
		if !ok {
			continue
		}
		key := a.viewKey(access)
		if a.views[key] == nil {
			a.views[key] = agg.View(slices.Sorted(maps.Keys(access)), a.policyTokens(access))
		}
	}
	// A request is served once startup is over, or once every server it may reach was listed or
	// waits for a login (which does not hold the startup either); until then it is held (see
	// awaitReady), so that a client that connects early does not take an empty catalog for the
	// whole one.
	ready := func(r *http.Request) (ok, pending bool) {
		gr, _ := r.Context().Value(grantKey{}).(*grant)
		if gr == nil {
			return g.started.Load(), false
		}
		// A member that a reload restarts holds the request, as on its own route.
		for name := range gr.access {
			if sn.servers[name].rt.restarting.Load() && sn.servers[name].sup.Status().ConnectsOnItsOwn() {
				return false, true
			}
		}
		if g.started.Load() {
			return true, false
		}
		for name := range gr.access {
			s := sn.servers[name]
			if !agg.Listed(name) && s.sup.Status().ConnectsOnItsOwn() {
				return false, true
			}
		}
		return true, false
	}
	getServer := func(r *http.Request) *mcp.Server {
		gr, _ := r.Context().Value(grantKey{}).(*grant)
		if gr == nil {
			return nil
		}
		return gr.view.Server()
	}
	rt := newRoute(key, again)
	rt.mirrors, rt.agg = mirrors, agg
	rt.handler = g.chain(sn, rt, config.AggregatePath, sn.cfg.Aggregate.Log.Requests, a.authorize, ready, getServer)
	return rt, nil
}

// access returns the members a request may reach, given its Authorization header, each with the
// name of the token it accepted (see upstream.Tokens.Authenticate). A request without the header
// reaches the public members; one whose header no member accepts reaches nothing, as on the
// members' own routes.
func (a *aggregate) access(header string) (map[string]string, bool) {
	present := strings.TrimSpace(header) != ""
	access := map[string]string{}
	matched := false
	for _, name := range a.members {
		t := a.tokens[name]
		if t == nil {
			access[name] = ""
			continue
		}
		if !present {
			continue
		}
		if principal, ok := t.Authenticate(header); ok {
			access[name] = principal
			matched = true
		}
	}
	if (present && !matched) || len(access) == 0 {
		return nil, false
	}
	return access, true
}

// authorize lets through only requests that may reach some member, with their grant in the
// context and their access in the TokenInfo the MCP handlers see. Others get 401 with the body
// "Unauthorized", and are counted.
func (a *aggregate) authorize(next http.Handler) http.Handler {
	return upstream.Authorize(func(r *http.Request) (context.Context, *auth.TokenInfo, bool) {
		access, ok := a.access(r.Header.Get("Authorization"))
		if !ok {
			return nil, nil, false
		}
		view := a.views[a.viewKey(access)]
		if view == nil {
			return nil, nil, false
		}
		gr := &grant{access: access, principal: principals(access), view: view}
		return context.WithValue(r.Context(), grantKey{}, gr), proxy.AccessInfo(gr.principal, gr.access), true
	}, a.rejected, next)
}

// principals joins the distinct token names of an access, sorted.
func principals(access map[string]string) string {
	seen := map[string]bool{}
	var names []string
	for _, p := range access {
		if p != "" && !seen[p] {
			seen[p] = true
			names = append(names, p)
		}
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

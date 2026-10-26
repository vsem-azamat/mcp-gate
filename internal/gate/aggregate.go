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
	"github.com/vsem-azamat/mcp-gate/internal/downstream"
	"github.com/vsem-azamat/mcp-gate/internal/policy"
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
}

// grant is what one request to the aggregate route may reach.
type grant struct {
	access    map[string]string // member → the token name it accepted, "" when public
	principal string            // the token names, joined, for lines that name no server
	view      *proxy.View
}

type grantKey struct{}

// policies returns the token policies of an access, by server; servers on which the token has
// none are left out.
func (a *aggregate) policies(access map[string]string) map[string]*policy.Token {
	out := map[string]*policy.Token{}
	for server, principal := range access {
		if p := a.mirrors[server].TokenPolicy(principal); p != nil {
			out[server] = p
		}
	}
	return out
}

// viewKey identifies the view of an access: the servers it reaches, each with the name of the
// token whose policy narrows it there, if any.
func (a *aggregate) viewKey(access map[string]string) string {
	parts := make([]string, 0, len(access))
	policies := a.policies(access)
	for _, server := range slices.Sorted(maps.Keys(access)) {
		part := server
		if policies[server] != nil {
			part += viewKeyToken + access[server]
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

// aggregateRoute builds the aggregate route and a view for every access a token, or no token,
// has. Tokens and policies do not change while the gate runs, so the accesses are known here.
func (g *Gate) aggregateRoute(remote upstream.RemoteFunc) (http.Handler, error) {
	members := g.cfg.AggregateMembers()
	mirrors := make([]*proxy.Mirror, 0, len(members))
	a := &aggregate{members: members, tokens: map[string]*upstream.Tokens{}, mirrors: map[string]*proxy.Mirror{}, views: map[string]*proxy.View{}}
	for _, name := range members {
		mirrors = append(mirrors, g.servers[name].mirror)
		a.mirrors[name] = g.servers[name].mirror
		if t := g.cfg.EffectiveTokens(name); t != nil {
			a.tokens[name] = upstream.NewTokens(t)
		}
	}
	if len(members) == 0 {
		g.logger.Warn("the aggregate endpoint serves no server: every server it would serve is disabled")
	}
	agg, err := proxy.NewAggregate(proxy.AggregateOptions{Name: g.cfg.Name, Version: g.opts.Version, Members: mirrors, Logger: g.logger})
	if err != nil {
		return nil, err
	}
	secrets := []string{""} // no token
	for _, name := range members {
		for _, secret := range g.cfg.EffectiveTokens(name) {
			secrets = append(secrets, secret)
		}
	}
	for _, secret := range secrets {
		access, ok := a.access(secret, secret != "")
		if !ok {
			continue
		}
		key := a.viewKey(access)
		if a.views[key] == nil {
			a.views[key] = agg.View(slices.Sorted(maps.Keys(access)), a.policies(access))
		}
	}
	// A request is served once startup is over, or once every server it may reach was listed or
	// waits for a login (which does not hold the startup either), so that a client that connects
	// early does not take an empty catalog for the whole one.
	ready := func(r *http.Request) bool {
		if g.started.Load() {
			return true
		}
		gr, _ := r.Context().Value(grantKey{}).(*grant)
		if gr == nil {
			return false
		}
		for name := range gr.access {
			s := g.servers[name]
			if !agg.Listed(name) && s.sup.Status().State != downstream.NeedsLogin {
				return false
			}
		}
		return true
	}
	getServer := func(r *http.Request) *mcp.Server {
		gr, _ := r.Context().Value(grantKey{}).(*grant)
		if gr == nil {
			return nil
		}
		return gr.view.Server()
	}
	log := g.cfg.Aggregate.Log.Requests
	return g.chain(config.AggregatePath, log, remote, a.authorize, ready, getServer), nil
}

// access returns the members a request may reach, given the credential of its Authorization
// header and whether it had one. A request without one reaches the public members; one with a
// credential that no member accepts reaches nothing, as on the members' own routes.
func (a *aggregate) access(secret string, present bool) (map[string]string, bool) {
	if present && (secret == "" || strings.ContainsAny(secret, " \t")) {
		return nil, false
	}
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
		if principal, ok := t.Lookup(secret); ok {
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
// "Unauthorized".
func (a *aggregate) authorize(next http.Handler) http.Handler {
	verify := func(_ context.Context, _ string, r *http.Request) (*auth.TokenInfo, error) {
		gr, _ := r.Context().Value(grantKey{}).(*grant)
		if gr == nil {
			return nil, auth.ErrInvalidToken
		}
		return proxy.AccessInfo(gr.principal, gr.access), nil
	}
	inner := auth.RequireBearerToken(verify, &auth.RequireBearerTokenOptions{AllowMissingExpiration: true})(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		access, ok := a.access(upstream.Credential(header), strings.TrimSpace(header) != "")
		var view *proxy.View
		if ok {
			view = a.views[a.viewKey(access)]
		}
		if view == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		gr := &grant{access: access, principal: principals(access), view: view}
		r = r.Clone(context.WithValue(r.Context(), grantKey{}, gr))
		// The SDK middleware reads a bearer header; the grant above is what it passes on.
		r.Header.Set("Authorization", "Bearer aggregate")
		inner.ServeHTTP(w, r)
	})
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

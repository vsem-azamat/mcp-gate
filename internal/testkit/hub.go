// Package testkit provides fake MCP servers for tests.
package testkit

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Catalog is what a fake server lists. Its entries are served as given; calling a tool, getting a
// prompt or reading a resource fails.
type Catalog struct {
	Tools             []*mcp.Tool
	Prompts           []*mcp.Prompt
	Resources         []*mcp.Resource
	ResourceTemplates []*mcp.ResourceTemplate
}

// HubOptions configures a fake hub.
type HubOptions struct {
	// Servers maps a server name to its catalog, served at /<name>/mcp.
	Servers map[string]Catalog
	// Token, if set, is required as "Authorization: Bearer <Token>" on every request; other
	// requests get 401.
	Token string
	// PageSize is the list page size; 0 is the SDK default.
	PageSize int
	// ProtocolVersions, if set, narrows the protocol versions the servers negotiate.
	ProtocolVersions []string
	// Capabilities, if set, are exactly the capabilities the servers advertise, instead of the
	// ones the SDK infers from the catalog. The lists are served either way.
	Capabilities *mcp.ServerCapabilities
	// JSONResponse answers requests with application/json instead of an event stream.
	JSONResponse bool
}

// Hub is an HTTP server that serves fake MCP servers over stateless streamable HTTP, the way an MCP
// gateway serves its downstreams. It is closed when the test ends.
type Hub struct {
	srv          *httptest.Server
	unauthorized atomic.Int64
}

// errNotServed is what every call, prompt get and resource read returns.
var errNotServed = errors.New("testkit: the fake server serves only lists")

// NewHub starts a hub serving opts.Servers.
func NewHub(t testing.TB, opts HubOptions) *Hub {
	t.Helper()
	h := &Hub{}
	mux := http.NewServeMux()
	for name, cat := range opts.Servers {
		s := newServer(name, cat, opts)
		handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s },
			&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: opts.JSONResponse})
		mux.Handle("/"+name+"/mcp", h.requireToken(opts.Token, handler))
	}
	h.srv = httptest.NewServer(mux)
	t.Cleanup(h.srv.Close)
	return h
}

// URLTemplate is the hub's endpoint template, with {server} in place of the server name.
func (h *Hub) URLTemplate() string { return h.srv.URL + "/{server}/mcp" }

// Unauthorized is the number of requests rejected for a missing or wrong token.
func (h *Hub) Unauthorized() int64 { return h.unauthorized.Load() }

func (h *Hub) requireToken(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			h.unauthorized.Add(1)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func newServer(name string, cat Catalog, opts HubOptions) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: name, Version: "test"}, &mcp.ServerOptions{
		PageSize:                  opts.PageSize,
		SupportedProtocolVersions: opts.ProtocolVersions,
	})
	if opts.Capabilities != nil {
		s.AddReceivingMiddleware(advertise(opts.Capabilities))
	}
	for _, tool := range cat.Tools {
		s.AddTool(tool, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return nil, errNotServed
		})
	}
	for _, p := range cat.Prompts {
		s.AddPrompt(p, func(context.Context, *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			return nil, errNotServed
		})
	}
	readResource := func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return nil, errNotServed
	}
	for _, r := range cat.Resources {
		s.AddResource(r, readResource)
	}
	for _, rt := range cat.ResourceTemplates {
		s.AddResourceTemplate(rt, readResource)
	}
	return s
}

// advertise replaces the capabilities in the server's initialize and discover results.
func advertise(caps *mcp.ServerCapabilities) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			res, err := next(ctx, method, req)
			c := *caps
			switch r := res.(type) {
			case *mcp.InitializeResult:
				r.Capabilities = &c
			case *mcp.DiscoverResult:
				r.Capabilities = &c
			}
			return res, err
		}
	}
}

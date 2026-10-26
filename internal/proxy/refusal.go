package proxy

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/audit"
	"github.com/vsem-azamat/mcp-gate/internal/policy"
)

// reachedKey marks, in a request's context, whether the request reached a handler of the gate,
// which writes its audit record.
type reachedKey struct{}

// receiving returns the receiving middleware of a mirror's or a view's servers. It answers a
// request whose handling panics with an internal error, logging only the panic's type, since
// the SDK handles requests on goroutines of its own that nothing else recovers. A tool call,
// prompt get or resource read that fails without reaching a handler of the gate, such as one
// the SDK refuses because the server holds no entry of that name, is handed to refused with its
// kind and the name it gives, so that it is audited too.
func receiving(logger *slog.Logger, refused func(ctx context.Context, extra *mcp.RequestExtra, kind audit.Kind, name string)) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (res mcp.Result, err error) {
			defer func() {
				if v := recover(); v != nil {
					logger.Error("request handler panicked", "method", method, "type", fmt.Sprintf("%T", v))
					res, err = nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "mcp-gate: internal error"}
				}
			}()
			kind, name := entryOf(req)
			if kind == 0 {
				return next(ctx, method, req)
			}
			reached := new(bool)
			res, err = next(context.WithValue(ctx, reachedKey{}, reached), method, req)
			if err != nil && !*reached {
				refused(ctx, req.GetExtra(), kind, name)
			}
			return res, err
		}
	}
}

// entryOf returns the kind of a tool call, prompt get or resource read and the name it gives;
// a kind of 0 for any other request.
func entryOf(req mcp.Request) (audit.Kind, string) {
	switch r := req.(type) {
	case *mcp.CallToolRequest:
		if r.Params != nil {
			return audit.Tool, r.Params.Name
		}
	case *mcp.GetPromptRequest:
		if r.Params != nil {
			return audit.Prompt, r.Params.Name
		}
	case *mcp.ReadResourceRequest:
		if r.Params != nil {
			return audit.Resource, r.Params.URI
		}
	}
	return 0, ""
}

// receive is the receiving middleware of the mirror's servers (see receiving).
func (m *Mirror) receive(next mcp.MethodHandler) mcp.MethodHandler {
	return receiving(m.logger, func(ctx context.Context, extra *mcp.RequestExtra, kind audit.Kind, name string) {
		m.refusedEarly(ctx, extra, kind, name, false)
	})(next)
}

// refusedEarly audits a request for an entry of the mirror that was refused before a handler
// ran (see refused). A resource read is audited only when the caller's token policy hides its
// URI: a read of a URI the server does not serve is not.
func (m *Mirror) refusedEarly(ctx context.Context, extra *mcp.RequestExtra, kind audit.Kind, name string, hidden bool) {
	if kind == audit.Resource && m.decision(principalOf(extra), kind, name) != policy.Denied {
		return
	}
	m.refused(ctx, extra, kind, name, hidden)
}

// refused writes the audit record of a tool call, prompt get or resource read that did not reach
// a handler: denied when the name is not in the mirrored catalog, hidden is set or the caller's
// token policy hides it, an error otherwise.
func (m *Mirror) refused(ctx context.Context, extra *mcp.RequestExtra, kind audit.Kind, name string, hidden bool) {
	c := m.begin(ctx, kind, extra, name)
	c.decision = m.decision(principalOf(extra), kind, name)
	c.outcome = audit.Error
	if hidden || c.decision == policy.Denied || !m.mirrored(kind, name) {
		c.outcome = audit.Denied
	}
	c.end()
}

package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/audit"
	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/downstream"
	"github.com/vsem-azamat/mcp-gate/internal/policy"
	"github.com/vsem-azamat/mcp-gate/internal/redact"
	"github.com/vsem-azamat/mcp-gate/internal/upstream"
)

// errNeedsInput is returned for a result that asks the client for input, which mcp-gate does
// not forward.
var errNeedsInput = errors.New("this request needs interactive input from the client, which mcp-gate does not support")

// call is one forwarded request, for its audit record.
type call struct {
	m         *Mirror
	kind      audit.Kind
	principal string
	decision  policy.Decision // of the caller's token policy
	start     time.Time
	name      string // fit for the log
	outcome   audit.Outcome
	count     *counter
	req       Request
}

// begin starts the audit record of a request for the entry of the given kind and name (a tool or
// prompt name, a resource URI), and counts the call.
func (m *Mirror) begin(ctx context.Context, kind audit.Kind, extra *mcp.RequestExtra, name string) *call {
	if reached, ok := ctx.Value(reachedKey{}).(*bool); ok {
		*reached = true
	}
	m.src.stats.calls.Add(1)
	return &call{
		m: m, kind: kind, principal: principalOf(extra), decision: policy.NoPolicy, start: time.Now(), name: m.logText(name),
		outcome: audit.OK, count: &counter{},
	}
}

// end hands the call's audit record to the mirror's sink. Arguments and results are never in it.
func (c *call) end() {
	c.m.emit(audit.Record{
		Server: c.m.opts.Name, Principal: c.principal, Kind: c.kind, Name: c.name, Duration: time.Since(c.start),
		Outcome: c.outcome, TokenPolicy: c.decision, Redactions: c.count.n.Load(),
	})
}

// emit is where every audit record of the mirror goes: it counts a failed call and hands the
// record to the sink.
func (m *Mirror) emit(r audit.Record) {
	if r.Outcome.Failed() {
		m.src.stats.failed.Add(1)
	}
	m.audit.Write(r)
}

// toolError is a tool result that reports an error to the model.
func toolError(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

// downstreamError turns a failed call into what the client gets, and sets the outcome. Every
// error is rebuilt, so that nothing the SDK or the server put in it reaches the client
// unchecked: its message never quotes the server's URL (an HTTP request that fails is reported
// with its full URL, inside a JSON-RPC error) and is redacted. A JSON-RPC error keeps its code.
// The data of a JSON-RPC error reply has the URL replaced and is redacted with the result, or
// dropped when results are not redacted.
func (c *call) downstreamError(ctx context.Context, err error) error {
	c.outcome = audit.Error
	switch {
	case ctx.Err() != nil && errors.Is(err, ctx.Err()):
		return ctx.Err() // the client has gone; the error may quote the server's URL
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("server %s did not answer in time", c.m.opts.Name)
	}
	var rpc *jsonrpc.Error
	if !errors.As(err, &rpc) || rpc == nil {
		return errors.New(c.m.src.down.ErrorText(err))
	}
	r := c.m.opts.Redaction
	if r == nil {
		return &jsonrpc.Error{Code: rpc.Code, Message: c.m.src.down.ErrorText(err)}
	}
	fresh := &jsonrpc.Error{Code: rpc.Code, Message: c.m.src.down.HideURL(err.Error())}
	if direct, ok := err.(*jsonrpc.Error); ok && direct == rpc { //nolint:errorlint // only an unwrapped error reply carries its data to the wire
		fresh.Data = json.RawMessage(c.m.src.down.HideURL(string(rpc.Data)))
	}
	return r.results.Error(fresh, c.replacer())
}

func (c *call) replacer() *countingReplacer {
	return &countingReplacer{next: c.m.opts.Redaction.replacer(c.req), n: c.count}
}

// toolArguments decodes a tool call's arguments once, when first asked for.
func toolArguments(raw json.RawMessage) func() map[string]any {
	return sync.OnceValue(func() map[string]any {
		var args map[string]any
		if len(raw) == 0 || json.Unmarshal(raw, &args) != nil {
			return nil
		}
		return args
	})
}

// promptArguments returns a prompt get's arguments.
func promptArguments(in map[string]string) func() map[string]any {
	return sync.OnceValue(func() map[string]any {
		if len(in) == 0 {
			return nil
		}
		out := make(map[string]any, len(in))
		for k, v := range in {
			out[k] = v
		}
		return out
	})
}

// withheld reports a result that could not be redacted.
func (c *call) withheld(err error) error {
	c.outcome = audit.Withheld
	c.m.logger.Warn("result withheld: it could not be redacted", "method", c.kind.Method(), "error", err.Error())
	return fmt.Errorf("server %s: %w", c.m.opts.Name, err)
}

func (m *Mirror) callTool(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return m.callToolAs(ctx, req, req.Params.Name)
}

// callToolAs calls a tool that the caller named shown, the name its errors give.
func (m *Mirror) callToolAs(ctx context.Context, req *mcp.CallToolRequest, shown string) (*mcp.CallToolResult, error) {
	name := req.Params.Name
	c := m.begin(ctx, audit.Tool, req.Extra, name)
	defer c.end()
	c.req = Request{Method: audit.Tool.Method(), Name: name, Arguments: toolArguments(req.Params.Arguments)}
	c.decision = m.decision(c.principal, audit.Tool, name)
	if !m.opts.Policy.Tools.Allows(name) || !m.tokenAllows(c.principal, audit.Tool, name) {
		c.outcome = audit.Denied
		return nil, errUnknownTool(shown)
	}
	params := &mcp.CallToolParams{Name: name}
	if len(req.Params.Arguments) > 0 {
		params.Arguments = req.Params.Arguments
	}
	var res *mcp.CallToolResult
	start := time.Now()
	err := m.forward(ctx, req.Session, req.Params.Meta, func(meta mcp.Meta) { params.Meta = meta },
		func(ctx context.Context, cs *mcp.ClientSession) (err error) {
			res, err = cs.CallTool(ctx, params)
			return err
		})
	var nr *downstream.NotReadyError
	switch {
	case errors.As(err, &nr):
		c.outcome = audit.Unavailable
		return toolError(fmt.Sprintf("server %s is not available (%s); try again later", m.opts.Name, nr.State)), nil
	case err != nil:
		return nil, c.downstreamError(ctx, err)
	case res == nil:
		c.outcome = audit.Error
		return nil, fmt.Errorf("server %s returned no result", m.opts.Name)
	case len(res.InputRequests) > 0 || res.RequestState != "":
		c.outcome = audit.InputRequired
		return toolError(errNeedsInput.Error()), nil
	}
	if r := m.opts.Redaction; r != nil {
		if res, err = r.results.CallToolResult(res, c.replacer()); err != nil {
			return nil, c.withheld(err)
		}
		if f := m.opts.Files; f != nil {
			var n int
			if res, n, err = f.Scan(ctx, name, c.req.Arguments, res, start); err != nil {
				return nil, c.withheld(err)
			}
			c.count.n.Add(int64(n))
		}
	}
	if res.IsError {
		c.outcome = audit.ToolError
	}
	return res, nil
}

func (m *Mirror) getPrompt(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	return m.getPromptAs(ctx, req, req.Params.Name)
}

// getPromptAs gets a prompt that the caller named shown, the name its errors give.
func (m *Mirror) getPromptAs(ctx context.Context, req *mcp.GetPromptRequest, shown string) (*mcp.GetPromptResult, error) {
	name := req.Params.Name
	c := m.begin(ctx, audit.Prompt, req.Extra, name)
	defer c.end()
	c.req = Request{Method: audit.Prompt.Method(), Name: name, Arguments: promptArguments(req.Params.Arguments)}
	c.decision = m.decision(c.principal, audit.Prompt, name)
	if !m.opts.Policy.Prompts.Allows(name) || !m.tokenAllows(c.principal, audit.Prompt, name) {
		c.outcome = audit.Denied
		return nil, errUnknownPrompt(shown)
	}
	params := &mcp.GetPromptParams{Name: name, Arguments: req.Params.Arguments}
	var res *mcp.GetPromptResult
	err := m.forward(ctx, req.Session, req.Params.Meta, func(meta mcp.Meta) { params.Meta = meta },
		func(ctx context.Context, cs *mcp.ClientSession) (err error) {
			res, err = cs.GetPrompt(ctx, params)
			return err
		})
	if err = c.result(ctx, err, res == nil, res != nil && (len(res.InputRequests) > 0 || res.RequestState != "")); err != nil {
		return nil, err
	}
	if r := m.opts.Redaction; r != nil {
		if res, err = r.results.GetPromptResult(res, c.replacer()); err != nil {
			return nil, c.withheld(err)
		}
	}
	return res, nil
}

func (m *Mirror) readResource(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	uri := req.Params.URI
	c := m.begin(ctx, audit.Resource, req.Extra, uri)
	defer c.end()
	c.req = Request{Method: audit.Resource.Method(), Name: uri}
	c.decision = m.decision(c.principal, audit.Resource, uri)
	if !m.opts.Policy.ReadAllowed(uri) || !m.tokenAllows(c.principal, audit.Resource, uri) {
		c.outcome = audit.Denied
		return nil, errUnknownResource(uri)
	}
	params := &mcp.ReadResourceParams{URI: uri}
	var res *mcp.ReadResourceResult
	err := m.forward(ctx, req.Session, req.Params.Meta, func(meta mcp.Meta) { params.Meta = meta },
		func(ctx context.Context, cs *mcp.ClientSession) (err error) {
			res, err = cs.ReadResource(ctx, params)
			return err
		})
	if err = c.result(ctx, err, res == nil, res != nil && (len(res.InputRequests) > 0 || res.RequestState != "")); err != nil {
		return nil, err
	}
	if r := m.opts.Redaction; r != nil {
		if res, err = r.results.ReadResourceResult(res, c.replacer()); err != nil {
			return nil, c.withheld(err)
		}
	}
	return res, nil
}

// result maps the outcome of a prompt get or resource read, which have no tool-error form.
func (c *call) result(ctx context.Context, err error, empty, needsInput bool) error {
	var nr *downstream.NotReadyError
	switch {
	case errors.As(err, &nr):
		c.outcome = audit.Unavailable
		return fmt.Errorf("server %s is not available (%s); try again later", c.m.opts.Name, nr.State)
	case err != nil:
		return c.downstreamError(ctx, err)
	case empty:
		c.outcome = audit.Error
		return fmt.Errorf("server %s returned no result", c.m.opts.Name)
	case needsInput:
		c.outcome = audit.InputRequired
		return errNeedsInput
	}
	return nil
}

// scrub redacts a text from the server or a client that is not part of a result, such as a
// progress message, even when the server's results are not redacted.
func (m *Mirror) scrub(s string) string {
	if r := m.opts.Redaction; r != nil {
		return r.engine.RedactText(s, redact.Marker{})
	}
	return m.src.down.ErrorText(errors.New(s))
}

// logText makes a value from a request fit for the log: scrubbed and cut at 256 bytes.
func (m *Mirror) logText(s string) string {
	return redact.Cut(m.scrub(s), 256)
}

// forward runs fn on the downstream session with the downstream _meta, built by setMeta from the
// upstream one, and remaps progress while it runs. ctx is the upstream request's: its
// cancellation cancels the downstream call, and progress is sent on its stream.
func (m *Mirror) forward(ctx context.Context, ss *mcp.ServerSession, meta mcp.Meta, setMeta func(mcp.Meta),
	fn func(context.Context, *mcp.ClientSession) error,
) error {
	down := downstreamMeta(meta, m.opts.ForwardMeta)
	if token := progressToken(meta); token != nil && ss != nil {
		sink := m.src.progress.open(ctx, ss, token, m.scrub, m.logger)
		defer m.src.progress.close(sink)
		if down == nil {
			down = mcp.Meta{}
		}
		down["progressToken"] = sink.id
	}
	setMeta(down)
	return m.src.down.Call(ctx, fn)
}

// progressToken returns the upstream request's progress token, if it has a usable one.
func progressToken(meta mcp.Meta) any {
	switch t := meta["progressToken"].(type) {
	case string, float64, int, int64:
		return t
	default:
		return nil
	}
}

// downstreamMeta builds the _meta sent downstream from the upstream one: the keys in forward,
// and nothing else. The upstream _meta describes the client (its session, its traces, its
// protocol version and capabilities), and the servers are third parties, so only keys the
// config names are passed on. The progress token is replaced by the gate's.
func downstreamMeta(meta mcp.Meta, forward []string) mcp.Meta {
	var out mcp.Meta
	for _, k := range forward {
		v, ok := meta[k]
		// Config validation already refuses these; checked again so that no caller can pass the
		// client's own.
		if !ok || k == "progressToken" || config.ReservedMetaKey(k) {
			continue
		}
		if out == nil {
			out = mcp.Meta{}
		}
		out[k] = v
	}
	return out
}

// mirrored reports whether the mirrored catalog has the tool or prompt name, or serves the
// resource URI.
func (m *Mirror) mirrored(kind audit.Kind, name string) bool {
	switch kind {
	case audit.Tool:
		m.mu.Lock()
		defer m.mu.Unlock()
		_, ok := m.tools[name]
		return ok
	case audit.Prompt:
		m.mu.Lock()
		defer m.mu.Unlock()
		_, ok := m.prompts[name]
		return ok
	case audit.Resource:
		return m.serves(name)
	}
	return false
}

// serves reports whether the mirrored catalog lists the resource URI or has a template that
// matches it, as the SDK checks before a read on the server's route.
func (m *Mirror) serves(uri string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.served.uris[uri] || slices.ContainsFunc(m.served.templates, func(re *regexp.Regexp) bool { return re.MatchString(uri) })
}

// servesSpelling reports whether the mirror serves uri, or lists a resource whose URI has the
// same comparison key.
func (m *Mirror) servesSpelling(uri string) bool {
	if m.serves(uri) {
		return true
	}
	key := policy.NormalizeURI(uri)
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.served.keys[key]
}

// tokenAllows reports whether the policy of the token named principal on the server passes a
// tool, a prompt or a resource read; true for a token without one. It is the access check, and
// does not depend on what the mirror holds.
func (m *Mirror) tokenAllows(principal string, kind audit.Kind, name string) bool {
	v := m.views[principal]
	if v == nil || principal == "" {
		return true
	}
	switch kind {
	case audit.Tool:
		return v.policy.Tools.Allows(name)
	case audit.Prompt:
		return v.policy.Prompts.Allows(name)
	case audit.Resource:
		m.mu.Lock()
		reads := v.reads
		m.mu.Unlock()
		return reads.Allowed(name)
	}
	return false
}

// decision labels, for the audit line, what the policy of the token named principal decided
// about a tool, a prompt or a resource read. Only what the mirrored catalog holds is labelled: a
// name it does not have, or a URI it does not serve in any spelling, is NoPolicy, so that the
// line does not credit a policy with what the server's own filter or the server itself refused.
// Access is checked by tokenAllows, never by this label.
func (m *Mirror) decision(principal string, kind audit.Kind, name string) policy.Decision {
	if v := m.views[principal]; v == nil || principal == "" {
		return policy.NoPolicy
	}
	held := false
	switch kind {
	case audit.Tool, audit.Prompt:
		held = m.mirrored(kind, name)
	case audit.Resource:
		held = m.servesSpelling(name)
	}
	if !held {
		return policy.NoPolicy
	}
	return policy.DecisionOf(m.tokenAllows(principal, kind, name))
}

// principalOf returns the token name of a request, or "".
func principalOf(extra *mcp.RequestExtra) string {
	if extra == nil {
		return ""
	}
	return upstream.Principal(extra.TokenInfo)
}

// reachedKey marks, in a request's context, whether the request reached a mirror handler.
type reachedKey struct{}

// receive is the mirror server's receiving middleware. It answers a request whose handling
// panics with an internal error, logging only the panic's type, since the SDK handles requests
// on goroutines of its own that nothing else recovers. It also writes the audit line of a tool
// call or prompt get that the SDK refuses before a handler runs, such as one of a tool the
// policy hides, and of a resource read the SDK refuses because the caller's token policy hides
// what it names.
func (m *Mirror) receive(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (res mcp.Result, err error) {
		defer func() {
			if v := recover(); v != nil {
				m.logger.Error("request handler panicked", "method", method, "type", fmt.Sprintf("%T", v))
				res, err = nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "mcp-gate: internal error"}
			}
		}()
		var kind audit.Kind
		var name string
		switch r := req.(type) {
		case *mcp.CallToolRequest:
			if r.Params != nil {
				kind, name = audit.Tool, r.Params.Name
			}
		case *mcp.GetPromptRequest:
			if r.Params != nil {
				kind, name = audit.Prompt, r.Params.Name
			}
		case *mcp.ReadResourceRequest:
			if r.Params != nil {
				kind, name = audit.Resource, r.Params.URI
			}
		}
		if kind == 0 {
			return next(ctx, method, req)
		}
		reached := new(bool)
		res, err = next(context.WithValue(ctx, reachedKey{}, reached), method, req)
		// A read of a URI the server does not serve is not audited; one the token's policy hides
		// is.
		if err != nil && !*reached && (kind != audit.Resource || m.decision(principalOf(req.GetExtra()), kind, name) == policy.Denied) {
			m.refused(ctx, req.GetExtra(), kind, name, false)
		}
		return res, err
	}
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

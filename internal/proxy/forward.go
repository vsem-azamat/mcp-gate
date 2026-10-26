package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yosida95/uritemplate/v3"

	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/downstream"
	"github.com/vsem-azamat/mcp-gate/internal/policy"
	"github.com/vsem-azamat/mcp-gate/internal/redact"
	"github.com/vsem-azamat/mcp-gate/internal/upstream"
)

// Outcomes in the audit line.
const (
	outcomeOK          = "ok"
	outcomeToolError   = "tool_error"
	outcomeError       = "error"
	outcomeDenied      = "denied"
	outcomeUnavailable = "unavailable"
	outcomeWithheld    = "withheld"
	outcomeInput       = "input_required"
)

// The attribute of the audit line that names what a request is for, which also tells its kind.
const (
	keyTool   = "tool"
	keyPrompt = "prompt"
	keyURI    = "uri"
)

// errNeedsInput is returned for a result that asks the client for input, which mcp-gate does
// not forward.
var errNeedsInput = errors.New("this request needs interactive input from the client, which mcp-gate does not support")

// call is one forwarded request, for the audit line.
type call struct {
	m         *Mirror
	method    string
	principal string
	decision  policy.Decision // of the caller's token policy
	start     time.Time
	attrs     []any
	outcome   string
	count     *counter
	req       Request
}

func (m *Mirror) begin(ctx context.Context, method string, extra *mcp.RequestExtra, attrs ...any) *call {
	if reached, ok := ctx.Value(reachedKey{}).(*bool); ok {
		*reached = true
	}
	m.stats.calls.Add(1)
	principal := ""
	if extra != nil {
		principal = upstream.Principal(extra.TokenInfo)
	}
	return &call{
		m: m, method: method, principal: principal, decision: policy.NoPolicy, start: time.Now(), attrs: attrs,
		outcome: outcomeOK, count: &counter{},
	}
}

// end writes the audit line. Arguments and results are never logged.
func (c *call) end() {
	if c.outcome != outcomeOK && c.outcome != outcomeToolError {
		c.m.stats.failed.Add(1)
	}
	attrs := append([]any{
		"principal", c.principal, "method", c.method,
	}, c.attrs...)
	attrs = append(attrs, "durMs", time.Since(c.start).Milliseconds(), "outcome", c.outcome,
		"tokenPolicy", string(c.decision), "redactions", c.count.n.Load())
	c.m.logger.Info("call", attrs...)
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
	c.outcome = outcomeError
	switch {
	case ctx.Err() != nil && errors.Is(err, ctx.Err()):
		return ctx.Err() // the client has gone; the error may quote the server's URL
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("server %s did not answer in time", c.m.opts.Name)
	}
	var rpc *jsonrpc.Error
	if !errors.As(err, &rpc) || rpc == nil {
		return errors.New(c.m.down.ErrorText(err))
	}
	r := c.m.opts.Redaction
	if r == nil {
		return &jsonrpc.Error{Code: rpc.Code, Message: c.m.down.ErrorText(err)}
	}
	fresh := &jsonrpc.Error{Code: rpc.Code, Message: c.m.down.HideURL(err.Error())}
	if direct, ok := err.(*jsonrpc.Error); ok && direct == rpc { //nolint:errorlint // only an unwrapped error reply carries its data to the wire
		fresh.Data = json.RawMessage(c.m.down.HideURL(string(rpc.Data)))
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
	c.outcome = outcomeWithheld
	c.m.logger.Warn("result withheld: it could not be redacted", "method", c.method, "error", err.Error())
	return fmt.Errorf("server %s: %w", c.m.opts.Name, err)
}

func (m *Mirror) callTool(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name := req.Params.Name
	c := m.begin(ctx, "tools/call", req.Extra, keyTool, m.logText(name))
	defer c.end()
	c.req = Request{Method: "tools/call", Name: name, Arguments: toolArguments(req.Params.Arguments)}
	c.decision = m.opts.Tokens.For(c.principal).Tool(name)
	if !m.opts.Policy.Tools.Allows(name) || c.decision == policy.Denied {
		c.outcome = outcomeDenied
		return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: fmt.Sprintf("unknown tool %q", name)}
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
		c.outcome = outcomeUnavailable
		return toolError(fmt.Sprintf("server %s is not available (%s); try again later", m.opts.Name, nr.State)), nil
	case err != nil:
		return nil, c.downstreamError(ctx, err)
	case res == nil:
		c.outcome = outcomeError
		return nil, fmt.Errorf("server %s returned no result", m.opts.Name)
	case len(res.InputRequests) > 0 || res.RequestState != "":
		c.outcome = outcomeInput
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
		c.outcome = outcomeToolError
	}
	return res, nil
}

func (m *Mirror) getPrompt(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	name := req.Params.Name
	c := m.begin(ctx, "prompts/get", req.Extra, keyPrompt, m.logText(name))
	defer c.end()
	c.req = Request{Method: "prompts/get", Name: name, Arguments: promptArguments(req.Params.Arguments)}
	c.decision = m.opts.Tokens.For(c.principal).Prompt(name)
	if !m.opts.Policy.Prompts.Allows(name) || c.decision == policy.Denied {
		c.outcome = outcomeDenied
		return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: fmt.Sprintf("unknown prompt %q", name)}
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
	c := m.begin(ctx, "resources/read", req.Extra, keyURI, m.logText(uri))
	defer c.end()
	c.req = Request{Method: "resources/read", Name: uri}
	c.decision = m.readDecision(m.opts.Tokens.For(c.principal), uri)
	if !m.opts.Policy.ReadAllowed(uri) || c.decision == policy.Denied {
		c.outcome = outcomeDenied
		return nil, mcp.ResourceNotFoundError(uri)
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
		c.outcome = outcomeUnavailable
		return fmt.Errorf("server %s is not available (%s); try again later", c.m.opts.Name, nr.State)
	case err != nil:
		return c.downstreamError(ctx, err)
	case empty:
		c.outcome = outcomeError
		return fmt.Errorf("server %s returned no result", c.m.opts.Name)
	case needsInput:
		c.outcome = outcomeInput
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
	return m.down.ErrorText(errors.New(s))
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
		sink := m.progress.open(ctx, ss, token, m.logger)
		defer m.progress.close(sink)
		if down == nil {
			down = mcp.Meta{}
		}
		down["progressToken"] = sink.id
	}
	setMeta(down)
	return m.down.Call(ctx, fn)
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

// mirrored reports whether the tool or prompt name is in the mirrored catalog.
func (m *Mirror) mirrored(key, name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if key == keyTool {
		_, ok := m.tools[name]
		return ok
	}
	_, ok := m.prompts[name]
	return ok
}

// serves reports whether the mirrored catalog lists the resource URI or has a template that
// matches it, as the SDK checks before a read on the server's route.
func (m *Mirror) serves(uri string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.resources[uri]; ok {
		return true
	}
	for ut := range m.templates {
		if t, err := uritemplate.New(ut); err == nil && t.Regexp().MatchString(uri) {
			return true
		}
	}
	return false
}

// readDecision returns what a token policy decides about a read of uri, given the mirrored
// resources and the mirrored templates that match it.
func (m *Mirror) readDecision(p *policy.Token, uri string) policy.Decision {
	if p == nil {
		return policy.NoPolicy
	}
	m.mu.Lock()
	resources := make([]policy.Entry, 0, len(m.resources))
	for _, r := range m.resources {
		resources = append(resources, policy.Entry{Key: r.URI, Name: r.Name})
	}
	var matching []policy.Entry
	for ut, t := range m.templates {
		if tmpl, err := uritemplate.New(ut); err == nil && tmpl.Regexp().MatchString(uri) {
			matching = append(matching, policy.Entry{Key: ut, Name: t.Name})
		}
	}
	m.mu.Unlock()
	return p.Read(uri, resources, matching)
}

// decision returns what a token policy decides about a tool, a prompt or a resource read (key
// keyTool, keyPrompt or keyURI).
func (m *Mirror) decision(p *policy.Token, key, name string) policy.Decision {
	switch key {
	case keyTool:
		return p.Tool(name)
	case keyPrompt:
		return p.Prompt(name)
	default:
		return m.readDecision(p, name)
	}
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
	for u := range m.resources {
		if policy.NormalizeURI(u) == key {
			return true
		}
	}
	return false
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
		var key, name string
		switch r := req.(type) {
		case *mcp.CallToolRequest:
			if r.Params != nil {
				key, name = keyTool, r.Params.Name
			}
		case *mcp.GetPromptRequest:
			if r.Params != nil {
				key, name = keyPrompt, r.Params.Name
			}
		case *mcp.ReadResourceRequest:
			if r.Params != nil {
				key, name = keyURI, r.Params.URI
			}
		}
		if key == "" {
			return next(ctx, method, req)
		}
		reached := new(bool)
		res, err = next(context.WithValue(ctx, reachedKey{}, reached), method, req)
		// A read of a URI the server does not serve is not audited; one the token's policy hides
		// is.
		if err != nil && !*reached && (key != keyURI || m.servesSpelling(name) && m.decision(m.tokenPolicy(req.GetExtra()), key, name) == policy.Denied) {
			m.refused(ctx, method, req.GetExtra(), key, name, false)
		}
		return res, err
	}
}

// refused writes the audit line of a tool call, prompt get or resource read (key keyTool,
// keyPrompt or keyURI) that did not reach a handler: denied when the name is not in the mirrored
// catalog, hidden is set or the caller's token policy hides it, an error otherwise.
func (m *Mirror) refused(ctx context.Context, method string, extra *mcp.RequestExtra, key, name string, hidden bool) {
	c := m.begin(ctx, method, extra, key, m.logText(name))
	c.decision = m.decision(m.tokenPolicy(extra), key, name)
	c.outcome = outcomeError
	if hidden || c.decision == policy.Denied || !m.mirrored(key, name) {
		c.outcome = outcomeDenied
	}
	c.end()
}

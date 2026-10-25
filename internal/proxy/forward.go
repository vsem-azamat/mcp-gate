package proxy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/downstream"
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

// errNeedsInput is returned for a result that asks the client for input, which mcp-gate does
// not forward.
var errNeedsInput = errors.New("this request needs interactive input from the client, which mcp-gate does not support")

// call is one forwarded request, for the audit line.
type call struct {
	m         *Mirror
	method    string
	principal string
	start     time.Time
	attrs     []any
	outcome   string
	count     *counter
}

func (m *Mirror) begin(method string, extra *mcp.RequestExtra, attrs ...any) *call {
	m.stats.calls.Add(1)
	principal := ""
	if extra != nil {
		principal = upstream.Principal(extra.TokenInfo)
	}
	return &call{m: m, method: method, principal: principal, start: time.Now(), attrs: attrs, outcome: outcomeOK, count: &counter{}}
}

// end writes the audit line. Arguments and results are never logged.
func (c *call) end() {
	if c.outcome != outcomeOK && c.outcome != outcomeToolError {
		c.m.stats.failed.Add(1)
	}
	attrs := append([]any{
		"principal", c.principal, "method", c.method,
	}, c.attrs...)
	attrs = append(attrs, "durMs", time.Since(c.start).Milliseconds(), "outcome", c.outcome, "redactions", c.count.n.Load())
	c.m.logger.Info("call", attrs...)
}

// toolError is a tool result that reports an error to the model.
func toolError(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

// downstreamError turns a failed call into what the client gets, and sets the outcome. A
// JSON-RPC error reply keeps its code and is redacted; any other error is described by the
// supervisor, which hides the server's URL.
func (c *call) downstreamError(ctx context.Context, err error) error {
	c.outcome = outcomeError
	switch {
	case ctx.Err() != nil && errors.Is(err, ctx.Err()):
		return err
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("server %s did not answer in time", c.m.opts.Name)
	}
	var rpc *jsonrpc.Error
	if errors.As(err, &rpc) {
		if r := c.m.opts.Redaction; r != nil {
			return r.results.Error(err, c.replacer())
		}
		return err
	}
	return errors.New(c.m.down.ErrorText(err))
}

func (c *call) replacer() *countingReplacer {
	return &countingReplacer{next: c.m.opts.Redaction.replacer, n: c.count}
}

// withheld reports a result that could not be redacted.
func (c *call) withheld(err error) error {
	c.outcome = outcomeWithheld
	c.m.logger.Warn("result withheld: it could not be redacted", "method", c.method, "error", err.Error())
	return fmt.Errorf("server %s: %w", c.m.opts.Name, err)
}

func (m *Mirror) callTool(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name := req.Params.Name
	c := m.begin("tools/call", req.Extra, "tool", name)
	defer c.end()
	if !m.opts.Policy.Tools.Allows(name) {
		c.outcome = outcomeDenied
		return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: fmt.Sprintf("unknown tool %q", name)}
	}
	params := &mcp.CallToolParams{Name: name}
	if len(req.Params.Arguments) > 0 {
		params.Arguments = req.Params.Arguments
	}
	var res *mcp.CallToolResult
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
	}
	if res.IsError {
		c.outcome = outcomeToolError
	}
	return res, nil
}

func (m *Mirror) getPrompt(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	name := req.Params.Name
	c := m.begin("prompts/get", req.Extra, "prompt", name)
	defer c.end()
	if !m.opts.Policy.Prompts.Allows(name) {
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
	c := m.begin("resources/read", req.Extra, "uri", m.logText(uri))
	defer c.end()
	if !m.opts.Policy.ReadAllowed(uri) {
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
		return r.engine.RedactText(s, r.replacer)
	}
	return m.down.ErrorText(errors.New(s))
}

// logText makes a value from a request fit for the log: scrubbed and cut at 256 bytes.
func (m *Mirror) logText(s string) string {
	s = m.scrub(s)
	if len(s) > 256 {
		s = s[:256] + "…"
	}
	return s
}

// forward runs fn on the downstream session with the downstream _meta, built by setMeta from the
// upstream one, and remaps progress while it runs. ctx is the upstream request's: its
// cancellation cancels the downstream call, and progress is sent on its stream.
func (m *Mirror) forward(ctx context.Context, ss *mcp.ServerSession, meta mcp.Meta, setMeta func(mcp.Meta),
	fn func(context.Context, *mcp.ClientSession) error,
) error {
	down := downstreamMeta(meta)
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

// downstreamMeta builds the _meta sent downstream from the upstream one: every key outside the
// namespaces the MCP specification reserves, and nothing else. Reserved keys describe the
// upstream client (its protocol version, capabilities, client info); passed on, the SDK would
// keep them instead of its own and send them as headers. The progress token is replaced by the
// gate's.
func downstreamMeta(meta mcp.Meta) mcp.Meta {
	var out mcp.Meta
	for k, v := range meta {
		if k == "progressToken" || reservedMetaKey(k) {
			continue
		}
		if out == nil {
			out = mcp.Meta{}
		}
		out[k] = v
	}
	return out
}

// reservedMetaKey reports whether a _meta key has a prefix the MCP specification reserves: one
// whose labels include "modelcontextprotocol" or "mcp", such as "io.modelcontextprotocol/".
func reservedMetaKey(k string) bool {
	prefix, _, ok := strings.Cut(k, "/")
	if !ok {
		return false
	}
	for _, label := range strings.Split(prefix, ".") {
		if label == "modelcontextprotocol" || label == "mcp" {
			return true
		}
	}
	return false
}

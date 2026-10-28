package proxy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/audit"
	"github.com/vsem-azamat/mcp-gate/internal/downstream"
	"github.com/vsem-azamat/mcp-gate/internal/redact/mcpredact"
)

// The request pipeline. Every tool call, prompt get and resource read that reaches a mirror's
// handler runs through the same stages, in this order:
//
//   - begin: the audit record starts and the call is counted (Mirror.begin), and the token
//     policy's decision is labelled (Mirror.start);
//   - before forward: the kind's before stages, each of which may refuse the request or change
//     what is sent: today the server's filter, then the caller's token policy, each of which
//     refuses an entry it hides with the error of an unknown one;
//   - forward: the request goes to the server through the supervisor, with the downstream
//     _meta and progress (Mirror.forward);
//   - outcome: the server's answer becomes a result or an error fit for the client, and what
//     mcp-gate does not forward fails (pipeline.outcome);
//   - after forward: the kind's after stages, each of which may change the result or withhold
//     it: today redaction, then, for a tool call, the scan of the files it wrote and the
//     tool-error outcome;
//   - end: the audit record goes to the mirror's sink (call.end).
//
// A refusal or a failure at any stage ends the request there, with an outcome that says why.

// exchange is one request on its way through the pipeline: its audit record, and what the
// stages need to know of it.
type exchange struct {
	*call
	// shown is the name the caller used, which the errors of a hidden entry give.
	shown string
	// session and meta are the upstream request's: progress goes to the session, and the
	// downstream _meta is built from meta.
	session *mcp.ServerSession
	meta    mcp.Meta
	// forwarded is when the request was sent downstream, zero before.
	forwarded time.Time
}

// result is the result of a tool call, prompt get or resource read.
type result interface {
	*mcp.CallToolResult | *mcp.GetPromptResult | *mcp.ReadResourceResult
}

// beforeStage checks or changes a request before it is forwarded. An error refuses the request,
// with the outcome the stage set.
type beforeStage[P any] func(ctx context.Context, x *exchange, p P) error

// afterStage checks or changes a result. An error withholds the result, with the outcome the
// stage set.
type afterStage[R result] func(ctx context.Context, x *exchange, res R) (R, error)

// pipeline is what differs between the kinds of request: the request P sent downstream, the
// result R, and the stages around the forward.
type pipeline[P any, R result] struct {
	before []beforeStage[P]
	// send forwards the request; setMeta sets its downstream _meta first.
	send    func(ctx context.Context, d Downstream, p P) (R, error)
	setMeta func(p P, meta mcp.Meta)
	// needsInput reports a result that asks the client for input.
	needsInput func(R) bool
	// soft, when set, answers what the server could not do with a result that reports it, as a
	// tool call does, instead of an error.
	soft  func(text string) R
	after []afterStage[R]
}

// run takes x and the request p through the pipeline.
func (pl *pipeline[P, R]) run(ctx context.Context, x *exchange, p P) (R, error) {
	defer x.end()
	var none R
	for _, stage := range pl.before {
		if err := stage(ctx, x, p); err != nil {
			return none, err
		}
	}
	res, err := pl.forward(ctx, x, p)
	res, done, err := pl.outcome(ctx, x, res, err)
	if done {
		return res, err
	}
	for _, stage := range pl.after {
		if res, err = stage(ctx, x, res); err != nil {
			return none, err
		}
	}
	return res, nil
}

// forward is the forward stage: it sends p downstream with the downstream _meta, and with the
// progress of the call routed to the upstream request while it runs. ctx is the upstream
// request's: its cancellation cancels the downstream call, and progress is sent on its stream.
func (pl *pipeline[P, R]) forward(ctx context.Context, x *exchange, p P) (R, error) {
	m := x.m
	down := downstreamMeta(x.meta, m.opts.ForwardMeta)
	if token := progressToken(x.meta); token != nil && x.session != nil {
		sink := m.src.progress.open(ctx, x.session, token, m.scrub, m.logger)
		defer m.src.progress.close(sink)
		if down == nil {
			down = mcp.Meta{}
		}
		down["progressToken"] = sink.id
	}
	pl.setMeta(p, down)
	x.forwarded = time.Now()
	return pl.send(ctx, m.src.down, p)
}

// outcome maps what the server answered to what the client gets, and sets the outcome: a server
// without a session is unavailable, an error is rebuilt (see call.downstreamError), and no
// result or one that asks for input fails. With soft set, being unavailable and asking for input
// are answered with a result that reports them. done reports an answer that ends the request:
// anything but the server's result.
func (pl *pipeline[P, R]) outcome(ctx context.Context, x *exchange, res R, err error) (_ R, done bool, _ error) {
	var none R
	var nr *downstream.NotReadyError
	switch {
	case errors.As(err, &nr):
		x.outcome = audit.Unavailable
		res, err = pl.fail(fmt.Errorf("server %s is not available (%s); try again later", x.m.opts.Name, nr.State))
		return res, true, err
	case err != nil:
		return none, true, x.downstreamError(ctx, err)
	case res == none:
		x.outcome = audit.Error
		return none, true, fmt.Errorf("server %s returned no result", x.m.opts.Name)
	case pl.needsInput(res):
		x.outcome = audit.InputRequired
		res, err = pl.fail(errNeedsInput)
		return res, true, err
	}
	return res, false, nil
}

// fail answers a failure with a soft result when the kind has one, else with err.
func (pl *pipeline[P, R]) fail(err error) (R, error) {
	if pl.soft != nil {
		return pl.soft(err.Error()), nil
	}
	var none R
	return none, err
}

// The before stages.

// serverFilter refuses an entry that the server's filter hides.
func serverFilter[P any](_ context.Context, x *exchange, _ P) error {
	if !x.m.serverAllows(x.kind, x.entry) {
		x.outcome = audit.Denied
		return errUnknown(x.kind, x.shown)
	}
	return nil
}

// tokenPolicy refuses an entry that the caller's token policy hides.
func tokenPolicy[P any](_ context.Context, x *exchange, _ P) error {
	if !x.m.tokenAllows(x.principal, x.kind, x.entry) {
		x.outcome = audit.Denied
		return errUnknown(x.kind, x.shown)
	}
	return nil
}

// The after stages.

// redactWith returns the stage that redacts a result with the server's redaction, if it has
// one, through fn; a result that cannot be redacted is withheld.
func redactWith[R result](fn func(*mcpredact.Redactor, R, *countingReplacer) (R, error)) afterStage[R] {
	return func(_ context.Context, x *exchange, res R) (R, error) {
		r := x.m.opts.Redaction
		if r == nil {
			return res, nil
		}
		out, err := fn(r.results, res, x.replacer())
		if err != nil {
			return out, x.withheld(err)
		}
		return out, nil
	}
}

// scanFiles withholds the files a tool call wrote that hold secrets, with the server's file
// scanner, on a redacted result; a file that cannot be scanned withholds the result.
func scanFiles(ctx context.Context, x *exchange, res *mcp.CallToolResult) (*mcp.CallToolResult, error) {
	f := x.m.opts.Files
	if f == nil || x.m.opts.Redaction == nil {
		return res, nil
	}
	out, n, err := f.Scan(ctx, x.entry, x.req.Arguments, res, x.forwarded)
	if err != nil {
		return nil, x.withheld(err)
	}
	x.count.n.Add(int64(n))
	return out, nil
}

// toolErrorOutcome records a tool result that reports an error to the model.
func toolErrorOutcome(_ context.Context, x *exchange, res *mcp.CallToolResult) (*mcp.CallToolResult, error) {
	if res.IsError {
		x.outcome = audit.ToolError
	}
	return res, nil
}

// The pipelines of the three kinds.

var toolPipeline = &pipeline[*mcp.CallToolParams, *mcp.CallToolResult]{
	before: []beforeStage[*mcp.CallToolParams]{serverFilter[*mcp.CallToolParams], tokenPolicy[*mcp.CallToolParams]},
	send: func(ctx context.Context, d Downstream, p *mcp.CallToolParams) (*mcp.CallToolResult, error) {
		return d.CallTool(ctx, p)
	},
	setMeta:    func(p *mcp.CallToolParams, meta mcp.Meta) { p.Meta = meta },
	needsInput: func(r *mcp.CallToolResult) bool { return len(r.InputRequests) > 0 || r.RequestState != "" },
	soft:       toolError,
	after: []afterStage[*mcp.CallToolResult]{
		redactWith(func(r *mcpredact.Redactor, res *mcp.CallToolResult, rep *countingReplacer) (*mcp.CallToolResult, error) {
			return r.CallToolResult(res, rep)
		}),
		scanFiles,
		toolErrorOutcome,
	},
}

var promptPipeline = &pipeline[*mcp.GetPromptParams, *mcp.GetPromptResult]{
	before: []beforeStage[*mcp.GetPromptParams]{serverFilter[*mcp.GetPromptParams], tokenPolicy[*mcp.GetPromptParams]},
	send: func(ctx context.Context, d Downstream, p *mcp.GetPromptParams) (*mcp.GetPromptResult, error) {
		return d.GetPrompt(ctx, p)
	},
	setMeta:    func(p *mcp.GetPromptParams, meta mcp.Meta) { p.Meta = meta },
	needsInput: func(r *mcp.GetPromptResult) bool { return len(r.InputRequests) > 0 || r.RequestState != "" },
	after: []afterStage[*mcp.GetPromptResult]{
		redactWith(func(r *mcpredact.Redactor, res *mcp.GetPromptResult, rep *countingReplacer) (*mcp.GetPromptResult, error) {
			return r.GetPromptResult(res, rep)
		}),
	},
}

var resourcePipeline = &pipeline[*mcp.ReadResourceParams, *mcp.ReadResourceResult]{
	before: []beforeStage[*mcp.ReadResourceParams]{serverFilter[*mcp.ReadResourceParams], tokenPolicy[*mcp.ReadResourceParams]},
	send: func(ctx context.Context, d Downstream, p *mcp.ReadResourceParams) (*mcp.ReadResourceResult, error) {
		return d.ReadResource(ctx, p)
	},
	setMeta:    func(p *mcp.ReadResourceParams, meta mcp.Meta) { p.Meta = meta },
	needsInput: func(r *mcp.ReadResourceResult) bool { return len(r.InputRequests) > 0 || r.RequestState != "" },
	after: []afterStage[*mcp.ReadResourceResult]{
		redactWith(func(r *mcpredact.Redactor, res *mcp.ReadResourceResult, rep *countingReplacer) (*mcp.ReadResourceResult, error) {
			return r.ReadResourceResult(res, rep)
		}),
	},
}

// The handlers.

// start begins the exchange of a request for the entry of the given kind that the server calls
// entry and the caller shown.
func (m *Mirror) start(ctx context.Context, kind audit.Kind, extra *mcp.RequestExtra, entry, shown string, ss *mcp.ServerSession, meta mcp.Meta) *exchange {
	c := m.begin(ctx, kind, extra, entry)
	c.decision = m.decision(c.principal, kind, entry)
	return &exchange{call: c, shown: shown, session: ss, meta: meta}
}

func (m *Mirror) callTool(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return m.callToolAs(ctx, req, req.Params.Name)
}

// callToolAs calls a tool that the caller named shown, the name its errors give.
func (m *Mirror) callToolAs(ctx context.Context, req *mcp.CallToolRequest, shown string) (*mcp.CallToolResult, error) {
	name := req.Params.Name
	x := m.start(ctx, audit.Tool, req.Extra, name, shown, req.Session, req.Params.Meta)
	x.req = Request{Method: audit.Tool.Method(), Name: name, Arguments: toolArguments(req.Params.Arguments)}
	params := &mcp.CallToolParams{Name: name}
	if len(req.Params.Arguments) > 0 {
		params.Arguments = req.Params.Arguments
	}
	return toolPipeline.run(ctx, x, params)
}

func (m *Mirror) getPrompt(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	return m.getPromptAs(ctx, req, req.Params.Name)
}

// getPromptAs gets a prompt that the caller named shown, the name its errors give.
func (m *Mirror) getPromptAs(ctx context.Context, req *mcp.GetPromptRequest, shown string) (*mcp.GetPromptResult, error) {
	name := req.Params.Name
	x := m.start(ctx, audit.Prompt, req.Extra, name, shown, req.Session, req.Params.Meta)
	x.req = Request{Method: audit.Prompt.Method(), Name: name, Arguments: promptArguments(req.Params.Arguments)}
	return promptPipeline.run(ctx, x, &mcp.GetPromptParams{Name: name, Arguments: req.Params.Arguments})
}

func (m *Mirror) readResource(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	uri := req.Params.URI
	x := m.start(ctx, audit.Resource, req.Extra, uri, uri, req.Session, req.Params.Meta)
	x.req = Request{Method: audit.Resource.Method(), Name: uri}
	return resourcePipeline.run(ctx, x, &mcp.ReadResourceParams{URI: uri})
}

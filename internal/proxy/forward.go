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
	// entry is the server's own name for the entry: the tool or prompt name, the resource URI.
	entry   string
	name    string // fit for the log
	outcome audit.Outcome
	count   *counter
	req     Request
	// rep replaces the findings of the call's result; set on first use, so that what it kept
	// can be discarded when the result is withheld.
	rep redact.Replacer
}

// begin starts the audit record of a request for the entry of the given kind and name (a tool or
// prompt name, a resource URI), and counts the call.
func (m *Mirror) begin(ctx context.Context, kind audit.Kind, extra *mcp.RequestExtra, name string) *call {
	if reached, ok := ctx.Value(reachedKey{}).(*bool); ok {
		*reached = true
	}
	m.src.stats.calls.Add(1)
	return &call{
		m: m, kind: kind, principal: principalOf(extra), decision: policy.NoPolicy, start: time.Now(), entry: name, name: m.logText(name),
		outcome: audit.OK, count: &counter{},
	}
}

// end hands the call's audit record to the mirror's sink. Arguments and results are never in it.
func (c *call) end() {
	c.m.emit(audit.Record{
		Server: c.m.opts.Name, Principal: c.principal, Kind: c.kind, Name: c.name, Duration: time.Since(c.start),
		Outcome: c.outcome, TokenPolicy: c.decision, Redactions: c.count.n.Load(),
		// A name the caller's token policy hides is not listed for it: the metrics must not
		// tell a hidden entry from a missing one.
		Listed: c.kind != audit.Resource && c.decision != policy.Denied && c.m.mirrored(c.kind, c.entry),
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

// replacer returns the call's replacer, counting the findings it replaces.
func (c *call) replacer() *countingReplacer {
	return &countingReplacer{next: c.resultReplacer(), n: c.count}
}

// resultReplacer returns the call's replacer, which does not count.
func (c *call) resultReplacer() redact.Replacer {
	if c.rep == nil {
		c.rep = c.m.opts.Redaction.replacer(c.req)
	}
	return c.rep
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
// What the call's replacer kept is discarded: its markers never reach the client.
func (c *call) withheld(err error) error {
	c.outcome = audit.Withheld
	if d, ok := c.rep.(Discarder); ok {
		d.Discard()
	}
	c.m.logger.Warn("result withheld: it could not be redacted", "method", c.kind.Method(), "error", err.Error())
	return fmt.Errorf("server %s: %w", c.m.opts.Name, err)
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

// serverAllows reports whether the server's filter passes a tool or prompt name, or a read of a
// resource URI.
func (m *Mirror) serverAllows(kind audit.Kind, name string) bool {
	switch kind {
	case audit.Tool:
		return m.opts.Policy.Tools.Allows(name)
	case audit.Prompt:
		return m.opts.Policy.Prompts.Allows(name)
	case audit.Resource:
		return m.opts.Policy.ReadAllowed(name)
	}
	return false
}

// isHeld reports whether the tool pins hold the tool.
func (m *Mirror) isHeld(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.held[name]
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

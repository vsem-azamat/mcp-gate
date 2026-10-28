// Package audit is the record of every tool call, prompt get and resource read that reaches the
// gate, and the sink that writes it. A record is made once per request, when it ends; it names
// what was asked for and what came of it, never the arguments or the result.
package audit

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/vsem-azamat/mcp-gate/internal/policy"
)

// Kind is a kind of catalog entry, and of the request that names one. The kinds are bits, so
// that a set of them fits in one value (see proxy's kindSet).
type Kind uint8

// The kinds. Resource covers resource templates too: a read names a URI either way.
const (
	Tool Kind = 1 << iota
	Prompt
	Resource
)

// String names the kind in log lines: tool, prompt or resource.
func (k Kind) String() string {
	switch k {
	case Tool:
		return "tool"
	case Prompt:
		return "prompt"
	case Resource:
		return "resource"
	default:
		return fmt.Sprintf("Kind(%d)", uint8(k))
	}
}

// Method is the MCP method of a request for an entry of the kind.
func (k Kind) Method() string {
	switch k {
	case Tool:
		return "tools/call"
	case Prompt:
		return "prompts/get"
	case Resource:
		return "resources/read"
	default:
		return ""
	}
}

// Key is the attribute that names the entry in an audit line: tool, prompt or uri.
func (k Kind) Key() string {
	switch k {
	case Tool:
		return "tool"
	case Prompt:
		return "prompt"
	case Resource:
		return "uri"
	default:
		return k.String()
	}
}

// Outcome is how a request ended.
type Outcome string

// The outcomes.
const (
	// OK is a result passed to the client.
	OK Outcome = "ok"
	// ToolError is a tool result that reports an error to the model.
	ToolError Outcome = "tool_error"
	// Error is a request that failed: the server returned an error or nothing, or the gate
	// refused it for a reason other than access.
	Error Outcome = "error"
	// Denied is a request for an entry the caller may not see, or that does not exist.
	Denied Outcome = "denied"
	// Unavailable is a request to a server without a session.
	Unavailable Outcome = "unavailable"
	// Withheld is a result that could not be redacted, or whose files could not be scanned.
	Withheld Outcome = "withheld"
	// InputRequired is a result that asks the client for input, which the gate does not forward.
	InputRequired Outcome = "input_required"
	// Limited is a request that a rate or concurrency limit refused before it was forwarded.
	Limited Outcome = "limited"
)

// Failed reports whether the outcome counts as a failed call: every one but ok and tool_error.
func (o Outcome) Failed() bool { return o != OK && o != ToolError }

// Record is the audit record of one request.
type Record struct {
	// Server is the server the request went to; "" for one the aggregate refused before any
	// server saw it.
	Server string
	// Principal is the name of the token the request was authorized with, "" without one; on
	// the aggregate route without a server, the token names, joined.
	Principal string
	Kind      Kind
	// Name is the tool or prompt name, or the resource URI, made fit for the log: redacted and
	// cut.
	Name     string
	Duration time.Duration
	Outcome  Outcome
	// TokenPolicy is what the caller's token policy decided about the entry.
	TokenPolicy policy.Decision
	// Redactions counts the findings replaced in the result, and the files withheld.
	Redactions int64
	// Listed reports a tool or prompt that was in the server's mirrored catalog when the request
	// ended and that the caller's token policy does not hide; false for a resource read and for a
	// request no server saw.
	Listed bool
}

// Sink receives the audit records. Write is called once per request, on the request's
// goroutine, and must not block.
type Sink interface {
	Write(Record)
}

// Tee returns the sink that hands each record to every one of sinks, in order.
func Tee(sinks ...Sink) Sink { return tee(sinks) }

type tee []Sink

func (t tee) Write(r Record) {
	for _, s := range t {
		s.Write(r)
	}
}

// Log returns the sink that writes each record as one "call" line to logger, at info level:
// server, principal, method, the entry under its Kind.Key, durMs, outcome, tokenPolicy and
// redactions, in that order.
func Log(logger *slog.Logger) Sink { return logSink{logger} }

type logSink struct{ logger *slog.Logger }

func (s logSink) Write(r Record) {
	s.logger.LogAttrs(context.Background(), slog.LevelInfo, "call",
		slog.String("server", r.Server),
		slog.String("principal", r.Principal),
		slog.String("method", r.Kind.Method()),
		slog.String(r.Kind.Key(), r.Name),
		slog.Int64("durMs", r.Duration.Milliseconds()),
		slog.String("outcome", string(r.Outcome)),
		slog.String("tokenPolicy", string(r.TokenPolicy)),
		slog.Int64("redactions", r.Redactions),
	)
}

// PinRecord is the audit record of a tool a server lists with a definition other than the one
// pinned for it (see the tool-pins spec).
type PinRecord struct {
	Server string
	// Tool is the tool's name, made fit for the log: redacted and cut.
	Tool string
	// Change is "changed" for a tool whose definition differs from its accepted one, "added" for
	// one without an accepted definition.
	Change string
	// Pinned is the hash of the accepted definition, "" for an added tool; Listed is the hash of
	// the definition the server lists.
	Pinned, Listed string
	// Held reports that the tool is left out of the catalog until it is accepted.
	Held bool
}

// The actions of a PinRecord, as its line names them.
const (
	PinServed = "served"
	PinHeld   = "held"
)

// LogToolPin writes a PinRecord as one "toolPin" line to logger, at warn level: server, tool,
// change, pinned, listed and action (PinServed or PinHeld), in that order.
func LogToolPin(logger *slog.Logger, r PinRecord) {
	action := PinServed
	if r.Held {
		action = PinHeld
	}
	logger.Warn("toolPin",
		slog.String("server", r.Server),
		slog.String("tool", r.Tool),
		slog.String("change", r.Change),
		slog.String("pinned", r.Pinned),
		slog.String("listed", r.Listed),
		slog.String("action", action),
	)
}

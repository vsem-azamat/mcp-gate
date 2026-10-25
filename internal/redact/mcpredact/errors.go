package mcpredact

import (
	"bytes"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/vsem-azamat/mcp-gate/internal/redact"
)

// Error returns err with every secret in its message, and in the message and data of a
// JSON-RPC error in it, replaced. Only the data of an unwrapped JSON-RPC error reaches the wire. An error without findings is returned as it is. A JSON-RPC error keeps its code. A
// redacted error matches errors.Is targets as err does, and errors.As finds a *jsonrpc.Error
// with the redacted message and data, but it does not unwrap to err. When the error cannot be
// redacted, the result is an ErrWithheld error that says nothing of err.
func (r *Redactor) Error(err error, replacer redact.Replacer) error {
	if err == nil {
		return nil
	}
	var out error
	if failure := r.run(replacer, func(p *pass) { out = p.error(err) }); failure != nil {
		return failure
	}
	return out
}

func (p *pass) error(err error) error {
	msg := err.Error()
	if !p.checkSize(len(msg), "error message") {
		return nil
	}
	redactedMsg := p.engine.RedactText(msg, p.replacer)

	var wire *jsonrpc.Error
	if !errors.As(err, &wire) || wire == nil {
		if redactedMsg == msg {
			return err
		}
		return &redactedError{msg: redactedMsg, cause: err}
	}
	data := wire.Data
	if len(data) > 0 {
		var failure error
		if !p.checkSize(len(data), "error data") {
			return nil
		}
		if data, failure = p.engine.RedactJSON(data, p.replacer); failure != nil {
			// Data that is not JSON cannot be redacted by value; it is dropped.
			data = nil
		}
	}
	wireMsg := redactedMsg
	if wire.Message != msg {
		if !p.checkSize(len(wire.Message), "error message") {
			return nil
		}
		wireMsg = p.engine.RedactText(wire.Message, p.replacer)
	}
	if redactedMsg == msg && wireMsg == wire.Message && bytes.Equal(data, wire.Data) {
		return err
	}
	sanitized := &jsonrpc.Error{Code: wire.Code, Message: wireMsg, Data: data}
	if direct, ok := err.(*jsonrpc.Error); ok && direct == wire { //nolint:errorlint // only an unwrapped *jsonrpc.Error is replaced by a copy of its own type
		return sanitized
	}
	return &redactedError{msg: redactedMsg, cause: err, wire: sanitized}
}

// redactedError is an error whose message was redacted.
type redactedError struct {
	msg   string
	cause error
	// wire is the redacted JSON-RPC error inside cause, if any.
	wire *jsonrpc.Error
}

func (e *redactedError) Error() string { return e.msg }

// Is reports whether the original error matches target, so that cancellation and timeouts are
// still recognised.
func (e *redactedError) Is(target error) bool { return errors.Is(e.cause, target) }

// As finds the redacted JSON-RPC error, so that its code is kept on the wire.
func (e *redactedError) As(target any) bool {
	t, ok := target.(**jsonrpc.Error)
	if !ok || e.wire == nil {
		return false
	}
	*t = e.wire
	return true
}

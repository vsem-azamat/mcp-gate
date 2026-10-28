package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/audit"
	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/escrow"
	"github.com/vsem-azamat/mcp-gate/internal/redact"
	"github.com/vsem-azamat/mcp-gate/internal/redact/mcpredact"
)

// The stages of the request pipeline that look at what a request sends: the argument scan,
// which finds secrets a client wrote out, and substitution, which puts the values of escrow
// handles into a tool call's arguments where the server's rules allow them. The scan runs first,
// on the arguments as the client sent them, so a handle that substitution replaces is never a
// finding (markers are placeholders to the engine) while a secret written out is.

// refusal is the error of a request a before stage refused for what it sends. A tool call
// answers it with a tool error, so that the model reads why.
type refusal struct{ msg string }

func (r *refusal) Error() string { return r.msg }

// refuse sets the outcome of a refused request and returns its refusal.
func (x *exchange) refuse(format string, args ...any) error {
	x.outcome = audit.Refused
	return &refusal{msg: fmt.Sprintf("server %s: ", x.m.opts.Name) + fmt.Sprintf(format, args...)}
}

// scanArguments returns the before stage that scans what input returns of a request with the
// server's redaction engine: a JSON document when isJSON, else a text. The kinds found go in the
// audit record; with the scan in block mode they refuse the request.
func scanArguments[P any](input func(P) (text []byte, isJSON bool)) beforeStage[P] {
	return func(_ context.Context, x *exchange, p P) error {
		r, mode := x.m.opts.Redaction, x.m.opts.Arguments
		if r == nil || (mode != config.ArgumentsLog && mode != config.ArgumentsBlock) {
			return nil
		}
		data, isJSON := input(p)
		if len(data) == 0 {
			return nil
		}
		kinds := map[string]bool{}
		record := redact.ReplacerFunc(func(f redact.Finding) string {
			kinds[f.Kind] = true
			return redact.MarkerText(f.Kind)
		})
		if !isJSON {
			r.engine.RedactText(string(data), record)
		} else if _, err := r.engine.RedactJSON(data, record); err != nil {
			r.engine.RedactText(string(data), record)
		}
		if len(kinds) == 0 {
			return nil
		}
		x.argumentSecrets = slices.Sorted(maps.Keys(kinds))
		if mode == config.ArgumentsBlock {
			return x.refuse("the arguments hold what looks like a secret (%s), so mcp-gate did not send them; "+
				"a secret the gate holds is passed as its escrow marker, where the server's config allows it", strings.Join(x.argumentSecrets, ", "))
		}
		return nil
	}
}

// The inputs of the argument scan of each kind.

func toolInput(p *mcp.CallToolParams) ([]byte, bool) {
	raw, _ := p.Arguments.(json.RawMessage)
	return raw, true
}

func promptInput(p *mcp.GetPromptParams) ([]byte, bool) {
	if len(p.Arguments) == 0 {
		return nil, true
	}
	data, err := json.Marshal(p.Arguments)
	if err != nil {
		panic(err) // a map of strings always encodes
	}
	return data, true
}

func resourceInput(p *mcp.ReadResourceParams) ([]byte, bool) { return []byte(p.URI), false }

// Secrets returns the values kept under escrow handles; *escrow.Escrow implements it.
type Secrets interface {
	// Secret returns the text value kept under handle if a delivered result of recipient (see
	// Mirror.recipient) carried the handle, and escrow.ErrNoSecret otherwise.
	Secret(handle, recipient string) (escrow.Secret, error)
}

// Substitution is where a server's tool calls may carry escrow handles for their values.
type Substitution struct {
	rules   map[string][]substitutionRule // by tool
	secrets Secrets
}

type substitutionRule struct {
	argument string // as the config writes it
	path     []string
	from     map[string][]string
}

// NewSubstitution returns the substitution of rules, whose handles secrets resolves; with a nil
// secrets, as with the escrow off, every handle at a path a rule matches is unknown.
func NewSubstitution(rules []config.Substitution, secrets Secrets) *Substitution {
	s := &Substitution{rules: map[string][]substitutionRule{}, secrets: secrets}
	for _, r := range rules {
		s.rules[r.Tool] = append(s.rules[r.Tool], substitutionRule{argument: r.Argument, path: r.Path(), from: r.From})
	}
	return s
}

// matches reports whether the rule's path names the value at path.
func (r *substitutionRule) matches(path []string) bool {
	if len(path) != len(r.path) {
		return false
	}
	for i, seg := range r.path {
		if seg != config.SubstitutionWildcard && seg != path[i] {
			return false
		}
	}
	return true
}

// substitute is the before stage that replaces the escrow markers in the values of a tool
// call's arguments that the server's rules name by the values of their handles, or refuses the
// call when a marker there is not a handle the caller may send there.
func substitute(_ context.Context, x *exchange, p *mcp.CallToolParams) error {
	s := x.m.opts.Substitution
	if s == nil {
		return nil
	}
	rules := s.rules[x.entry]
	raw, _ := p.Arguments.(json.RawMessage)
	if len(rules) == 0 || len(raw) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var args any
	if err := dec.Decode(&args); err != nil {
		return x.refuse("the arguments are not a JSON value, so their escrow handles cannot be substituted")
	}
	w := &substitutionWalk{x: x, s: s, rules: rules}
	out := w.value(args, nil)
	if w.err != nil {
		return w.err // nothing is recorded of a refused call: it sends nothing
	}
	if !w.changed {
		return nil
	}
	x.substitutions = w.subs
	for _, e := range w.echoes {
		x.echo(e.kind, e.value, e.marker)
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return x.refuse("the arguments could not be encoded again after substitution")
	}
	p.Arguments = json.RawMessage(bytes.TrimRight(b.Bytes(), "\n"))
	return nil
}

// substitutionWalk walks the decoded arguments of one call.
type substitutionWalk struct {
	x       *exchange
	s       *Substitution
	rules   []substitutionRule
	changed bool
	err     error
	// subs and echoes are what the call records once every marker was substituted.
	subs   []audit.Substitution
	echoes []struct{ kind, value, marker string }
}

// value returns v, at path, with its markers substituted. Members are walked in name order, so
// that the first refusal does not depend on the encoding.
func (w *substitutionWalk) value(v any, path []string) any {
	if w.err != nil {
		return v
	}
	switch v := v.(type) {
	case map[string]any:
		for _, k := range slices.Sorted(maps.Keys(v)) {
			v[k] = w.value(v[k], append(path, k))
		}
	case []any:
		for i := range v {
			v[i] = w.value(v[i], append(path, strconv.Itoa(i)))
		}
	case string:
		var matched []*substitutionRule
		for i := range w.rules {
			if w.rules[i].matches(path) {
				matched = append(matched, &w.rules[i])
			}
		}
		if len(matched) > 0 {
			return w.text(v, matched)
		}
	}
	return v
}

// text returns a string value that rules match with each marker replaced by its value and each
// continuation marker removed.
func (w *substitutionWalk) text(v string, rules []*substitutionRule) string {
	x := w.x
	out := escrow.MarkerRE.ReplaceAllStringFunc(v, func(marker string) string {
		if w.err != nil {
			return marker
		}
		m := escrow.MarkerRE.FindStringSubmatch(marker)
		kind, handle := m[1], m[2]
		var sec escrow.Secret
		err := escrow.ErrNoSecret
		if w.s.secrets != nil {
			sec, err = w.s.secrets.Secret(handle, x.req.Recipient)
		}
		if err != nil || sec.Kind != kind {
			w.refused(rules[0], handle, "unknown")
			w.err = x.refuse("argument %s: handle %s is unknown or expired, or was not shown to this token; mcp-gate did not send the call", rules[0].argument, handle)
			return marker
		}
		i := slices.IndexFunc(rules, func(r *substitutionRule) bool { return slices.Contains(r.from[sec.Server], sec.Kind) })
		if i < 0 {
			w.refused(rules[0], handle, "not allowed")
			w.err = x.refuse("argument %s: handle %s (%s from %s) may not be sent there; mcp-gate did not send the call", rules[0].argument, handle, sec.Kind, sec.Server)
			return marker
		}
		w.subs = append(w.subs, audit.Substitution{Handle: handle, Kind: sec.Kind, Origin: sec.Server, Argument: rules[i].argument})
		w.echoes = append(w.echoes, struct{ kind, value, marker string }{sec.Kind, sec.Value, marker})
		return sec.Value
	})
	out = strings.ReplaceAll(out, redact.ContinuationMarker, "")
	if out != v {
		w.changed = true
	}
	return out
}

// refused logs a refused substitution, without the value.
func (w *substitutionWalk) refused(r *substitutionRule, handle, reason string) {
	w.x.m.logger.Warn("substitution refused", "tool", w.x.name, "argument", r.argument, "handle", handle, "reason", reason, "principal", w.x.principal)
}

// echo records a value substituted into the call under marker, which its answer gets wherever
// the value appears.
func (c *call) echo(kind, value, marker string) {
	if c.echoes == nil {
		c.echoes = map[string]string{}
	}
	if _, seen := c.echoes[value]; !seen {
		c.literals = append(c.literals, redact.Literal{Kind: kind, Value: value})
	}
	c.echoes[value] = marker
}

// results returns the redactor of the call's answer: the server's, finding the call's
// substituted values too when there are any.
func (c *call) results() *mcpredact.Redactor {
	r := c.m.opts.Redaction
	if len(c.literals) == 0 {
		return r.results
	}
	if c.echoRedactor == nil {
		c.echoRedactor = mcpredact.New(r.engine.WithLiterals(c.literals), r.maxTextBytes)
	}
	return c.echoRedactor
}

// scrub redacts a text from the server that is not part of the call's result, such as a
// progress message, also finding the call's substituted values.
func (c *call) scrub(s string) string {
	if r := c.m.opts.Redaction; r != nil && len(c.literals) > 0 {
		return r.engine.WithLiterals(c.literals).RedactText(s, redact.Marker{})
	}
	return c.m.scrub(s)
}

// scrubEcho redacts the call's substituted values from a text that is already fit for the
// client otherwise, such as an error message; without them it returns the text unchanged.
func (c *call) scrubEcho(s string) string {
	if len(c.literals) == 0 {
		return s
	}
	return c.scrub(s)
}

// echoReplacer replaces a finding that is a value substituted into the call by the marker the
// client passed for it, so that the value is not kept again under the server it was sent to,
// and one that holds such a value with more text by the plain marker, which keeps nothing.
// Other findings go to next.
type echoReplacer struct {
	next    redact.Replacer
	echoes  map[string]string // marker by value
	escaped []string          // the values and their JSON-escaped forms
}

func newEchoReplacer(next redact.Replacer, echoes map[string]string) *echoReplacer {
	r := &echoReplacer{next: next, echoes: echoes}
	for v := range echoes {
		r.escaped = append(r.escaped, redact.LiteralForms(v)...)
	}
	return r
}

func (r *echoReplacer) Replace(f redact.Finding) string {
	if marker, ok := r.echoes[f.Value]; ok {
		return marker
	}
	for _, v := range r.escaped {
		if strings.Contains(f.Value, v) {
			return redact.MarkerText(f.Kind)
		}
	}
	return r.next.Replace(f)
}

// isRefusal reports a refusal of a before stage.
func isRefusal(err error) bool {
	var r *refusal
	return errors.As(err, &r)
}

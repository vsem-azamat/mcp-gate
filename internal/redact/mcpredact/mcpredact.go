// Package mcpredact applies a redact.Engine to the results and errors an MCP server returns,
// as the official Go SDK decodes them.
//
// It fails closed: when a result cannot be redacted completely (a value does not re-encode, a
// text is over the size limit, a content kind is unknown, or anything panics), it returns an
// error and no result, never the original. Inputs are not modified; a redacted result shares
// every part that needed no change with its input.
package mcpredact

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/redact"
)

// ErrWithheld is the error every failed redaction matches. Its messages never quote the
// content that failed.
var ErrWithheld = errors.New("result withheld: it could not be redacted")

// MaxBlobBytes is the largest blob with a text MIME type that is scanned; a larger one fails
// the result.
const MaxBlobBytes = 8 << 20

// Redactor redacts MCP results with one engine. It is safe for concurrent use.
type Redactor struct {
	engine *redact.Engine
	// maxTextBytes is the largest text scanned; a larger one fails the result. 0 means no
	// limit.
	maxTextBytes int
}

// New returns a Redactor that uses engine. A text (a content block's text, a resource's text,
// an encoded structured value) longer than maxTextBytes fails the result; 0 means no limit.
func New(engine *redact.Engine, maxTextBytes int) *Redactor {
	return &Redactor{engine: engine, maxTextBytes: maxTextBytes}
}

// pass carries one redaction: the replacer, and the first error.
type pass struct {
	*Redactor
	replacer redact.Replacer
	err      error
}

func (p *pass) fail(format string, args ...any) {
	if p.err == nil {
		p.err = fmt.Errorf("%w: "+format, append([]any{ErrWithheld}, args...)...)
	}
}

// run calls fn and turns a panic into an error. Neither the panic value nor the content is
// reported.
func (r *Redactor) run(replacer redact.Replacer, fn func(p *pass)) (err error) {
	p := &pass{Redactor: r, replacer: replacer}
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("%w: panic during redaction", ErrWithheld)
		}
	}()
	fn(p)
	return p.err
}

// CallToolResult returns res with the secrets in its text fields replaced: text content,
// embedded resources, resource links, nested tool-use and tool-result content,
// structuredContent and every _meta. A result with input requests fails.
func (r *Redactor) CallToolResult(res *mcp.CallToolResult, replacer redact.Replacer) (*mcp.CallToolResult, error) {
	if res == nil {
		return nil, nil
	}
	var out *mcp.CallToolResult
	err := r.run(replacer, func(p *pass) {
		p.noInputRequests(len(res.InputRequests), res.RequestState)
		cp := *res
		cp.Content = p.contents(res.Content, "content")
		cp.StructuredContent = p.anyValue(res.StructuredContent, "structuredContent")
		cp.Meta = p.meta(res.Meta, "_meta")
		out = &cp
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetPromptResult returns res with every secret replaced in its description, messages and
// _meta.
func (r *Redactor) GetPromptResult(res *mcp.GetPromptResult, replacer redact.Replacer) (*mcp.GetPromptResult, error) {
	if res == nil {
		return nil, nil
	}
	var out *mcp.GetPromptResult
	err := r.run(replacer, func(p *pass) {
		p.noInputRequests(len(res.InputRequests), res.RequestState)
		cp := *res
		cp.Description = p.plainText(res.Description, "description")
		cp.Meta = p.meta(res.Meta, "_meta")
		if res.Messages != nil {
			cp.Messages = make([]*mcp.PromptMessage, len(res.Messages))
			for i, m := range res.Messages {
				if m == nil {
					continue
				}
				msg := *m
				msg.Content = p.content(m.Content, fmt.Sprintf("messages[%d].content", i))
				cp.Messages[i] = &msg
			}
		}
		out = &cp
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ReadResourceResult returns res with every secret replaced in its contents and _meta.
func (r *Redactor) ReadResourceResult(res *mcp.ReadResourceResult, replacer redact.Replacer) (*mcp.ReadResourceResult, error) {
	if res == nil {
		return nil, nil
	}
	var out *mcp.ReadResourceResult
	err := r.run(replacer, func(p *pass) {
		p.noInputRequests(len(res.InputRequests), res.RequestState)
		cp := *res
		cp.Meta = p.meta(res.Meta, "_meta")
		if res.Contents != nil {
			cp.Contents = make([]*mcp.ResourceContents, len(res.Contents))
			for i, c := range res.Contents {
				cp.Contents[i] = p.resource(c, fmt.Sprintf("contents[%d]", i))
			}
		}
		out = &cp
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// noInputRequests fails a result that asks the client for input (a multi-round-trip result):
// its requests and state are not redacted, so it is withheld.
func (p *pass) noInputRequests(requests int, state string) {
	if requests > 0 || state != "" {
		p.fail("input requests are not supported")
	}
}

func (p *pass) contents(blocks []mcp.Content, where string) []mcp.Content {
	if blocks == nil {
		return nil
	}
	out := make([]mcp.Content, len(blocks))
	for i, c := range blocks {
		out[i] = p.content(c, fmt.Sprintf("%s[%d]", where, i))
	}
	return out
}

func (p *pass) content(c mcp.Content, where string) mcp.Content {
	switch v := c.(type) {
	case nil:
		return nil
	case *mcp.TextContent:
		cp := *v
		cp.Text = p.text(v.Text, where+".text")
		cp.Meta = p.meta(v.Meta, where+"._meta")
		return &cp
	case *mcp.ImageContent:
		cp := *v
		cp.Meta = p.meta(v.Meta, where+"._meta")
		return &cp
	case *mcp.AudioContent:
		cp := *v
		cp.Meta = p.meta(v.Meta, where+"._meta")
		return &cp
	case *mcp.ResourceLink:
		cp := *v
		cp.URI = p.plainText(v.URI, where+".uri")
		cp.Name = p.plainText(v.Name, where+".name")
		cp.Title = p.plainText(v.Title, where+".title")
		cp.Description = p.plainText(v.Description, where+".description")
		cp.Icons = p.icons(v.Icons, where+".icons")
		cp.Meta = p.meta(v.Meta, where+"._meta")
		return &cp
	case *mcp.EmbeddedResource:
		cp := *v
		cp.Resource = p.resource(v.Resource, where+".resource")
		cp.Meta = p.meta(v.Meta, where+"._meta")
		return &cp
	case *mcp.ToolUseContent:
		cp := *v
		cp.Input = p.object(v.Input, where+".input")
		cp.Meta = p.meta(v.Meta, where+"._meta")
		return &cp
	case *mcp.ToolResultContent:
		cp := *v
		cp.Content = p.contents(v.Content, where+".content")
		cp.StructuredContent = p.anyValue(v.StructuredContent, where+".structuredContent")
		cp.Meta = p.meta(v.Meta, where+"._meta")
		return &cp
	default:
		p.fail("%s: unknown content type %T", where, c)
		return nil
	}
}

func (p *pass) resource(c *mcp.ResourceContents, where string) *mcp.ResourceContents {
	if c == nil {
		return nil
	}
	cp := *c
	cp.URI = p.plainText(c.URI, where+".uri")
	cp.Text = p.text(c.Text, where+".text")
	cp.Blob = p.blob(c.Blob, c.MIMEType, where+".blob")
	cp.Meta = p.meta(c.Meta, where+"._meta")
	return &cp
}

// icons redacts icon sources that are URLs; data URIs hold image data and pass unchanged.
func (p *pass) icons(icons []mcp.Icon, where string) []mcp.Icon {
	if icons == nil {
		return nil
	}
	out := make([]mcp.Icon, len(icons))
	for i, icon := range icons {
		if !strings.HasPrefix(strings.ToLower(icon.Source), "data:") {
			icon.Source = p.plainText(icon.Source, fmt.Sprintf("%s[%d].src", where, i))
		}
		out[i] = icon
	}
	return out
}

// checkSize fails the pass for a text over the limit.
func (p *pass) checkSize(n int, where string) bool {
	if p.maxTextBytes > 0 && n > p.maxTextBytes {
		p.fail("%s: %d bytes is over the %d-byte limit", where, n, p.maxTextBytes)
		return false
	}
	return true
}

// text redacts a string that may be a JSON document.
func (p *pass) text(s, where string) string {
	if s == "" || p.err != nil || !p.checkSize(len(s), where) {
		return s
	}
	return p.engine.RedactString(s, p.replacer)
}

// plainText redacts a short string matched as text only.
func (p *pass) plainText(s, where string) string {
	if s == "" || p.err != nil || !p.checkSize(len(s), where) {
		return s
	}
	return p.engine.RedactText(s, p.replacer)
}

// blob redacts a blob with a text MIME type that is valid UTF-8. A text blob over
// MaxBlobBytes fails the result; other blobs pass through unchanged.
func (p *pass) blob(b []byte, mimeType, where string) []byte {
	if len(b) == 0 || p.err != nil || !textMIMEType(mimeType) {
		return b
	}
	if len(b) > MaxBlobBytes {
		p.fail("%s: %d-byte text blob is over the %d-byte scan limit", where, len(b), MaxBlobBytes)
		return b
	}
	if !utf8.Valid(b) || !p.checkSize(len(b), where) {
		return b
	}
	text := string(b)
	if out := p.engine.RedactString(text, p.replacer); out != text {
		return []byte(out)
	}
	return b
}

// rewrite encodes v, redacts the encoding and decodes it into a fresh value of the same type.
// It returns v itself when nothing was found.
func rewrite[T any](p *pass, v T, where string) T {
	var zero T
	if p.err != nil {
		return zero
	}
	raw, err := json.Marshal(v)
	if err != nil {
		p.fail("%s does not encode", where)
		return zero
	}
	if !p.checkSize(len(raw), where) {
		return zero
	}
	out, err := p.engine.RedactJSON(raw, p.replacer)
	if err != nil {
		p.fail("%s does not encode as valid JSON", where)
		return zero
	}
	if bytes.Equal(out, raw) {
		return v
	}
	var decoded T
	if err := json.Unmarshal(out, &decoded); err != nil {
		p.fail("%s does not decode after redaction", where)
		return zero
	}
	return decoded
}

// anyValue redacts a decoded JSON value such as structuredContent.
func (p *pass) anyValue(v any, where string) any {
	if v == nil {
		return nil
	}
	return rewrite(p, v, where)
}

// object redacts a JSON object such as a tool-use input.
func (p *pass) object(m map[string]any, where string) map[string]any {
	if m == nil {
		return nil
	}
	return rewrite(p, m, where)
}

// meta redacts a _meta object.
func (p *pass) meta(m mcp.Meta, where string) mcp.Meta {
	if m == nil {
		return nil
	}
	return rewrite(p, m, where)
}

// textMIMEType reports whether a blob of this type is text worth scanning.
func textMIMEType(mimeType string) bool {
	mimeType, _, _ = strings.Cut(mimeType, ";")
	mimeType = strings.ToLower(strings.TrimSpace(mimeType))
	if strings.HasPrefix(mimeType, "text/") || strings.HasSuffix(mimeType, "+json") || strings.HasSuffix(mimeType, "+xml") {
		return true
	}
	switch mimeType {
	case "application/json", "application/xml", "application/yaml", "application/x-yaml",
		"application/toml", "application/x-sh", "application/javascript", "application/x-pem-file",
		"application/x-www-form-urlencoded":
		return true
	}
	return false
}

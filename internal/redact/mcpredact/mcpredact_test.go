package mcpredact

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/redact"
)

// fake builds a made-up secret at run time, so that no token-shaped literal sits in the source.
func fake(prefix string, n int) string {
	const alphabet = "a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ"
	var b strings.Builder
	b.WriteString(prefix)
	for i := range n {
		b.WriteByte(alphabet[(i*7+3)%len(alphabet)])
	}
	return b.String()
}

var secret = fake("ghp_", 36)

const marker = "[REDACTED:github_token]"

func newRedactor(t testing.TB, maxTextBytes int) *Redactor {
	t.Helper()
	engine, err := redact.New(redact.Options{Russian: true})
	if err != nil {
		t.Fatal(err)
	}
	return New(engine, maxTextBytes)
}

// recorder is a test Replacer that keeps every finding.
type recorder struct {
	mu       sync.Mutex
	findings []redact.Finding
}

func (r *recorder) Replace(f redact.Finding) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.findings = append(r.findings, f)
	return fmt.Sprintf("<%s #%d>", f.Kind, len(r.findings))
}

func wire(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}

// decodeResult decodes a result as an MCP client receives it.
func decodeResult(t *testing.T, raw string) *mcp.CallToolResult {
	t.Helper()
	var res mcp.CallToolResult
	if err := json.Unmarshal([]byte(raw), &res); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return &res
}

func TestCallToolResultCoversEveryTextField(t *testing.T) {
	t.Parallel()

	r := newRedactor(t, 0)
	res := &mcp.CallToolResult{
		Meta: mcp.Meta{"note": "token: " + secret, "progressToken": 7},
		Content: []mcp.Content{
			&mcp.TextContent{Text: "plain " + secret, Meta: mcp.Meta{"x": secret}},
			&mcp.EmbeddedResource{Resource: &mcp.ResourceContents{URI: "x://1", Text: "embedded " + secret, Meta: mcp.Meta{"r": secret}}, Meta: mcp.Meta{"e": secret}},
			&mcp.EmbeddedResource{Resource: &mcp.ResourceContents{URI: "x://2", MIMEType: "text/plain; charset=utf-8", Blob: []byte("blob " + secret)}},
			&mcp.ResourceLink{
				URI: "postgres://app:link-pw-9@db.example.com/x", Name: "name " + secret, Title: "title " + secret, Description: "token: " + secret,
				Icons: []mcp.Icon{{Source: "https://u:icon-pw-7@example.com/i.png"}, {Source: "data:image/png;base64,AAAA"}},
			},
			&mcp.ToolUseContent{ID: "1", Name: "n", Input: map[string]any{"api_key": "in-put-key-1", "q": "plain " + secret}, Meta: mcp.Meta{"u": secret}},
			&mcp.ToolResultContent{
				ToolUseID:         "1",
				Content:           []mcp.Content{&mcp.TextContent{Text: "nested " + secret}},
				StructuredContent: map[string]any{"password": "nested-pw-1"},
				Meta:              mcp.Meta{"m": secret},
			},
			&mcp.ImageContent{Data: []byte(secret), MIMEType: "image/png", Meta: mcp.Meta{"alt": secret}},
			&mcp.AudioContent{Data: []byte(secret), MIMEType: "audio/wav"},
		},
		StructuredContent: map[string]any{"b": 2, "note": secret, "a": 1},
	}
	got, err := r.CallToolResult(res, redact.Marker{})
	if err != nil {
		t.Fatal(err)
	}
	out := wire(t, got)
	for _, leaked := range []string{"link-pw-9", "icon-pw-7", "in-put-key-1", "nested-pw-1"} {
		if strings.Contains(out, leaked) {
			t.Errorf("%q survived: %s", leaked, out)
		}
	}
	// The image and audio data are binary and pass through; everything else is redacted.
	if n := strings.Count(out, secret); n != 0 {
		t.Errorf("secret survived %d times outside binary data: %s", n, out)
	}
	if img, ok := got.Content[6].(*mcp.ImageContent); !ok || string(img.Data) != secret {
		t.Error("image data must pass through unchanged")
	}
	if audio, ok := got.Content[7].(*mcp.AudioContent); !ok || string(audio.Data) != secret {
		t.Error("audio data must pass through unchanged")
	}
	if res, ok := got.Content[2].(*mcp.EmbeddedResource); !ok || string(res.Resource.Blob) != "blob "+marker {
		t.Errorf("blob = %+v", got.Content[2])
	}
	if structured, ok := got.StructuredContent.(map[string]any); !ok || structured["note"] != marker {
		t.Errorf("structured content = %v", got.StructuredContent)
	}
	if got.Meta["progressToken"] != float64(7) || got.Meta["note"] != "token: "+marker {
		t.Errorf("_meta = %v", got.Meta)
	}
}

func TestCallToolResultDecodedFromTheWire(t *testing.T) {
	t.Parallel()

	r := newRedactor(t, 0)
	res := decodeResult(t, `{"content":[{"type":"text","text":"{\"text\":\"`+secret+`\",\"id\":42}"}],`+
		`"structuredContent":{"text":"`+secret+`","pin":123456,"n":1.5},"isError":true,"_meta":{"k":"v"}}`)
	got, err := r.CallToolResult(res, redact.Marker{})
	if err != nil {
		t.Fatal(err)
	}
	if text := textOf(t, got.Content[0]); text != `{"text":"`+marker+`","id":42}` {
		t.Errorf("text = %s", text)
	}
	// A number under a secret member becomes a string marker.
	want := map[string]any{"text": marker, "pin": "[REDACTED:password]", "n": 1.5}
	if !reflect.DeepEqual(got.StructuredContent, want) {
		t.Errorf("structuredContent = %v, want %v", got.StructuredContent, want)
	}
	if !got.IsError || !reflect.DeepEqual(got.Meta, res.Meta) {
		t.Errorf("other fields changed: %+v", got)
	}
}

func TestInputIsNotModified(t *testing.T) {
	t.Parallel()

	r := newRedactor(t, 0)
	raw := `{"content":[{"type":"text","text":"` + secret + `","_meta":{"t":"` + secret + `"}},` +
		`{"type":"resource","resource":{"uri":"x://1","mimeType":"text/plain","blob":"` + b64(secret) + `"}},` +
		`{"type":"tool_use","id":"1","name":"n","input":{"token":"abc-123-def"}}],` +
		`"structuredContent":{"token":"abc-123-def"},"_meta":{"t":"` + secret + `"}}`
	res := decodeResult(t, raw)
	before := wire(t, res)
	if _, err := r.CallToolResult(res, redact.Marker{}); err != nil {
		t.Fatal(err)
	}
	if after := wire(t, res); after != before {
		t.Errorf("input changed:\n%s\n%s", before, after)
	}
}

func textOf(t *testing.T, c mcp.Content) string {
	t.Helper()
	text, ok := c.(*mcp.TextContent)
	if !ok {
		t.Fatalf("content is %T, want text", c)
	}
	return text.Text
}

func TestPromptAndResourceInputsAreNotModified(t *testing.T) {
	t.Parallel()

	r := newRedactor(t, 0)
	prompt := &mcp.GetPromptResult{
		Description: "token: " + secret,
		Messages:    []*mcp.PromptMessage{{Role: "user", Content: &mcp.ToolResultContent{Content: []mcp.Content{&mcp.TextContent{Text: secret}}}}},
	}
	before := wire(t, prompt)
	if _, err := r.GetPromptResult(prompt, redact.Marker{}); err != nil {
		t.Fatal(err)
	}
	if after := wire(t, prompt); after != before {
		t.Errorf("prompt changed:\n%s\n%s", before, after)
	}
	resource := &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: "x://1", MIMEType: "text/plain", Blob: []byte(secret), Text: secret}}}
	before = wire(t, resource)
	if _, err := r.ReadResourceResult(resource, redact.Marker{}); err != nil {
		t.Fatal(err)
	}
	if after := wire(t, resource); after != before {
		t.Errorf("resource changed:\n%s\n%s", before, after)
	}
}

func TestInputRequestsAreWithheld(t *testing.T) {
	t.Parallel()

	r := newRedactor(t, 0)
	for name, res := range map[string]*mcp.CallToolResult{
		"input requests": decodeResult(t, `{"content":[],"resultType":"input_required","inputRequests":{"a":{"method":"elicitation/create","params":{"message":"token: `+secret+`","requestedSchema":{"type":"object"}}}}}`),
		"request state":  {RequestState: "state " + secret},
	} {
		if got, err := r.CallToolResult(res, redact.Marker{}); !errors.Is(err, ErrWithheld) || got != nil {
			t.Errorf("%s: got %v, %v; want ErrWithheld", name, got, err)
		}
	}
	if _, err := r.GetPromptResult(&mcp.GetPromptResult{RequestState: "s"}, redact.Marker{}); !errors.Is(err, ErrWithheld) {
		t.Errorf("prompt with request state: %v", err)
	}
	if _, err := r.ReadResourceResult(&mcp.ReadResourceResult{RequestState: "s"}, redact.Marker{}); !errors.Is(err, ErrWithheld) {
		t.Errorf("resource with request state: %v", err)
	}
}

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func TestNothingFoundKeepsTheResult(t *testing.T) {
	t.Parallel()

	r := newRedactor(t, 0)
	raw := `{"content":[{"type":"text","text":"hello"},{"type":"image","data":"AAAA","mimeType":"image/png"}],` +
		`"structuredContent":{"n":12345678901234567890,"s":"x"},"_meta":{"k":"v"}}`
	res := decodeResult(t, raw)
	got, err := r.CallToolResult(res, redact.Marker{})
	if err != nil {
		t.Fatal(err)
	}
	if wire(t, got) != wire(t, res) {
		t.Errorf("result changed: %s", wire(t, got))
	}
	if !reflect.DeepEqual(got.StructuredContent, res.StructuredContent) {
		t.Error("structuredContent was rebuilt although nothing was found")
	}
}

func TestReplacerReceivesFindings(t *testing.T) {
	t.Parallel()

	r := newRedactor(t, 0)
	rec := &recorder{}
	res := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "password: hunter22 and " + secret}}}
	got, err := r.CallToolResult(res, rec)
	if err != nil {
		t.Fatal(err)
	}
	if text := textOf(t, got.Content[0]); text != "password: <password #1> and <github_token #2>" {
		t.Fatalf("text = %q", text)
	}
	if len(rec.findings) != 2 || rec.findings[0].Value != "hunter22" || rec.findings[1].Value != secret {
		t.Fatalf("findings = %+v", rec.findings)
	}
}

func TestBlobs(t *testing.T) {
	t.Parallel()

	r := newRedactor(t, 0)
	big := []byte(strings.Repeat("x", MaxBlobBytes) + secret)
	for _, tt := range []struct {
		name     string
		mimeType string
		blob     []byte
		redacted bool
		wantErr  bool
	}{
		{"text", "text/markdown", []byte(secret), true, false},
		{"json suffix", "application/vnd.api+json", []byte(`{"token":"abc-123-def"}`), true, false},
		{"pem", "application/x-pem-file", []byte(secret), true, false},
		{"binary type", "application/octet-stream", []byte(secret), false, false},
		{"no type", "", []byte(secret), false, false},
		{"text not UTF-8", "text/plain", append([]byte{0xff, 0xfe}, secret...), false, true},
		{"binary not UTF-8", "image/png", append([]byte{0xff, 0xfe}, secret...), false, false},
		{"text over the cap", "text/plain", big, false, true},
		{"binary over the cap", "application/octet-stream", big, false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res := &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: "x://1", MIMEType: tt.mimeType, Blob: tt.blob}}}
			got, err := r.ReadResourceResult(res, redact.Marker{})
			if tt.wantErr {
				if !errors.Is(err, ErrWithheld) || got != nil {
					t.Fatalf("got %v, %v; want ErrWithheld", got, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			changed := string(got.Contents[0].Blob) != string(tt.blob)
			if changed != tt.redacted {
				t.Errorf("redacted = %v, want %v: %.80q", changed, tt.redacted, got.Contents[0].Blob)
			}
		})
	}
}

func TestPromptAndResourceResults(t *testing.T) {
	t.Parallel()

	r := newRedactor(t, 0)
	prompt := &mcp.GetPromptResult{
		Description: "token: " + secret,
		Messages: []*mcp.PromptMessage{
			{Role: "user", Content: &mcp.TextContent{Text: "пароль: Qwerty-12345"}},
			nil,
			{Role: "assistant", Content: &mcp.EmbeddedResource{Resource: &mcp.ResourceContents{URI: "x://1", Text: secret}}},
		},
		Meta: mcp.Meta{"s": secret},
	}
	gotPrompt, err := r.GetPromptResult(prompt, redact.Marker{})
	if err != nil {
		t.Fatal(err)
	}
	if out := wire(t, gotPrompt); strings.Contains(out, secret) || strings.Contains(out, "Qwerty-12345") {
		t.Errorf("prompt not redacted: %s", out)
	}
	if gotPrompt.Messages[1] != nil || gotPrompt.Messages[0].Role != "user" {
		t.Errorf("messages = %+v", gotPrompt.Messages)
	}

	resource := &mcp.ReadResourceResult{
		Contents: []*mcp.ResourceContents{{URI: "postgres://app:uri-pw-5@db.example.com/x", MIMEType: "text/plain", Text: "API_KEY=" + fake("", 20)}, nil},
		Meta:     mcp.Meta{"s": secret},
	}
	gotResource, err := r.ReadResourceResult(resource, redact.Marker{})
	if err != nil {
		t.Fatal(err)
	}
	if out := wire(t, gotResource); strings.Contains(out, fake("", 20)) || strings.Contains(out, secret) || strings.Contains(out, "uri-pw-5") {
		t.Errorf("resource not redacted: %s", out)
	}

	for _, res := range []any{must(r.CallToolResult(nil, redact.Marker{})), must(r.GetPromptResult(nil, redact.Marker{})), must(r.ReadResourceResult(nil, redact.Marker{}))} {
		if !reflect.ValueOf(res).IsNil() {
			t.Errorf("nil result redacted to %v", res)
		}
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// unknownContent is a content kind the adapter does not know, as a future SDK might add.
type unknownContent struct{ mcp.Content }

type panicReplacer struct{}

func (panicReplacer) Replace(f redact.Finding) string { panic("replacer saw " + f.Value) }

func TestFailsClosed(t *testing.T) {
	t.Parallel()

	r := newRedactor(t, 0)
	tests := []struct {
		name     string
		res      *mcp.CallToolResult
		replacer redact.Replacer
		r        *Redactor
	}{
		{
			name: "structured content that does not encode",
			res:  &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: secret}}, StructuredContent: map[string]any{"x": math.NaN(), "s": secret}},
		},
		{
			name: "_meta that does not encode",
			res:  &mcp.CallToolResult{Meta: mcp.Meta{"c": make(chan int), "s": secret}},
		},
		{
			name: "tool-use input that does not encode",
			res:  &mcp.CallToolResult{Content: []mcp.Content{&mcp.ToolUseContent{Input: map[string]any{"f": func() {}, "s": secret}}}},
		},
		{
			name: "structured raw JSON that is invalid",
			res:  &mcp.CallToolResult{StructuredContent: json.RawMessage(`{"s":"` + secret + `"`)},
		},
		{
			name: "unknown content kind",
			res:  &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: secret}, unknownContent{}}},
		},
		{
			name: "nested unknown content kind",
			res:  &mcp.CallToolResult{Content: []mcp.Content{&mcp.ToolResultContent{Content: []mcp.Content{unknownContent{}}}}},
		},
		{
			name: "typed nil content",
			res:  &mcp.CallToolResult{Content: []mcp.Content{(*mcp.TextContent)(nil)}},
		},
		{
			name:     "panicking replacer",
			res:      &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: secret}}},
			replacer: panicReplacer{},
		},
		{
			name: "text over the limit",
			res:  &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Repeat("a", 64) + secret}}},
			r:    newRedactor(t, 64),
		},
		{
			name: "structured content over the limit",
			res:  &mcp.CallToolResult{StructuredContent: map[string]any{"s": strings.Repeat("a", 64) + secret}},
			r:    newRedactor(t, 64),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rd, replacer := r, tt.replacer
			if tt.r != nil {
				rd = tt.r
			}
			if replacer == nil {
				replacer = redact.Marker{}
			}
			got, err := rd.CallToolResult(tt.res, replacer)
			if !errors.Is(err, ErrWithheld) || got != nil {
				t.Fatalf("got %v, %v; want ErrWithheld and no result", got, err)
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "replacer saw") {
				t.Errorf("error quotes the content: %v", err)
			}
		})
	}

	// The limit applies to every text the adapter scans, in prompts and resources too.
	small := newRedactor(t, 8)
	if _, err := small.GetPromptResult(&mcp.GetPromptResult{Description: "a long description"}, redact.Marker{}); !errors.Is(err, ErrWithheld) {
		t.Errorf("prompt description over the limit: %v", err)
	}
	if _, err := small.ReadResourceResult(&mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: "x://1", Text: "a long resource text"}}}, redact.Marker{}); !errors.Is(err, ErrWithheld) {
		t.Errorf("resource text over the limit: %v", err)
	}
}

func TestErrors(t *testing.T) {
	t.Parallel()

	r := newRedactor(t, 0)

	t.Run("plain error", func(t *testing.T) {
		t.Parallel()
		cause := fmt.Errorf("bad credentials for %s: %w", secret, context.DeadlineExceeded)
		err := r.Error(cause, redact.Marker{})
		if err.Error() != "bad credentials for "+marker+": context deadline exceeded" {
			t.Errorf("message = %q", err)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Error("a redacted error must still match its cause's targets")
		}
		if errors.Unwrap(err) != nil {
			t.Error("a redacted error must not unwrap to the original")
		}
		var wireErr *jsonrpc.Error
		if errors.As(err, &wireErr) {
			t.Errorf("found a JSON-RPC error in a plain error: %v", wireErr)
		}
	})

	t.Run("JSON-RPC error", func(t *testing.T) {
		t.Parallel()
		cause := &jsonrpc.Error{Code: -32001, Message: "token: " + secret, Data: json.RawMessage(`{"password":"wire-pw-1","n":1}`)}
		err := r.Error(cause, redact.Marker{})
		got, ok := err.(*jsonrpc.Error) //nolint:errorlint // the direct type is the contract
		if !ok {
			t.Fatalf("got %T, want *jsonrpc.Error", err)
		}
		if got.Code != -32001 || got.Message != "token: "+marker || string(got.Data) != `{"password":"[REDACTED:password]","n":1}` {
			t.Errorf("error = %+v, data %s", got, got.Data)
		}
		if cause.Message != "token: "+secret {
			t.Error("the original error was modified")
		}
	})

	t.Run("wrapped JSON-RPC error", func(t *testing.T) {
		t.Parallel()
		inner := &jsonrpc.Error{Code: -32002, Message: "inner " + secret}
		err := r.Error(fmt.Errorf("call failed: %w", inner), redact.Marker{})
		if strings.Contains(err.Error(), secret) {
			t.Errorf("message = %q", err)
		}
		var wireErr *jsonrpc.Error
		if !errors.As(err, &wireErr) || wireErr.Code != -32002 || strings.Contains(wireErr.Message, secret) {
			t.Errorf("errors.As found %+v", wireErr)
		}
		if !errors.Is(err, &jsonrpc.Error{Code: -32002}) {
			t.Error("the JSON-RPC code must still match")
		}
	})

	t.Run("JSON-RPC error behind a message that hides it", func(t *testing.T) {
		t.Parallel()
		inner := &jsonrpc.Error{Code: -32003, Message: "inner " + secret}
		err := r.Error(hidingError{inner}, redact.Marker{})
		var wireErr *jsonrpc.Error
		if !errors.As(err, &wireErr) || wireErr.Code != -32003 || strings.Contains(wireErr.Message, secret) {
			t.Errorf("errors.As found %+v", wireErr)
		}
		if err.Error() != "call failed" {
			t.Errorf("message = %q", err)
		}
	})

	t.Run("JSON-RPC data that is not JSON is dropped", func(t *testing.T) {
		t.Parallel()
		cause := &jsonrpc.Error{Code: 1, Message: "m", Data: json.RawMessage(`not json ` + secret)}
		got := r.Error(cause, redact.Marker{}).(*jsonrpc.Error) //nolint:errorlint,forcetypeassert // the direct type is the contract
		if got.Data != nil || got.Message != "m" {
			t.Errorf("error = %+v", got)
		}
	})

	t.Run("nothing found", func(t *testing.T) {
		t.Parallel()
		cause := fmt.Errorf("not found: %w", context.Canceled)
		if err := r.Error(cause, redact.Marker{}); err != cause { //nolint:errorlint // identity is the contract
			t.Errorf("got %v, want the same error", err)
		}
		if r.Error(nil, redact.Marker{}) != nil {
			t.Error("nil error redacted to non-nil")
		}
	})

	t.Run("failure", func(t *testing.T) {
		t.Parallel()
		err := r.Error(errors.New("token: "+secret), panicReplacer{})
		if !errors.Is(err, ErrWithheld) || strings.Contains(err.Error(), secret) {
			t.Errorf("err = %v", err)
		}
		if err := newRedactor(t, 4).Error(errors.New("a long message"), redact.Marker{}); !errors.Is(err, ErrWithheld) {
			t.Errorf("message over the limit: %v", err)
		}
	})
}

// hidingError wraps an error without repeating its message.
type hidingError struct{ cause error }

func (e hidingError) Error() string { return "call failed" }
func (e hidingError) Unwrap() error { return e.cause }

func TestTextMIMEType(t *testing.T) {
	t.Parallel()

	for mimeType, want := range map[string]bool{
		"text/plain": true, "TEXT/HTML; charset=utf-8": true, " application/json ": true,
		"application/ld+json": true, "image/svg+xml": true, "application/x-yaml": true,
		"application/octet-stream": false, "image/png": false, "": false, "application/pdf": false,
	} {
		if got := textMIMEType(mimeType); got != want {
			t.Errorf("textMIMEType(%q) = %v, want %v", mimeType, got, want)
		}
	}
}

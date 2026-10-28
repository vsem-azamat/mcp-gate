package audit

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/vsem-azamat/mcp-gate/internal/policy"
)

func TestLogLine(t *testing.T) {
	var out strings.Builder
	logger := slog.New(slog.NewJSONHandler(&out, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	}))
	sink := Log(logger)
	sink.Write(Record{
		Server: "s", Principal: "laptop", Kind: Tool, Name: "echo", Duration: 1500 * time.Microsecond,
		Outcome: ToolError, TokenPolicy: policy.Allowed, Redactions: 2,
	})
	sink.Write(Record{Kind: Prompt, Name: "greet", Outcome: Denied, TokenPolicy: policy.NoPolicy})
	sink.Write(Record{Server: "s", Kind: Resource, Name: "x://y", Outcome: Withheld, TokenPolicy: policy.Denied})
	sink.Write(Record{Server: "s", Principal: "phone", Kind: Tool, Name: "echo", Outcome: Limited, TokenPolicy: policy.NoPolicy})
	want := `{"level":"INFO","msg":"call","server":"s","principal":"laptop","method":"tools/call","tool":"echo","durMs":1,"outcome":"tool_error","tokenPolicy":"allow","redactions":2}
{"level":"INFO","msg":"call","server":"","principal":"","method":"prompts/get","prompt":"greet","durMs":0,"outcome":"denied","tokenPolicy":"none","redactions":0}
{"level":"INFO","msg":"call","server":"s","principal":"","method":"resources/read","uri":"x://y","durMs":0,"outcome":"withheld","tokenPolicy":"deny","redactions":0}
{"level":"INFO","msg":"call","server":"s","principal":"phone","method":"tools/call","tool":"echo","durMs":0,"outcome":"limited","tokenPolicy":"none","redactions":0}
`
	if out.String() != want {
		t.Errorf("lines:\n%s\nwant:\n%s", out.String(), want)
	}
}

func TestToolPinLine(t *testing.T) {
	var out strings.Builder
	logger := slog.New(slog.NewJSONHandler(&out, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	}))
	LogToolPin(logger, PinRecord{Server: "s", Tool: "echo", Change: "changed", Pinned: "sha256:aa", Listed: "sha256:bb", Held: true})
	LogToolPin(logger, PinRecord{Server: "s", Tool: "fresh", Change: "added", Listed: "sha256:cc"})
	want := `{"level":"WARN","msg":"toolPin","server":"s","tool":"echo","change":"changed","pinned":"sha256:aa","listed":"sha256:bb","action":"held"}
{"level":"WARN","msg":"toolPin","server":"s","tool":"fresh","change":"added","pinned":"","listed":"sha256:cc","action":"served"}
`
	if out.String() != want {
		t.Errorf("lines:\n%s\nwant:\n%s", out.String(), want)
	}
}

func TestOutcomeFailed(t *testing.T) {
	for _, c := range []struct {
		o      Outcome
		failed bool
	}{
		{OK, false},
		{ToolError, false},
		{Error, true},
		{Denied, true},
		{Unavailable, true},
		{Withheld, true},
		{InputRequired, true},
		{Limited, true},
	} {
		if got := c.o.Failed(); got != c.failed {
			t.Errorf("%s.Failed() = %v", c.o, got)
		}
	}
}

func TestKind(t *testing.T) {
	for _, c := range []struct {
		k                 Kind
		name, method, key string
	}{
		{Tool, "tool", "tools/call", "tool"},
		{Prompt, "prompt", "prompts/get", "prompt"},
		{Resource, "resource", "resources/read", "uri"},
	} {
		if c.k.String() != c.name || c.k.Method() != c.method || c.k.Key() != c.key {
			t.Errorf("%d: %q %q %q", c.k, c.k.String(), c.k.Method(), c.k.Key())
		}
	}
	if Tool|Prompt|Resource != 7 {
		t.Error("the kinds are not distinct bits")
	}
}

type collect []Record

func (c *collect) Write(r Record) { *c = append(*c, r) }

func TestTee(t *testing.T) {
	var a, b collect
	Tee(&a, &b).Write(Record{Server: "s", Kind: Tool, Name: "echo", Outcome: OK})
	if len(a) != 1 || len(b) != 1 || a[0].Name != "echo" || b[0].Server != "s" {
		t.Errorf("tee: %v %v", a, b)
	}
}

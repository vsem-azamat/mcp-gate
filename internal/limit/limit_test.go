package limit

import (
	"testing"
	"time"
)

// clock is a fake time source.
type clock struct{ t time.Time }

func newClock() *clock                   { return &clock{t: time.Unix(1_000_000, 0)} }
func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

// The rules of the tests, built up with the selectors.
func rate(n int, per time.Duration) *Rule { return &Rule{Rate: n, Per: per, Burst: n} }
func conc(n int) *Rule                    { return &Rule{Concurrency: n} }
func (r *Rule) on(server string) *Rule    { r.Server = server; return r }
func (r *Rule) of(token string) *Rule     { r.Token = token; return r }
func (r *Rule) tool(name string) *Rule    { r.Tool = name; return r }
func (r *Rule) burst(n int) *Rule         { r.Burst = n; return r }

func rules(rs ...*Rule) []Rule {
	out := make([]Rule, len(rs))
	for i, r := range rs {
		out[i] = *r
	}
	return out
}

func toolCall(token, server, tool string) Request {
	return Request{Token: token, Server: server, Tool: tool}
}

func TestRateAndBurst(t *testing.T) {
	c := newClock()
	l := New(c.now)
	l.Set(rules(rate(2, time.Minute).of("phone").on("a").tool("echo")))
	for i := range 2 {
		if _, ref := l.Acquire(toolCall("phone", "a", "echo")); ref != nil {
			t.Fatalf("call %d refused: %v", i, ref)
		}
	}
	_, ref := l.Acquire(toolCall("phone", "a", "echo"))
	if ref == nil {
		t.Fatal("third call passed")
	}
	if ref.RetryAfter != 30*time.Second {
		t.Errorf("retry after %v, want 30s", ref.RetryAfter)
	}
	if got, want := ref.Error(), "mcp-gate: rate limit reached: at most 2 calls per 1m; retry in 30s"; got != want {
		t.Errorf("message %q, want %q", got, want)
	}
	// Other tools, tokens and servers do not match.
	for _, r := range []Request{toolCall("phone", "a", "env"), toolCall("laptop", "a", "echo"), toolCall("phone", "b", "echo"), {Token: "phone", Server: "a"}} {
		if _, ref := l.Acquire(r); ref != nil {
			t.Errorf("%+v refused", r)
		}
	}
	c.advance(30 * time.Second)
	if _, ref := l.Acquire(toolCall("phone", "a", "echo")); ref != nil {
		t.Errorf("refused after the refill: %v", ref)
	}
}

func TestBurstBelowRate(t *testing.T) {
	c := newClock()
	l := New(c.now)
	l.Set(rules(rate(10, time.Second).burst(1)))
	if _, ref := l.Acquire(Request{}); ref != nil {
		t.Fatal(ref)
	}
	_, ref := l.Acquire(Request{})
	if ref == nil || ref.RetryAfter != 100*time.Millisecond {
		t.Fatalf("refusal %v", ref)
	}
	if got, want := ref.Error(), "mcp-gate: rate limit reached: at most 10 calls per 1s; retry in 1s"; got != want {
		t.Errorf("message %q, want %q", got, want)
	}
}

func TestAllMustPass(t *testing.T) {
	c := newClock()
	l := New(c.now)
	server, token := rate(10, time.Second).on("a"), rate(1, time.Hour).of("phone")
	l.Set(rules(server, token))
	if _, ref := l.Acquire(Request{Token: "phone", Server: "a"}); ref != nil {
		t.Fatal(ref)
	}
	_, ref := l.Acquire(Request{Token: "phone", Server: "a"})
	if ref == nil || ref.Rule != *token {
		t.Fatalf("refusal %v, want the token's", ref)
	}
	// The server's entry took one call only: nine more pass at once.
	for i := range 9 {
		if _, ref := l.Acquire(Request{Token: "laptop", Server: "a"}); ref != nil {
			t.Fatalf("call %d refused: %v", i, ref)
		}
	}
	if _, ref := l.Acquire(Request{Token: "laptop", Server: "a"}); ref == nil {
		t.Error("the server's entry passed an eleventh call")
	}
}

func TestFirstRefusingEntry(t *testing.T) {
	l := New(newClock().now)
	l.Set(rules(conc(1), rate(1, time.Hour)))
	release, _ := l.Acquire(Request{})
	_, ref := l.Acquire(Request{})
	if ref == nil || ref.Rule.Concurrency != 1 {
		t.Fatalf("refusal %v, want the concurrency entry", ref)
	}
	if got, want := ref.Error(), "mcp-gate: concurrency limit reached: at most 1 call in flight; retry when one ends"; got != want {
		t.Errorf("message %q, want %q", got, want)
	}
	release()
	release() // a second release is a no-op
	_, ref = l.Acquire(Request{})
	if ref == nil || ref.Rule.Rate != 1 {
		t.Fatalf("refusal %v, want the rate entry", ref)
	}
}

func TestConcurrency(t *testing.T) {
	l := New(newClock().now)
	l.Set(rules(conc(2).on("a")))
	r1, _ := l.Acquire(Request{Server: "a"})
	r2, _ := l.Acquire(Request{Server: "a"})
	if _, ref := l.Acquire(Request{Server: "a"}); ref == nil || ref.RetryAfter != 0 {
		t.Fatalf("third call: %v", ref)
	}
	r1()
	r3, ref := l.Acquire(Request{Server: "a"})
	if ref != nil {
		t.Fatal(ref)
	}
	r2()
	r3()
}

func TestToolRuleOnlyForTools(t *testing.T) {
	l := New(newClock().now)
	l.Set(rules(rate(1, time.Hour).on("a").tool("echo")))
	for range 3 {
		if _, ref := l.Acquire(Request{Server: "a"}); ref != nil {
			t.Fatal("a prompt get or resource read matched a tool entry")
		}
	}
}

func TestTokenRuleWithoutToken(t *testing.T) {
	l := New(newClock().now)
	l.Set(rules(rate(1, time.Hour).of("phone")))
	for range 3 {
		if _, ref := l.Acquire(Request{Server: "a"}); ref != nil {
			t.Fatal("a request without a token matched a token entry")
		}
	}
}

func TestSetKeepsUnchanged(t *testing.T) {
	c := newClock()
	l := New(c.now)
	kept, other := rate(1, time.Hour).of("phone"), conc(1).on("b")
	l.Set(rules(kept, other))
	if _, ref := l.Acquire(Request{Token: "phone"}); ref != nil {
		t.Fatal(ref)
	}
	held, _ := l.Acquire(Request{Server: "b"})
	defer held()
	// Another entry changes; the unchanged ones keep their state.
	l.Set(rules(rate(5, time.Second).on("c"), other, kept))
	if _, ref := l.Acquire(Request{Token: "phone"}); ref == nil {
		t.Error("an unchanged entry got a full bucket")
	}
	if _, ref := l.Acquire(Request{Server: "b"}); ref == nil {
		t.Error("an unchanged entry lost its calls in flight")
	}
	// The entry changes: a full bucket.
	l.Set(rules(rate(2, time.Hour).of("phone")))
	if _, ref := l.Acquire(Request{Token: "phone"}); ref != nil {
		t.Errorf("a changed entry kept its bucket: %v", ref)
	}
	// A call that held a place of a dropped entry releases without harm.
	held()
}

func TestNoRules(t *testing.T) {
	var l *Limiter
	release, ref := l.Acquire(Request{Token: "x"})
	if ref != nil || release == nil {
		t.Fatal("a nil limiter refused")
	}
	release()
	l = New(nil)
	if _, ref := l.Acquire(Request{}); ref != nil {
		t.Fatal(ref)
	}
}

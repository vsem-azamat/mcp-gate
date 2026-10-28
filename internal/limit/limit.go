// Package limit is the rate and concurrency limits on the requests that reach the servers: a
// token bucket and a count of calls in flight for each configured entry, in memory.
package limit

import (
	"fmt"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/vsem-azamat/mcp-gate/internal/config"
)

// Rule is one limit entry: the requests it matches and what it lets through. It is comparable,
// and a reload keeps the state of a rule equal to one it had.
type Rule struct {
	// Token, Server and Tool select the requests; "" matches any. Tool matches only tool calls.
	Token, Server, Tool string
	// Rate calls per Per refill a bucket of Burst calls; a Rate of 0 sets no rate limit.
	Rate  int
	Per   time.Duration
	Burst int
	// Concurrency is the most calls in flight at once; 0 sets none.
	Concurrency int
}

// Rules returns the rules of a config's limits, in order.
func Rules(cfg *config.Config) []Rule {
	out := make([]Rule, 0, len(cfg.Limits))
	for _, l := range cfg.Limits {
		out = append(out, Rule{
			Token: l.Token, Server: l.Server, Tool: l.Tool,
			Rate: l.Calls, Per: l.Per, Burst: l.Burst, Concurrency: l.Concurrency,
		})
	}
	return out
}

// Request is what a rule is matched against: the name of the caller's token ("" without one),
// the server, and the tool of a tool call ("" for a prompt get or a resource read).
type Request struct {
	Token, Server, Tool string
}

// matches reports whether the rule applies to r.
func (r *Rule) matches(req Request) bool {
	return (r.Token == "" || r.Token == req.Token) &&
		(r.Server == "" || r.Server == req.Server) &&
		(r.Tool == "" || r.Tool == req.Tool)
}

// Refusal is the error of a request a rule refused: it says the limit and when to retry, and
// nothing of the request or of the other rules.
type Refusal struct {
	Rule Rule
	// RetryAfter is when the rule would pass the request again, for a rate limit; 0 for a
	// concurrency limit, which passes once a call in flight ends.
	RetryAfter time.Duration
}

func (e *Refusal) Error() string {
	r := e.Rule
	if e.RetryAfter == 0 {
		return fmt.Sprintf("mcp-gate: concurrency limit reached: at most %s in flight; retry when one ends", calls(r.Concurrency))
	}
	secs := max(1, int64(math.Ceil(e.RetryAfter.Seconds())))
	return fmt.Sprintf("mcp-gate: rate limit reached: at most %s per %s; retry in %ds", calls(r.Rate), config.FormatDuration(r.Per), secs)
}

func calls(n int) string {
	if n == 1 {
		return "1 call"
	}
	return fmt.Sprintf("%d calls", n)
}

// state is what a rule has used: its bucket and its calls in flight.
type state struct {
	rule     Rule
	tokens   float64 // calls left in the bucket at last
	last     time.Time
	inflight int
}

// refill brings the bucket up to now.
func (s *state) refill(now time.Time) {
	if s.rule.Rate == 0 {
		return
	}
	if d := now.Sub(s.last); d > 0 {
		s.tokens = min(float64(s.rule.Burst), s.tokens+float64(d)*float64(s.rule.Rate)/float64(s.rule.Per))
	}
	s.last = now
}

// refuses returns the refusal of one more call, nil when the rule passes it. The bucket is
// refilled first.
func (s *state) refuses() *Refusal {
	if s.rule.Rate > 0 && s.tokens < 1 {
		wait := time.Duration(math.Ceil((1 - s.tokens) * float64(s.rule.Per) / float64(s.rule.Rate)))
		return &Refusal{Rule: s.rule, RetryAfter: max(wait, time.Millisecond)}
	}
	if c := s.rule.Concurrency; c > 0 && s.inflight >= c {
		return &Refusal{Rule: s.rule}
	}
	return nil
}

// Limiter holds the state of the rules in force. The zero value and nil pass every request.
type Limiter struct {
	now func() time.Time

	mu    sync.Mutex
	rules []*state
}

// New returns a limiter without rules; now is its clock, time.Now when nil.
func New(now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{now: now}
}

// selector is what a rule matches, which a reload carries its state by.
type selector struct{ token, server, tool string }

func (r *Rule) selector() selector { return selector{r.Token, r.Server, r.Tool} }

// Set puts rules in force, in order. A rule equal to one in force keeps its state. A rule whose
// selectors are those of one in force that is not kept takes that one's state: its calls in
// flight, and its bucket as it is now, capped at the new burst, or full when the old rule had no
// rate. Any other rule starts with a full bucket and nothing in flight.
func (l *Limiter) Set(rules []Rule) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	free := slices.Clone(l.rules) // the states not taken yet, in order
	take := func(ok func(*state) bool) *state {
		for i, s := range free {
			if s != nil && ok(s) {
				free[i] = nil
				return s
			}
		}
		return nil
	}
	next := make([]*state, len(rules))
	for i, r := range rules {
		next[i] = take(func(s *state) bool { return s.rule == r })
	}
	for i, r := range rules {
		if next[i] != nil {
			continue
		}
		// The calls in flight give their places back to the state they took them from, so a
		// changed rule keeps that state and changes in place.
		if s := take(func(s *state) bool { return s.rule.selector() == r.selector() }); s != nil {
			s.refill(now)
			if s.rule.Rate == 0 {
				s.tokens = float64(r.Burst)
			}
			s.tokens = min(s.tokens, float64(r.Burst))
			s.rule, s.last = r, now
			next[i] = s
			continue
		}
		next[i] = &state{rule: r, tokens: float64(r.Burst), last: now}
	}
	l.rules = next
}

// Acquire checks a request against every rule that matches it. When all pass, it takes a call
// from each one's bucket and a place in flight, and returns the function that gives the places
// back when the request ends, which may be called more than once. Otherwise it takes nothing and
// returns a refusal: of the rate rule that refused with the longest wait, or, when only
// concurrency rules refused, of the first of them, in order.
func (l *Limiter) Acquire(req Request) (release func(), refused *Refusal) {
	if l == nil {
		return func() {}, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	var matched []*state
	for _, s := range l.rules {
		if !s.rule.matches(req) {
			continue
		}
		s.refill(now)
		if ref := s.refuses(); ref != nil && (refused == nil || ref.RetryAfter > refused.RetryAfter) {
			refused = ref
		}
		matched = append(matched, s)
	}
	if refused != nil {
		return nil, refused
	}
	for _, s := range matched {
		if s.rule.Rate > 0 {
			s.tokens--
		}
		s.inflight++
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			for _, s := range matched {
				s.inflight--
			}
		})
	}, nil
}

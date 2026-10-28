// Package limit is the rate and concurrency limits on the requests that reach the servers: a
// token bucket and a count of calls in flight for each configured entry, in memory.
package limit

import (
	"fmt"
	"math"
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
	// RetryAfter is when the rule would pass the request again; 0 for a concurrency limit.
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
	if c := s.rule.Concurrency; c > 0 && s.inflight >= c {
		return &Refusal{Rule: s.rule}
	}
	if s.rule.Rate > 0 && s.tokens < 1 {
		wait := time.Duration(math.Ceil((1 - s.tokens) * float64(s.rule.Per) / float64(s.rule.Rate)))
		return &Refusal{Rule: s.rule, RetryAfter: max(wait, time.Millisecond)}
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

// Set puts rules in force, in order. A rule equal to one in force keeps its state; any other
// starts with a full bucket and nothing in flight.
func (l *Limiter) Set(rules []Rule) {
	l.mu.Lock()
	defer l.mu.Unlock()
	old := make(map[Rule]*state, len(l.rules))
	for _, s := range l.rules {
		old[s.rule] = s
	}
	now := l.now()
	next := make([]*state, 0, len(rules))
	for _, r := range rules {
		if s := old[r]; s != nil {
			delete(old, r) // two equal rules get a state each
			next = append(next, s)
			continue
		}
		next = append(next, &state{rule: r, tokens: float64(r.Burst), last: now})
	}
	l.rules = next
}

// Acquire checks a request against every rule that matches it. When all pass, it takes a call
// from each one's bucket and a place in flight, and returns the function that gives the places
// back when the request ends, which may be called more than once. Otherwise it takes nothing and
// returns the refusal of the first rule, in order, that refused.
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
		if ref := s.refuses(); ref != nil {
			return nil, ref
		}
		matched = append(matched, s)
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

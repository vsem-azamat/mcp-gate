package escrow

import (
	"net/netip"
	"sync"
	"time"
)

// The failed-authentication limit: a token bucket per client address. A presented key that is
// wrong spends a token; a client earns one back every failRefill, up to failBurst. A client
// without a token gets 429 for any request, so that a guess that happens to be right is refused
// too. A request that presents no key is refused but costs nothing: it cannot be a guess, and a
// web page can send such requests to a local listener without the owner knowing.
//
// Clients that rotate addresses get a fresh budget with each one, so a global bucket bounds
// them all: every keyed request from a client that has not presented the right key within
// trustedFor spends one of globalBurst tokens, earned back one every globalRefill, and gets it
// back when the key is right. While it is empty, a request that presents a key is refused
// unless its client is trusted, so the owner keeps the addresses it used recently and an
// attacker gets globalBurst guesses plus one per globalRefill, however many addresses it has.
const (
	failBurst  = 20
	failRefill = 3 * time.Second
	// maxClients bounds the addresses tracked. When it is reached, the budget with the most
	// tokens left, the least suspicious one, is forgotten, so that the clients that failed most
	// stay tracked and a client that never failed is never limited.
	maxClients = 4096

	globalBurst  = 100
	globalRefill = time.Second
	// trustedFor is how long a client that presented the right key stays trusted; maxTrusted
	// bounds those kept, dropping the one that authenticated longest ago.
	trustedFor = 24 * time.Hour
	maxTrusted = 256
)

type limiter struct {
	clock   *clock
	mu      sync.Mutex
	budgets map[string]*budget
	global  budget
	// trusted holds when each client last presented the right key.
	trusted map[string]time.Time
}

// budget is a token bucket of failures.
type budget struct {
	tokens float64
	at     time.Time
}

func newLimiter(c *clock) *limiter {
	return &limiter{
		clock: c, budgets: map[string]*budget{}, trusted: map[string]time.Time{},
		global: budget{tokens: globalBurst},
	}
}

// refill brings b, a client's budget, up to now and returns its tokens.
func (b *budget) refill(now time.Time) float64 { return b.refillAt(now, failBurst, failRefill) }

func (b *budget) refillAt(now time.Time, burst float64, every time.Duration) float64 {
	if now.After(b.at) {
		b.tokens = min(burst, b.tokens+float64(now.Sub(b.at))/float64(every))
		b.at = now
	}
	return b.tokens
}

// wait is how long until b, refilled at every, has one token.
func (b *budget) wait(every time.Duration) time.Duration {
	return time.Duration((1 - b.tokens) * float64(every))
}

// isTrusted reports whether the client of key presented the right key within trustedFor.
// The caller holds l.mu.
func (l *limiter) isTrusted(key string, now time.Time) bool {
	at, ok := l.trusted[key]
	return ok && now.Sub(at) < trustedFor
}

// clientKey groups the addresses of one IPv6 /64, which one host usually holds whole.
func clientKey(client string) string {
	a, err := netip.ParseAddr(client)
	if err != nil || a.Unmap().Is4() {
		return client
	}
	p, err := a.Prefix(64)
	if err != nil {
		return client
	}
	return p.String()
}

// allow reports whether client may try now, and if not, how long until it may. withKey says
// whether the request presents a key; one that does not is never refused by the global bucket.
// A keyed request from a client that is not trusted reserves a global token before its key is
// checked, so that concurrent guesses cannot all pass on the same token; reserved reports it,
// and succeed gives it back.
func (l *limiter) allow(client string, withKey bool) (wait time.Duration, reserved, ok bool) {
	now := l.clock.Now()
	key := clientKey(client)
	l.mu.Lock()
	defer l.mu.Unlock()
	if b := l.budgets[key]; b != nil && b.refill(now) < 1 {
		return b.wait(failRefill), false, false
	}
	if !withKey || l.isTrusted(key, now) {
		return 0, false, true
	}
	if l.global.refillAt(now, globalBurst, globalRefill) < 1 {
		return l.global.wait(globalRefill), false, false
	}
	l.global.tokens--
	return 0, true, true
}

// succeed records that client presented the right key, giving back the global token its
// request reserved, if any.
func (l *limiter) succeed(client string, reserved bool) {
	now := l.clock.Now()
	key := clientKey(client)
	l.mu.Lock()
	defer l.mu.Unlock()
	if reserved {
		l.global.tokens = min(globalBurst, l.global.tokens+1)
	}
	if _, ok := l.trusted[key]; !ok && len(l.trusted) >= maxTrusted {
		oldest, first := "", true
		for k, at := range l.trusted {
			if first || at.Before(l.trusted[oldest]) {
				oldest, first = k, false
			}
		}
		delete(l.trusted, oldest)
	}
	l.trusted[key] = now
}

// fail counts a wrong key presented by client; the global token, when the client is not
// trusted, was spent by allow.
func (l *limiter) fail(client string) {
	now := l.clock.Now()
	key := clientKey(client)
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.budgets[key]
	if b == nil {
		if len(l.budgets) >= maxClients {
			// Linear in the table, under the lock, once per wrong key from a new client.
			var fullest string
			most := -1.0
			for k, c := range l.budgets {
				if t := c.refill(now); t > most {
					fullest, most = k, t
				}
			}
			delete(l.budgets, fullest)
		}
		b = &budget{tokens: failBurst, at: now}
		l.budgets[key] = b
	}
	b.refill(now)
	b.tokens = max(0, b.tokens-1)
}

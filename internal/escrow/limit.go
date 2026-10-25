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
const (
	failBurst  = 20
	failRefill = 3 * time.Second
	// maxClients bounds the addresses tracked. When it is reached, the budget with the most
	// tokens left, the least suspicious one, is forgotten, so that the clients that failed most
	// stay tracked and a client that never failed is never limited.
	maxClients = 4096
)

type limiter struct {
	clock   *clock
	mu      sync.Mutex
	budgets map[string]*budget
}

// budget is a token bucket of failures.
type budget struct {
	tokens float64
	at     time.Time
}

func newLimiter(c *clock) *limiter { return &limiter{clock: c, budgets: map[string]*budget{}} }

// refill brings b up to now and returns its tokens.
func (b *budget) refill(now time.Time) float64 {
	b.tokens = min(failBurst, b.tokens+float64(now.Sub(b.at))/float64(failRefill))
	b.at = now
	return b.tokens
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

// allow reports whether client may try now, and if not, how long until it may.
func (l *limiter) allow(client string) (time.Duration, bool) {
	now := l.clock.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.budgets[clientKey(client)]
	if b == nil || b.refill(now) >= 1 {
		return 0, true
	}
	return time.Duration((1 - b.tokens) * float64(failRefill)), false
}

// fail counts a wrong key presented by client.
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

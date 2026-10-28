package escrow

import (
	"net/netip"
	"sync"
	"time"
)

// The failed-authentication limit bounds guessing per client address and sheds the load of
// wrong keys; a key of at least 128 random bits is what makes guessing hopeless.
//
// Each client has a token bucket (failBurst, one more every failRefill) that a presented wrong
// key spends. While it is empty, every request of that client that presents a key gets 429
// before its key is looked at, the right key included, so that guessing from one address is
// bounded however fast it is sent. Whoever shares the owner's address (behind a NAT, or every
// client behind a same-host proxy without listen.behindProxy) can therefore empty the owner's
// bucket too.
//
// A global bucket (globalBurst, one more every globalRefill) is spent by wrong keys from clients
// that have not presented the right key within trustedFor; while it is empty, wrong keys get
// 429 instead of 401. It limits the load of guessing from many addresses and never refuses the
// right key, so it cannot lock anyone out.
//
// A request that presents no key costs nothing: it cannot be a guess, and a web page can send
// such requests to a local listener without the owner knowing.
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

// isTrusted reports whether the client with client key ck presented the right key within
// trustedFor. The caller holds l.mu.
func (l *limiter) isTrusted(ck string, now time.Time) bool {
	at, ok := l.trusted[ck]
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

// succeed records that client presented the right key.
func (l *limiter) succeed(client string) {
	now := l.clock.Now()
	ck := clientKey(client)
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.trusted[ck]; !ok && len(l.trusted) >= maxTrusted {
		oldest, first := "", true
		for k, at := range l.trusted {
			if first || at.Before(l.trusted[oldest]) {
				oldest, first = k, false
			}
		}
		delete(l.trusted, oldest)
	}
	l.trusted[ck] = now
}

// allow reports whether client may present a key now, and if not, how long until it may.
func (l *limiter) allow(client string) (time.Duration, bool) {
	now := l.clock.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if b := l.budgets[clientKey(client)]; b != nil && b.refill(now) < 1 {
		return b.wait(failRefill), false
	}
	return 0, true
}

// fail counts a wrong key presented by client. It reports false, with how long until a wrong
// key is counted again, when the global bucket is empty for a client that is not trusted; the
// client's own bucket is spent either way.
func (l *limiter) fail(client string) (time.Duration, bool) {
	now := l.clock.Now()
	ck := clientKey(client)
	l.mu.Lock()
	defer l.mu.Unlock()
	// The client's bucket is spent first, so a wrong key the global bucket refuses still counts
	// against its address.
	b := l.budgets[ck]
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
		l.budgets[ck] = b
	}
	b.refill(now)
	b.tokens = max(0, b.tokens-1)
	if l.isTrusted(ck, now) {
		return 0, true
	}
	if l.global.refillAt(now, globalBurst, globalRefill) < 1 {
		return l.global.wait(globalRefill), false
	}
	l.global.tokens--
	return 0, true
}

// AuthLimit is the failed-authentication limit above, for another endpoint that takes a secret,
// such as the gate's admin endpoints. It keeps its own buckets.
type AuthLimit struct{ l *limiter }

// NewAuthLimit returns an empty limit.
func NewAuthLimit() *AuthLimit { return &AuthLimit{l: newLimiter(&clock{now: time.Now})} }

// Allow reports whether client may present a secret now, and if not, how long until it may.
func (a *AuthLimit) Allow(client string) (time.Duration, bool) { return a.l.allow(client) }

// Fail counts a wrong secret presented by client; false, with how long until one is counted
// again, refuses it with 429.
func (a *AuthLimit) Fail(client string) (time.Duration, bool) { return a.l.fail(client) }

// Succeed records that client presented the right secret.
func (a *AuthLimit) Succeed(client string) { a.l.succeed(client) }

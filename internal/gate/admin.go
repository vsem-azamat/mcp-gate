package gate

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vsem-azamat/mcp-gate/internal/upstream"
)

// limitAdmin puts the failed-authentication limit of the admin tokens (the escrow's, with buckets
// of its own) in front of next, an admin endpoint: a client that presented too many wrong tokens
// gets 429 before its token is looked at. A request without a token costs nothing, as at the
// escrow.
func (g *Gate) limitAdmin(sn *snapshot, admin *upstream.Tokens, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if strings.TrimSpace(header) == "" {
			next.ServeHTTP(w, r)
			return
		}
		client := sn.remote(r)
		tooMany := func(wait time.Duration) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Retry-After", strconv.Itoa(int((wait+time.Second-1)/time.Second)))
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		}
		if wait, ok := g.adminLimit.Allow(client); !ok {
			tooMany(wait)
			return
		}
		if _, ok := admin.Authenticate(header); !ok {
			if wait, ok := g.adminLimit.Fail(client); !ok {
				tooMany(wait)
				return
			}
			next.ServeHTTP(w, r) // answers 401
			return
		}
		g.adminLimit.Succeed(client)
		next.ServeHTTP(w, r)
	})
}

// Package upstream serves mcp-gate's HTTP listener: the MCP routes behind token checks, the
// health endpoints and the admin status, with limits on every request.
package upstream

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

// Tokens checks secrets against a set of named tokens. Only SHA-256 digests are kept.
type Tokens struct {
	entries []tokenEntry
}

type tokenEntry struct {
	digest [sha256.Size]byte
	name   string
}

// NewTokens returns the token set for byName, a map from token name to secret.
func NewTokens(byName map[string]string) *Tokens {
	t := &Tokens{entries: make([]tokenEntry, 0, len(byName))}
	for name, secret := range byName {
		t.entries = append(t.entries, tokenEntry{digest: sha256.Sum256([]byte(secret)), name: name})
	}
	sort.Slice(t.entries, func(i, j int) bool { return t.entries[i].name < t.entries[j].name })
	return t
}

// lookup returns the name of the token whose secret is secret. Every entry is compared, in
// constant time on fixed-length digests, so the timing tells nothing about which token matched
// or how much of one did.
func (t *Tokens) lookup(secret string) (string, bool) {
	if t == nil || secret == "" {
		return "", false
	}
	d := sha256.Sum256([]byte(secret))
	found := -1
	for i := range t.entries {
		if subtle.ConstantTimeCompare(d[:], t.entries[i].digest[:]) == 1 {
			found = i
		}
	}
	if found < 0 {
		return "", false
	}
	return t.entries[found].name, true
}

// Authenticate returns the name of the token that an Authorization header value carries, as
// "Bearer <token>" (the scheme in any case) or as the bare token. It is the one check of a
// client's credential: a value without a credential, or whose credential holds a space or a tab,
// carries no token.
func (t *Tokens) Authenticate(header string) (principal string, ok bool) {
	secret := credential(header)
	if secret == "" || strings.ContainsAny(secret, " \t") {
		return "", false
	}
	return t.lookup(secret)
}

// credential returns the secret in an Authorization header value: the credentials after a
// "Bearer" scheme, matched without regard to case, or the whole value when it has no scheme.
func credential(header string) string {
	header = strings.TrimSpace(header)
	const scheme = "bearer "
	if len(header) >= len(scheme) && strings.EqualFold(header[:len(scheme)], scheme) {
		header = header[len(scheme):]
	}
	return strings.TrimSpace(header)
}

// Principal returns the token name an MCP request was authorized with, or "" for a server that
// needs no token.
func Principal(info *auth.TokenInfo) string {
	if info == nil {
		return ""
	}
	return info.UserID
}

// RequireToken passes only requests whose Authorization header carries one of tokens (see
// Tokens.Authenticate). Others get 401 with the body "Unauthorized", and rejected, if set, is
// called for each. The token's name reaches MCP handlers as the TokenInfo UserID.
func RequireToken(tokens *Tokens, rejected func(), next http.Handler) http.Handler {
	return Authorize(func(r *http.Request) (context.Context, *auth.TokenInfo, bool) {
		name, ok := tokens.Authenticate(r.Header.Get("Authorization"))
		return r.Context(), &auth.TokenInfo{UserID: name}, ok
	}, rejected, next)
}

// Authorize passes only the requests that check accepts; the others get 401 with the body
// "Unauthorized", and rejected, if set, is called for each. check returns the context the
// request goes on with and the TokenInfo that reaches its MCP handlers (see Principal).
func Authorize(check func(*http.Request) (context.Context, *auth.TokenInfo, bool), rejected func(), next http.Handler) http.Handler {
	type infoKey struct{}
	verify := func(_ context.Context, _ string, r *http.Request) (*auth.TokenInfo, error) {
		info, _ := r.Context().Value(infoKey{}).(*auth.TokenInfo)
		if info == nil {
			return nil, auth.ErrInvalidToken
		}
		return info, nil
	}
	// The SDK middleware puts the TokenInfo where the MCP handlers find it. It only sees
	// requests already checked here, with a header in the form it reads that holds no secret.
	inner := auth.RequireBearerToken(verify, &auth.RequireBearerTokenOptions{AllowMissingExpiration: true})(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, info, ok := check(r)
		if !ok {
			if rejected != nil {
				rejected()
			}
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		r = r.Clone(context.WithValue(ctx, infoKey{}, info)) //nolint:contextcheck // check derives ctx from the request's own
		r.Header.Set("Authorization", "Bearer checked")
		inner.ServeHTTP(w, r)
	})
}

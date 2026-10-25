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

// Lookup returns the name of the token whose secret is secret. Every entry is compared, in
// constant time on fixed-length digests, so the timing tells nothing about which token matched
// or how much of one did.
func (t *Tokens) Lookup(secret string) (string, bool) {
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

// Credential returns the secret in an Authorization header value: the credentials after a
// "Bearer" scheme, matched without regard to case, or the whole value when it has no scheme.
func Credential(header string) string {
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

// RequireToken passes only requests whose Authorization header carries one of tokens, as
// "Bearer <token>" or as the bare token. Others get 401 with the body "Unauthorized". The token's
// name reaches MCP handlers as the TokenInfo UserID.
func RequireToken(tokens *Tokens, next http.Handler) http.Handler {
	verify := func(_ context.Context, secret string, _ *http.Request) (*auth.TokenInfo, error) {
		name, ok := tokens.Lookup(secret)
		if !ok {
			return nil, auth.ErrInvalidToken
		}
		return &auth.TokenInfo{UserID: name}, nil
	}
	// The SDK middleware puts the TokenInfo where the MCP handlers find it. It only sees
	// requests already checked here, with the header in the form it reads.
	inner := auth.RequireBearerToken(verify, &auth.RequireBearerTokenOptions{AllowMissingExpiration: true})(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secret := Credential(r.Header.Get("Authorization"))
		if _, ok := tokens.Lookup(secret); !ok || strings.ContainsAny(secret, " \t") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		r = r.Clone(r.Context())
		r.Header.Set("Authorization", "Bearer "+secret)
		inner.ServeHTTP(w, r)
	})
}

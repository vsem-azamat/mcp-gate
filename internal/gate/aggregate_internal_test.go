package gate

import (
	"maps"
	"testing"

	"github.com/vsem-azamat/mcp-gate/internal/upstream"
)

func TestAccessOfHeader(t *testing.T) {
	a := &aggregate{
		members: []string{"open", "private", "shared", "twin"},
		tokens: map[string]*upstream.Tokens{
			"shared":  upstream.NewTokens(map[string]string{"laptop": "secret-laptop"}),
			"private": upstream.NewTokens(map[string]string{"phone": "secret-phone"}),
			// The same secret under another name: each server names the caller its own way.
			"twin": upstream.NewTokens(map[string]string{"laptop-twin": "secret-laptop"}),
		},
	}
	for _, c := range []struct {
		name    string
		secret  string
		present bool
		want    map[string]string
	}{
		{"no header", "", false, map[string]string{"open": ""}},
		{"laptop", "secret-laptop", true, map[string]string{"open": "", "shared": "laptop", "twin": "laptop-twin"}},
		{"phone", "secret-phone", true, map[string]string{"open": "", "private": "phone"}},
		{"wrong", "secret-wrong", true, nil},
		{"empty", "", true, nil},
		{"with a space", "secret-laptop x", true, nil},
		{"a prefix", "secret-lap", true, nil},
	} {
		got, ok := a.access(c.secret, c.present)
		if ok != (c.want != nil) || !maps.Equal(got, c.want) {
			t.Errorf("%s: access %v %v, want %v", c.name, got, ok, c.want)
		}
	}
	closed := &aggregate{members: []string{"shared"}, tokens: map[string]*upstream.Tokens{"shared": a.tokens["shared"]}}
	if got, ok := closed.access("", false); ok {
		t.Errorf("no public server, no header: %v", got)
	}
	if got := principals(map[string]string{"open": "", "shared": "laptop", "twin": "laptop-twin", "x": "laptop"}); got != "laptop,laptop-twin" {
		t.Errorf("principals %q", got)
	}
}

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
		name   string
		header string
		want   map[string]string
	}{
		{"no header", "", map[string]string{"open": ""}},
		{"laptop", "Bearer secret-laptop", map[string]string{"open": "", "shared": "laptop", "twin": "laptop-twin"}},
		{"bare", "secret-laptop", map[string]string{"open": "", "shared": "laptop", "twin": "laptop-twin"}},
		{"phone", "bearer secret-phone", map[string]string{"open": "", "private": "phone"}},
		{"wrong", "Bearer secret-wrong", nil},
		{"a scheme alone", "Bearer  ", nil},
		{"with a space", "Bearer secret-laptop x", nil},
		{"a prefix", "Bearer secret-lap", nil},
	} {
		got, ok := a.access(c.header)
		if ok != (c.want != nil) || !maps.Equal(got, c.want) {
			t.Errorf("%s: access %v %v, want %v", c.name, got, ok, c.want)
		}
	}
	closed := &aggregate{members: []string{"shared"}, tokens: map[string]*upstream.Tokens{"shared": a.tokens["shared"]}}
	if got, ok := closed.access(""); ok {
		t.Errorf("no public server, no header: %v", got)
	}
	if got := principals(map[string]string{"open": "", "shared": "laptop", "twin": "laptop-twin", "x": "laptop"}); got != "laptop,laptop-twin" {
		t.Errorf("principals %q", got)
	}
}

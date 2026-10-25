package policy

import (
	"testing"

	"github.com/vsem-azamat/mcp-gate/internal/config"
)

func TestFilters(t *testing.T) {
	allow := &config.Filter{Allow: []string{"a", "b"}}
	deny := &config.Filter{Deny: []string{"a"}}
	emptyAllow := &config.Filter{Allow: []string{}}
	emptyDeny := &config.Filter{Deny: []string{}}
	cases := []struct {
		name    string
		f       Filter
		keys    []string
		want    bool
		nothing bool
	}{
		{name: "no tool filter", f: NewToolFilter(nil), keys: []string{"x"}, want: true},
		{name: "no filter", f: NewFilter(nil), keys: []string{"x"}, want: true},
		{name: "allow listed", f: NewFilter(allow), keys: []string{"a"}, want: true},
		{name: "allow other key listed", f: NewFilter(allow), keys: []string{"x", "b"}, want: true},
		{name: "allow unlisted", f: NewFilter(allow), keys: []string{"x"}, want: false},
		{name: "deny listed", f: NewFilter(deny), keys: []string{"a"}, want: false},
		{name: "deny other key listed", f: NewFilter(deny), keys: []string{"x", "a"}, want: false},
		{name: "deny unlisted", f: NewFilter(deny), keys: []string{"x"}, want: true},
		{name: "empty tool allow list filters nothing", f: NewToolFilter(emptyAllow), keys: []string{"x"}, want: true},
		{name: "empty allow list exposes nothing", f: NewFilter(emptyAllow), keys: []string{"x"}, want: false, nothing: true},
		{name: "empty deny list", f: NewFilter(emptyDeny), keys: []string{"x"}, want: true},
	}
	for _, c := range cases {
		if got := c.f.Allows(c.keys...); got != c.want {
			t.Errorf("%s: Allows(%v) = %v, want %v", c.name, c.keys, got, c.want)
		}
		if got := c.f.ExposesNothing(); got != c.nothing {
			t.Errorf("%s: ExposesNothing = %v", c.name, got)
		}
	}
	if !NewFilter(deny).Deny() || NewFilter(allow).Deny() || NewFilter(nil).Deny() {
		t.Error("Deny reports the wrong kind of list")
	}
	if got := NewFilter(allow).Listed(); got != nil {
		t.Errorf("Listed of an allow list = %v", got)
	}
}

func TestNormalizeURI(t *testing.T) {
	for in, want := range map[string]string{
		"test://echo/private":        "test:echo/private",
		"TEST://Echo/Private":        "test:echo/Private",
		"test://echo/%70rivate":      "test:echo/private",
		"test://echo/%2fprivate":     "test:echo/private",
		"test://echo/private#frag":   "test:echo/private",
		"test://echo/private?":       "test:echo/private",
		"test://echo/private?a=1":    "test:echo/private",
		"test://echo/private/":       "test:echo/private",
		"test://echo/private;v=1":    "test:echo/private",
		"test://echo/./private":      "test:echo/private",
		"test://echo//private":       "test:echo/private",
		"test://echo/x/../private":   "test:echo/private",
		"test://echo/x%2F..%2F%70ri": "test:echo/pri",
		"test://echo/private%00":     "test:echo/private",
		"test://echo/private%20":     "test:echo/private",
		"test:///echo/private":       "test:echo/private",
		"test:echo/private":          "test:echo/private",
		"test://echo/%7%30":          "test:echo/p", // decoding formed %70
		"test://echo/%2570":          "test:echo/p",
		"file:///etc/./notes":        "file:etc/notes",
		"file://localhost/etc/notes": "file:etc/notes",
		"file:/etc/notes":            "file:etc/notes",
		"urn:Example:Thing":          "urn:Example:Thing",
		"no-scheme/path":             "no-scheme/path",
		"test://host":                "test:host",
		"test://user@Host:80/x":      "test:host/x",
		"test://host./x":             "test:host/x",
		"test://[::1]:80/x":          "test:[::1]/x",
		"test://[::1]/x":             "test:[::1]/x",
		"":                           "",
		"%":                          "%",
	} {
		if got := NormalizeURI(in); got != want {
			t.Errorf("NormalizeURI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReadAllowed(t *testing.T) {
	deny := New(&config.Server{Resources: &config.Filter{Deny: []string{"fake://listed"}}})
	deny.SetHiddenResources([]string{"fake://hidden"})
	for uri, want := range map[string]bool{
		"fake://listed":      false,
		"FAKE://listed":      false,
		"fake://hidden":      false,
		"fake://%68idden":    false,
		"fake://hidden#x":    false,
		"fake://other":       true,
		"fake://HIDDEN":      false, // the host is not case-sensitive
		"fake://items/one":   true,
		"fake://hidden/":     false,
		"fake://hidden?":     false,
		"fake://./hidden":    false,
		"fake://x/../hidden": false,
		"fake://hidden%2F":   false,
		"fake://hidden;":     false,
	} {
		if got := deny.ReadAllowed(uri); got != want {
			t.Errorf("deny list: ReadAllowed(%q) = %v, want %v", uri, got, want)
		}
	}
	if !New(&config.Server{}).ReadAllowed("fake://anything") {
		t.Error("no filter refuses a read")
	}
	none := New(&config.Server{Resources: &config.Filter{Allow: []string{}}})
	if none.ReadAllowed("fake://anything") {
		t.Error("an empty allow list lets a read through")
	}
	allow := New(&config.Server{Resources: &config.Filter{Allow: []string{"fake://a"}}})
	allow.SetHiddenResources([]string{"fake://b"})
	if !allow.ReadAllowed("fake://b") {
		t.Error("an allow list checks reads against hidden resources; the catalog filter does that")
	}
}

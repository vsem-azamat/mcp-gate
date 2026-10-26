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

func TestTokenPolicies(t *testing.T) {
	cfg := &config.Config{Policies: map[string]*config.TokenPolicy{
		"agent": {Servers: map[string]*config.ServerPolicy{
			"a": {Tools: &config.Filter{Allow: []string{}}, Prompts: &config.Filter{Deny: []string{"p"}}},
			"b": {Resources: &config.Filter{Allow: []string{"items"}}},
		}},
	}}
	a, b := NewTokens(cfg, "a"), NewTokens(cfg, "b")
	if a.For("other") != nil || a.For("") != nil || NewTokens(cfg, "c").For("agent") != nil {
		t.Error("a policy where none is set")
	}
	var none *Token
	if none.Tool("x") != NoPolicy || none.Read("x://y", nil, nil) != NoPolicy {
		t.Error("a nil policy decides")
	}
	p := a.For("agent")
	for _, c := range []struct {
		name      string
		got, want Decision
	}{
		{"an empty tool allow list exposes nothing", p.Tool("echo"), Denied},
		{"prompt denied", p.Prompt("p"), Denied},
		{"prompt passed", p.Prompt("q"), Allowed},
		{"no resource filter", p.Resource("x://y", "y"), Allowed},
		{"template allowed by name", b.For("agent").Resource("x://items/{id}", "items"), Allowed},
		{"tool without a filter", b.For("agent").Tool("echo"), Allowed},
	} {
		if c.got != c.want {
			t.Errorf("%s: %s, want %s", c.name, c.got, c.want)
		}
	}
}

func TestTokenReads(t *testing.T) {
	resources := []Entry{{"fake://info", "info"}, {"fake://hidden", "hidden"}}
	items := Entry{"fake://items/{id}", "items"}
	anyPath := Entry{"fake://{+path}", "any"}
	policy := func(f config.Filter) *Token {
		cfg := &config.Config{Policies: map[string]*config.TokenPolicy{"t": {Servers: map[string]*config.ServerPolicy{"s": {Resources: &f}}}}}
		return NewTokens(cfg, "s").For("t")
	}
	allow := policy(config.Filter{Allow: []string{"fake://info", "items"}})
	deny := policy(config.Filter{Deny: []string{"hidden", "items"}})
	none := policy(config.Filter{Allow: []string{}})
	for _, c := range []struct {
		name     string
		p        *Token
		uri      string
		matching []Entry
		want     Decision
	}{
		{"allowed resource", allow, "fake://info", []Entry{anyPath}, Allowed},
		{"resource not allowed", allow, "fake://hidden", []Entry{anyPath}, Denied},
		{"through an allowed template", allow, "fake://items/7", []Entry{items, anyPath}, Allowed},
		{"through a template not allowed", allow, "fake://other", []Entry{anyPath}, Denied},
		{"nothing matches", allow, "other://x", nil, Denied},
		{"resource denied by name", deny, "fake://hidden", []Entry{anyPath}, Denied},
		{"hidden resource in another spelling", deny, "FAKE:///%68idden/", []Entry{anyPath}, Denied},
		{"through a denied template", deny, "fake://items/7", []Entry{items, anyPath}, Denied},
		{"through a template passed", deny, "fake://other", []Entry{anyPath}, Allowed},
		{"resource passed", deny, "fake://info", []Entry{anyPath}, Allowed},
		{"empty allow list", none, "fake://info", nil, Denied},
	} {
		if got := c.p.Read(c.uri, resources, c.matching); got != c.want {
			t.Errorf("%s: Read(%s) = %s, want %s", c.name, c.uri, got, c.want)
		}
	}
}

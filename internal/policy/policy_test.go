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
	type filter interface {
		Allows(...string) bool
		ExposesNothing() bool
	}
	cases := []struct {
		name    string
		f       filter
		keys    []string
		want    bool
		nothing bool
	}{
		{name: "no tool filter", f: NewServerToolFilter(nil), keys: []string{"x"}, want: true},
		{name: "no filter", f: NewServerFilter(nil), keys: []string{"x"}, want: true},
		{name: "allow listed", f: NewServerFilter(allow), keys: []string{"a"}, want: true},
		{name: "allow other key listed", f: NewServerFilter(allow), keys: []string{"x", "b"}, want: true},
		{name: "allow unlisted", f: NewServerFilter(allow), keys: []string{"x"}, want: false},
		{name: "deny listed", f: NewServerFilter(deny), keys: []string{"a"}, want: false},
		{name: "deny other key listed", f: NewServerFilter(deny), keys: []string{"x", "a"}, want: false},
		{name: "deny unlisted", f: NewServerFilter(deny), keys: []string{"x"}, want: true},
		{name: "empty tool allow list filters nothing", f: NewServerToolFilter(emptyAllow), keys: []string{"x"}, want: true},
		{name: "empty allow list exposes nothing", f: NewServerFilter(emptyAllow), keys: []string{"x"}, want: false, nothing: true},
		{name: "empty deny list", f: NewServerFilter(emptyDeny), keys: []string{"x"}, want: true},
		{name: "no token filter", f: NewTokenFilter(nil), keys: []string{"x"}, want: true},
		{name: "token none", f: NewTokenFilter(&config.PolicyFilter{None: true}), keys: []string{"x"}, want: false, nothing: true},
		{name: "token allow", f: NewTokenFilter(&config.PolicyFilter{Allow: []string{"a"}}), keys: []string{"a"}, want: true},
		{name: "token deny", f: NewTokenFilter(&config.PolicyFilter{Deny: []string{"a"}}), keys: []string{"a"}, want: false},
	}
	for _, c := range cases {
		if got := c.f.Allows(c.keys...); got != c.want {
			t.Errorf("%s: Allows(%v) = %v, want %v", c.name, c.keys, got, c.want)
		}
		if got := c.f.ExposesNothing(); got != c.nothing {
			t.Errorf("%s: ExposesNothing = %v", c.name, got)
		}
	}
	if !NewServerFilter(deny).Deny() || NewServerFilter(allow).Deny() || NewServerFilter(nil).Deny() {
		t.Error("Deny reports the wrong kind of list")
	}
	if got := NewServerFilter(allow).Listed(); got != nil {
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
	deny := New(&config.Server{Resources: &config.Filter{Deny: []string{"fake://listed", "hidden", "secret"}}})
	deny.SetCatalog([]Entry{{"fake://hidden", "hidden"}, {"fake://ok", "ok"}}, []Entry{{"fake://{+path}", "any"}, {"fake://secret/{id}", "secret"}})
	for uri, want := range map[string]bool{
		"fake://listed":      false,
		"FAKE://listed":      false,
		"fake://hidden":      false,
		"fake://%68idden":    false,
		"fake://hidden#x":    false,
		"fake://other":       true,
		"fake://ok":          true,
		"fake://HIDDEN":      false, // the host is not case-sensitive
		"fake://items/one":   true,
		"fake://hidden/":     false,
		"fake://hidden?":     false,
		"fake://./hidden":    false,
		"fake://x/../hidden": false,
		"fake://hidden%2F":   false,
		"fake://hidden;":     false,
		"fake://secret/7":    false, // a hidden template matches it
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
	allow := New(&config.Server{Resources: &config.Filter{Allow: []string{"fake://a", "any"}}})
	allow.SetCatalog([]Entry{{"fake://a", "a"}, {"fake://b", "b"}}, []Entry{{"fake://{+path}", "any"}, {"other://{id}", "other"}})
	for uri, want := range map[string]bool{
		"fake://a": true, "fake://b": false, "FAKE://%62": false, "fake://c": true, "other://1": false, "none://x": false,
	} {
		if got := allow.ReadAllowed(uri); got != want {
			t.Errorf("allow list: ReadAllowed(%q) = %v, want %v", uri, got, want)
		}
	}
}

// Under an allow list, a hidden resource with a query refuses the reads whose query holds all
// of its parameters, however written, and passes other queries; one without a query refuses
// every query. Under a deny list every query of a hidden URI is refused.
func TestReadQueries(t *testing.T) {
	resources := []Entry{{"db://t?id=1", "one"}, {"fake://hidden", "hidden"}}
	templates := []Entry{{"db://t{?id}", "rows"}, {"db://{+path}", "db"}, {"fake://{+path}", "any"}}
	allow := New(&config.Server{Resources: &config.Filter{Allow: []string{"rows", "db", "any"}}})
	allow.SetCatalog(resources, templates)
	deny := New(&config.Server{Resources: &config.Filter{Deny: []string{"one"}}})
	deny.SetCatalog(resources, templates)
	refused := []string{
		"db://t?id=1", "DB://t?id=%31", "db://t?id=1&", "db://t?&id=1", "db://t?id=1&id=1", "db://t?x=&id=1",
		"db://t?id=1&x=y", "db://t?id=1;", "db://t?ID=1", "db://t?id=01", "db://t?id=+1", "db://t/?id=1#x",
		"fake://hidden", "fake://hidden?a=b", "FAKE://%68idden?", "fake://hidden/?x",
	}
	for _, uri := range refused {
		if allow.ReadAllowed(uri) {
			t.Errorf("allow list: %s is read", uri)
		}
	}
	for _, uri := range []string{"db://t?id=2", "db://t", "db://t?id=10", "db://t?x=1", "fake://other?a=b"} {
		if !allow.ReadAllowed(uri) {
			t.Errorf("allow list: %s is refused", uri)
		}
	}
	for _, uri := range []string{"db://t?id=2", "db://t", "db://t?id=1"} {
		if deny.ReadAllowed(uri) {
			t.Errorf("deny list: %s is read", uri)
		}
	}
}

func TestTokenPolicies(t *testing.T) {
	cfg := &config.Config{Policies: map[string]*config.TokenPolicy{
		"agent": {Servers: map[string]*config.ServerPolicy{
			"a": {Tools: &config.PolicyFilter{None: true}, Prompts: &config.PolicyFilter{Deny: []string{"p"}}},
			"b": {Resources: &config.PolicyFilter{Allow: []string{"items"}}},
		}},
	}}
	a, b := NewTokens(cfg, "a"), NewTokens(cfg, "b")
	if a.For("other") != nil || a.For("") != nil || NewTokens(cfg, "c").For("agent") != nil {
		t.Error("a policy where none is set")
	}
	p := a.For("agent")
	if p.Tools.Allows("echo") || p.Prompts.Allows("p") || !p.Prompts.Allows("q") || !p.Resources.Allows("x://y", "y") {
		t.Error("agent's filters on a")
	}
	if q := b.For("agent"); !q.Resources.Allows("x://items/{id}", "items") || !q.Tools.Allows("echo") {
		t.Error("agent's filters on b")
	}
	if DecisionOf(true) != Allowed || DecisionOf(false) != Denied {
		t.Error("DecisionOf")
	}
}

func TestTokenReads(t *testing.T) {
	resources := []Entry{{"fake://info", "info"}, {"fake://hidden", "hidden"}}
	templates := []Entry{{"fake://items/{id}", "items"}, {"fake://{+path}", "any"}}
	reads := func(f config.PolicyFilter) *Reads {
		cfg := &config.Config{Policies: map[string]*config.TokenPolicy{"t": {Servers: map[string]*config.ServerPolicy{"s": {Resources: &f}}}}}
		return NewTokens(cfg, "s").For("t").Reads(resources, templates)
	}
	allow := reads(config.PolicyFilter{Allow: []string{"fake://info", "items"}})
	anyTemplate := reads(config.PolicyFilter{Allow: []string{"any"}})
	deny := reads(config.PolicyFilter{Deny: []string{"hidden", "items"}})
	none := reads(config.PolicyFilter{None: true})
	for _, c := range []struct {
		name string
		r    *Reads
		uri  string
		want bool
	}{
		{"allowed resource", allow, "fake://info", true},
		{"resource not allowed", allow, "fake://hidden", false},
		{"through an allowed template", allow, "fake://items/7", true},
		{"through a template not allowed", allow, "fake://other", false},
		{"nothing matches", allow, "other://x", false},
		{"hidden resource in another spelling through an allowed template", anyTemplate, "FAKE://%68idden", false},
		{"hidden resource with a query through an allowed template", anyTemplate, "fake://hidden?a=b", false},
		{"resource through an allowed template", anyTemplate, "fake://other", true},
		{"resource denied by name", deny, "fake://hidden", false},
		{"hidden resource in another spelling", deny, "FAKE:///%68idden/", false},
		{"through a denied template", deny, "fake://items/7", false},
		{"through a template passed", deny, "fake://other", true},
		{"resource passed", deny, "fake://info", true},
		{"none", none, "fake://info", false},
	} {
		if got := c.r.Allowed(c.uri); got != c.want {
			t.Errorf("%s: Allowed(%s) = %v, want %v", c.name, c.uri, got, c.want)
		}
	}
}

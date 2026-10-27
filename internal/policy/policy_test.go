package policy

import (
	"strings"
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
		// Invisible characters are removed from the path, and Unicode spaces around a segment.
		"test://echo/pri%E2%80%8Bvate":        "test:echo/private",
		"test://echo/private\u200b":           "test:echo/private",
		"test://ec%EF%BB%BFho/private":        "test:echo/private",
		"test://echo/pri%CD%8Fvate%EF%B8%8F":  "test:echo/private",
		"test://echo/%E3%85%A4private":        "test:echo/private",
		"test://echo/%C2%A0private%E2%80%83":  "test:echo/private",
		"test://echo/x/.%E2%80%8B./private":   "test:echo/private",
		"test://echo/%E2%80%8B/private":       "test:echo/private",
		"te%E2%80%8Bst://echo/private":        "test:echo/private",
		"test://%E2%80%8B..%E2%80%8B/private": "test:private",
		// Visible characters are kept, encoded or not.
		"test://echo/caf%C3%A9":          "test:echo/café",
		"test://echo/café":               "test:echo/café",
		"test://echo/%E6%96%87%E6%A1%A3": "test:echo/文档",
		"test://echo/a%20b":              "test:echo/a b",
		"test://echo/%F0%9F%98%80":       "test:echo/😀",
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
	allow.SetCatalog([]Entry{{"fake://a", "a"}, {"fake://b", "b"}, {"fake://docs/secret", "secret"}}, []Entry{{"fake://{+path}", "any"}, {"other://{id}", "other"}})
	for uri, want := range map[string]bool{
		"fake://a": true, "fake://b": false, "FAKE://%62": false, "fake://c": true, "other://1": false, "none://x": false,
		// Invisible characters in the path of a hidden resource do not reach it.
		"fake://%E2%80%8Bb": false, "fake://b%E2%80%8B": false, "fake://b%EF%BB%BF": false,
		"fake://b%E2%81%A0": false, "fake://b%CD%8F": false, "fake://b%EF%B8%8F": false, "fake://b%C2%A0": false,
		"fake://docs/se%E2%80%8Ccret": false, "fake://docs%E2%80%8B/secret": false, "fake://docs/%E2%80%8B/secret": false,
		"fake://x/.%E2%80%8B./docs/secret": false, "fake://docs/secret%E2%80%8B?a=1": false,
		// Visible characters, encoded or not, name other resources.
		"fake://caf%C3%A9": true, "fake://b%C3%A9": true, "fake://%E6%96%87%E6%A1%A3": true,
		"fake://docs/secret2": true, "fake://docs/se%20cret": true, "fake://%F0%9F%91%A8%E2%80%8D%F0%9F%91%A9": true,
		"fake://b%E2%80%8Bc": true,
		// The authority rules apply again once invisible characters are gone.
		"fake://b.%E2%80%8B": false, "fake://b.%C2%A0": false, "fake://localhost%E2%80%8B/docs/secret": false,
		"fake://localhost%E2%80%8B/c": true,
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
	resources := []Entry{{"db://t?id=1", "one"}, {"db://f?flag", "flag"}, {"fake://hidden", "hidden"}}
	templates := []Entry{{"db://t{?id}", "rows"}, {"db://{+path}", "db"}, {"fake://{+path}", "any"}}
	allow := New(&config.Server{Resources: &config.Filter{Allow: []string{"rows", "db", "any"}}})
	allow.SetCatalog(resources, templates)
	deny := New(&config.Server{Resources: &config.Filter{Deny: []string{"one"}}})
	deny.SetCatalog(resources, templates)
	refused := []string{
		"db://t?id=1", "DB://t?id=%31", "db://t?id=1&", "db://t?&id=1", "db://t?id=1&id=1", "db://t?x=&id=1",
		"db://t?id=1&x=y", "db://t?id=1;", "db://t?ID=1", "db://t?id=01", "db://t?id=+1", "db://t/?id=1#x",
		"fake://hidden", "fake://hidden?a=b", "FAKE://%68idden?", "fake://hidden/?x",
		// A ";" parameter of the path counts as a query parameter.
		"db://t;id=1", "db://t;x=y;id=1", "db://t/;id=1", "db://t;id=1?x=2", "db://t%3Bid=1",
		// A "[...]" suffix of a key is dropped.
		"db://t?id[]=1", "db://t?id%5B%5D=1", "db://t?id[0]=1", "db://t;id[]=1",
		// A number is compared in its canonical form.
		"db://t?id=1.0", "db://t?id=1.", "db://t?id=0x1", "db://t?id=0X01", "db://t?id=0o1", "db://t?id=0b1",
		"db://t?id=1e0", "db://t?id=10e-1", "db://t?id=%2B1", "db://t?id=0x1p0", "db://t?id=1_",
		"db://t?id=" + strings.Repeat("0", 300) + "1." + strings.Repeat("0", 300),
		// "=" around a value is trimmed.
		"db://t?id==1", "db://t?id=1=", "db://t?id===1",
		// Format characters are removed and Unicode spaces trimmed.
		"db://t?id=%E2%80%8B1", "db://t?id=1%E2%80%8B", "db://t?i%E2%80%8Bd=1", "db://t?id=%EF%BB%BF1",
		"db://t?id=%C2%A01", "db://t?id=%E2%80%831", "db://t?id=%011",
		// So are variation selectors and the other default ignorable code points.
		"db://t?i%CD%8Fd=1%EF%B8%8F", "db://t?id=%E3%85%A41", "db://t?id=0x%EF%B8%801",
		// A hidden parameter without a value is held by the key with any value.
		"db://f?flag", "db://f?flag=", "db://f?flag=1", "db://f?FLAG=yes", "db://f;flag=1", "db://f?flag[]=1", "db://f?x=1&flag",
	}
	for _, uri := range refused {
		if allow.ReadAllowed(uri) {
			t.Errorf("allow list: %s is read", uri)
		}
	}
	for _, uri := range []string{
		"db://t?id=2", "db://t", "db://t?id=10", "db://t?id=12", "db://t?x=1", "fake://other?a=b",
		"db://t;x=1", "db://t;id=2", "db://t?id[]=2", "db://t?id=1.5", "db://t?id=0x2", "db://t?id=1e1",
		"db://t?id==2", "db://t?id=%E2%80%8B2", "db://t?xid=1", "db://t?i=1", "db://t?id=1x",
		"db://t?id=" + strings.Repeat("1", 200), "db://f", "db://f?other=1", "db://f?flagx=1",
	} {
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

// TestReadQueryKeySuffix checks that a key whose "[...]" suffix starts after an invisible
// character is cut as before the other invisible characters were removed, so that a read refused
// before is still refused.
func TestReadQueryKeySuffix(t *testing.T) {
	allow := New(&config.Server{Resources: &config.Filter{Allow: []string{"db"}}})
	allow.SetCatalog([]Entry{{"db://t?%EF%B8%8F[]=1", "a"}, {"db://u?%CD%8F[x]=1", "b"}}, []Entry{{"db://{+path}", "db"}})
	for _, uri := range []string{"db://t?%EF%B8%8F=1", "db://t?%EF%B8%8F[]=1", "db://u?%CD%8F[y]=1", "db://u?%CD%8F=1"} {
		if allow.ReadAllowed(uri) {
			t.Errorf("%s is read", uri)
		}
	}
}

// TestQueryParams checks which values queryParams compares alike: the values of a group share a
// form, and no two groups do.
func TestQueryParams(t *testing.T) {
	groups := [][]string{
		{"1", "01", "1.0", "1.", "0x1", "0X01", "0o1", "0b1", "1e0", "10e-1", "+1", "%2B1", "0x1p0", "1_", "%E2%80%8B==1", "1%E2%80%8B", "%011"},
		{"10", "0xa", "1e1", "1%090", "1 0", "010.000"},
		{"0", "-0", "0.000", "0x0", "00"},
		{"2"},
		{"12"},
		{"1.5"},
		{"-1"},
		{"abc"},
		{"inf"},
		{"00inf"},
		{"e5"},
		{"."},
		{"0x"},
		{strings.Repeat("9", 200), strings.Repeat("0", 10) + strings.Repeat("9", 200)},
		// Large exponents stay cheap, since the canonical form is binary.
		{"1e-300000000"},
		{"1e600000000"},
		{"0x1p-2000000000"},
	}
	value := func(v string) string {
		vs := queryParams("x://a?id=" + v)["id"]
		if len(vs) != 1 {
			t.Fatalf("queryParams(id=%s) = %q", v, vs)
		}
		return vs[0]
	}
	group := map[string]int{}
	for i, g := range groups {
		for _, v := range g {
			got := value(v)
			if j, ok := group[got]; ok && j != i {
				t.Errorf("%q (group %d) reads as group %d", v, i, j)
			}
			if first := value(g[0]); got != first {
				t.Errorf("%q reads as %q, %q as %q", v, got, g[0], first)
			}
			group[got] = i
		}
	}
	got := queryParams("x://a?a[b]=X&flag&ID%E2%80%8B[]=2")
	if len(got) != 3 || got["a"][0] != "x" || got["flag"][0] != "" || len(got["id"]) != 1 {
		t.Errorf("queryParams of keys = %v", got)
	}
	if got := readParams("x://a;id=1/b;k=2?q=3"); len(got) != 3 || got["id"][0] != value("1") || got["k"][0] != value("2") || got["q"][0] != value("3") {
		t.Errorf("readParams = %v", got)
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

// FuzzNormalizeURIOnlyMerges checks that the removal of invisible characters only merges keys:
// the key of a URI depends only on its key before the removal (the decoded URI without query,
// normalizeDecoded), so URIs that shared a key still share one and no read refused by its key
// before is passed. A key before the removal is itself a URI with that same key, which gives a
// second URI to compare with.
func FuzzNormalizeURIOnlyMerges(f *testing.F) {
	for _, seed := range []string{
		"fake://x/%E2%80%8B/../b", "fake://hid%E2%80%8Bden", "fake://a/.%E2%80%8B./b", "/a:b",
		"te%E2%80%8Bst://x", "/te%E2%80%8Bst:x", "fake://%C2%A0/../x", "test://user@Host:80/x;v=1?q#f",
	} {
		f.Add(seed)
	}
	before := func(raw string) string {
		raw, _, _ = strings.Cut(decodeAll(raw), "?")
		return normalizeDecoded(raw)
	}
	f.Fuzz(func(t *testing.T, uri string) {
		key := before(uri)
		if before(key) != key {
			return // the key does not read back as itself; nothing to compare with
		}
		if got, want := NormalizeURI(uri), NormalizeURI(key); got != want {
			t.Errorf("%q and %q share the key %q before invisible characters are removed, but not after: %q, %q", uri, key, key, got, want)
		}
	})
}

package gate

import (
	"reflect"
	"strings"
	"testing"

	"github.com/vsem-azamat/mcp-gate/internal/config"
)

// classified checks that table classifies every field of t, reached by path from prefix, and
// returns the paths it saw. A struct field is classified either as a whole or field by field.
func classified(t *testing.T, typ reflect.Type, prefix string, table map[string]fieldClass, seen map[string]bool) {
	t.Helper()
	for f := range typ.Fields() {
		path := prefix + f.Name
		if _, ok := table[path]; ok {
			seen[path] = true
			continue
		}
		ft := f.Type
		if ft.Kind() == reflect.Struct && hasPrefix(table, path+".") {
			classified(t, ft, path+".", table, seen)
			continue
		}
		t.Errorf("%s is not classified: say what a reload does when it changes", path)
	}
}

func hasPrefix(table map[string]fieldClass, prefix string) bool {
	for path := range table {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// TestFieldsClassified fails on a config field that configFields or serverFields leave out, and
// on an entry that names no field.
func TestFieldsClassified(t *testing.T) {
	for _, c := range []struct {
		typ   reflect.Type
		table map[string]fieldClass
	}{
		{reflect.TypeFor[config.Config](), configFields},
		{reflect.TypeFor[config.Server](), serverFields},
	} {
		seen := map[string]bool{}
		classified(t, c.typ, "", c.table, seen)
		for path := range c.table {
			if !seen[path] {
				t.Errorf("%s.%s is classified but is no field", c.typ.Name(), path)
			}
		}
	}
}

// TestKeys checks the keys a reload compares: a change of a downstream setting changes the
// downstream key only, one of the policy the mirror key only.
func TestKeys(t *testing.T) {
	cfg := &config.Config{Name: "gate"}
	s := &config.Server{Stdio: &config.Stdio{Command: "a"}}
	d, m := downstreamKey(cfg, s), mirrorKey(cfg, "s", s)
	s2 := *s
	s2.Stdio = &config.Stdio{Command: "b"}
	if reflect.DeepEqual(d, downstreamKey(cfg, &s2)) || !reflect.DeepEqual(m, mirrorKey(cfg, "s", &s2)) {
		t.Error("a changed command")
	}
	s3 := *s
	s3.Tools = &config.Filter{Deny: []string{"x"}}
	if !reflect.DeepEqual(d, downstreamKey(cfg, &s3)) || reflect.DeepEqual(m, mirrorKey(cfg, "s", &s3)) {
		t.Error("a changed filter")
	}
	if !reflect.DeepEqual(d, downstreamKey(cfg, s)) {
		t.Error("the same server")
	}
	if got := bootChanges(cfg, &config.Config{Name: "gate", Listen: config.Listen{Addr: "127.0.0.1:1"}}); len(got) != 1 || got[0] != "Listen.Addr" {
		t.Errorf("boot changes %v", got)
	}
}

// TestPolicyKey checks that a token policy on one server changes that server's mirror key only.
func TestPolicyKey(t *testing.T) {
	s := &config.Server{Stdio: &config.Stdio{Command: "a"}}
	none := &config.Config{}
	on := func(server string) *config.Config {
		return &config.Config{Policies: map[string]*config.TokenPolicy{"phone": {Servers: map[string]*config.ServerPolicy{
			server: {Tools: &config.PolicyFilter{Allow: []string{"echo"}}},
		}}}}
	}
	if reflect.DeepEqual(mirrorKey(none, "a", s), mirrorKey(on("a"), "a", s)) {
		t.Error("a policy on the server left its mirror key alone")
	}
	if !reflect.DeepEqual(mirrorKey(none, "b", s), mirrorKey(on("a"), "b", s)) {
		t.Error("a policy on another server changed the mirror key")
	}
}

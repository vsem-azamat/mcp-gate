package gate

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/vsem-azamat/mcp-gate/internal/config"
)

// fieldClass says what a reload does when a config field changes. Every field of config.Config and
// config.Server is classified below; a test fails on a field that is not.
type fieldClass uint8

const (
	// downstreamField is a setting the server's supervisor is built from: a change restarts the
	// server.
	downstreamField fieldClass = 1 << iota
	// mirrorField is a setting the server's mirror is built from (its policy, redaction, file
	// scanning, forwarded _meta): a change replaces the mirror, which ends the listen streams of
	// its routes; the server keeps running.
	mirrorField
	// routeField is a setting of the routes (tokens, request logging, Host and proxy checks, the
	// aggregate endpoint): a change of a config-wide one replaces every route, of a server's one
	// the routes that serve the server, which ends their listen streams. The route keys are read
	// from this table (routeKey), so classifying a field here is all a route needs.
	routeField
	// snapshotField is applied in place without touching a route: the log level, the health
	// endpoints, /_status, /_metrics on the listener, the limits.
	snapshotField
	// bootField keeps its value from the start; a reload that changes it logs a warning.
	bootField
	// derivedField is set while the config is loaded, not written in the file.
	derivedField
)

// configFields classifies the fields of config.Config, by path; a struct field whose own fields
// are classified one by one is written as a prefix of their paths. Servers are classified by
// serverFields.
var configFields = map[string]fieldClass{
	"Version":                bootField,
	"FileRootsUnchecked":     derivedField,
	"Name":                   downstreamField | routeField | snapshotField,
	"Listen.Addr":            bootField,
	"Listen.BehindProxy":     routeField,
	"Listen.TrustedProxies":  routeField,
	"Listen.AllowedHosts":    routeField,
	"StartupGracePeriod":     bootField,
	"LogLevel":               snapshotField,
	"Auth":                   routeField,
	"Admin":                  snapshotField,
	"Metrics.Enabled":        snapshotField,
	"Metrics.Addr":           bootField,
	"Escrow.TTL":             mirrorField, // the default of every server's redact.escrowTTL
	"Escrow.MaxEntries":      bootField,
	"Escrow.KeyHash":         bootField,
	"Escrow.KeyHashFile":     bootField,
	"Escrow.SourceArguments": bootField,
	"Escrow.KeyHashVars":     derivedField,
	"Escrow.TCP":             bootField,
	"Escrow.Socket":          bootField,
	"Warnings":               derivedField,
	"Aggregate":              routeField,
	"Policies":               mirrorField,   // each server's mirror takes the token policies on it
	"Limits":                 snapshotField, // set on the gate's limiter, which keeps the buckets of unchanged entries
	"Servers":                0,             // see serverFields
}

// serverFields classifies the fields of config.Server.
var serverFields = map[string]fieldClass{
	"Stdio":           downstreamField,
	"HTTP":            downstreamField,
	"CallTimeout":     downstreamField,
	"MaxMessageBytes": downstreamField | mirrorField,
	"ProtocolVersion": downstreamField,
	"ProbeInterval":   downstreamField,
	"Restart":         downstreamField,
	"Disabled":        downstreamField, // enables or disables the server
	"Tools":           mirrorField,
	"Prompts":         mirrorField,
	"Resources":       mirrorField,
	"Redact":          mirrorField,
	"ForwardMeta":     mirrorField,
	"ToolPins":        mirrorField,
	"Auth":            routeField,
	"Log":             routeField,
	"Transport":       derivedField,
}

// pick returns the values of the fields of v (a config.Config or config.Server) that table gives
// class, by path, for comparing two configs.
func pick(v any, table map[string]fieldClass, class fieldClass) map[string]any {
	out := map[string]any{}
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Pointer {
		rv = rv.Elem()
	}
	for path, c := range table {
		if c&class == 0 {
			continue
		}
		f := rv
		for name := range strings.SplitSeq(path, ".") {
			f = f.FieldByName(name)
		}
		out[path] = f.Interface()
	}
	return out
}

// downstreamKey is what a server's supervisor is built from.
func downstreamKey(cfg *config.Config, s *config.Server) map[string]any {
	k := pick(s, serverFields, downstreamField)
	for path, v := range pick(cfg, configFields, downstreamField) {
		k["config."+path] = v
	}
	return k
}

// mirrorKey is what the mirror of the server named name is built from, besides its supervisor:
// of the token policies, those on the server.
func mirrorKey(cfg *config.Config, name string, s *config.Server) map[string]any {
	k := pick(s, serverFields, mirrorField)
	for path, v := range pick(cfg, configFields, mirrorField) {
		k["config."+path] = v
	}
	policies := map[string]*config.ServerPolicy{}
	for token := range cfg.Policies {
		if p := cfg.ServerPolicy(token, name); p != nil {
			policies[token] = p
		}
	}
	k["config.Policies"] = policies
	return k
}

// bootChanges returns the paths of the boot fields that differ between two configs.
func bootChanges(a, b *config.Config) []string {
	pa, pb := pick(a, configFields, bootField), pick(b, configFields, bootField)
	var out []string
	for path, v := range pa {
		if !reflect.DeepEqual(v, pb[path]) {
			out = append(out, path)
		}
	}
	return out
}

// routeKey is what a route is built from besides its mirrors: every route setting of the config
// and of the servers it serves. A route whose key and mirrors are unchanged is kept.
func routeKey(cfg *config.Config, servers ...*config.Server) map[string]any {
	k := map[string]any{}
	for path, v := range pick(cfg, configFields, routeField) {
		k["config."+path] = v
	}
	for i, s := range servers {
		for path, v := range pick(s, serverFields, routeField) {
			k[fmt.Sprintf("server%d.%s", i, path)] = v
		}
	}
	return k
}

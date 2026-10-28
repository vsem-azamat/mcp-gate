// Package metrics counts what the gate does and writes the counts in the Prometheus text
// exposition format (version 0.0.4). The counts come from the audit records of the requests
// (Registry is an audit.Sink) and from hooks the gate calls: restarts, reloads and refused
// tokens. What is read at a scrape (the servers' states, the escrow) is passed to Expose. A
// Registry lives as long as the process, so a reload does not reset it.
package metrics

import (
	"bytes"
	"cmp"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/vsem-azamat/mcp-gate/internal/audit"
)

// ContentType is the media type of the exposition.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// MaxNames is how many distinct tool or prompt names of one server get a series of their own;
// the others, like names not in the server's catalog, are counted under Other.
const MaxNames = 100

// Other is the name label of a tool or prompt that is not in the server's catalog or past
// MaxNames. MCP tool names do not hold parentheses.
const Other = "(other)"

// buckets are the upper bounds, in seconds, of the duration histogram.
var buckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300}

// Escrow route label of the escrow API's refusals.
const escrowRoute = "/_escrow/"

// Registry holds the counts. Its methods are safe for concurrent use. Write and the hooks hold
// the lock for a map update; Expose holds it while it copies the counts, which takes time
// proportional to the number of series.
type Registry struct {
	mu         sync.Mutex
	requests   map[requestKey]uint64
	durations  map[entryKey]*histogram
	redactions map[string]uint64
	restarts   map[string]uint64
	reloads    map[string]uint64
	rejected   map[string]uint64
	names      map[scope]map[string]bool // the names with a series of their own
}

// scope is a server and a kind, which the name cap counts within.
type scope struct {
	server string
	kind   audit.Kind
}

type entryKey struct {
	server, kind, name string
}

type requestKey struct {
	entryKey
	token, outcome string
}

type histogram struct {
	counts []uint64 // per bucket, not cumulative; the last is +Inf
	sum    float64
	count  uint64
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{
		requests: map[requestKey]uint64{}, durations: map[entryKey]*histogram{}, redactions: map[string]uint64{},
		restarts: map[string]uint64{}, reloads: map[string]uint64{}, rejected: map[string]uint64{},
		names: map[scope]map[string]bool{},
	}
}

// Write counts an audit record; Registry is an audit.Sink.
func (r *Registry) Write(rec audit.Record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := entryKey{server: rec.Server, kind: rec.Kind.String(), name: r.nameLocked(rec)}
	r.requests[requestKey{entryKey: e, token: rec.Principal, outcome: string(rec.Outcome)}]++
	h := r.durations[e]
	if h == nil {
		h = &histogram{counts: make([]uint64, len(buckets)+1)}
		r.durations[e] = h
	}
	secs := rec.Duration.Seconds()
	i, _ := slices.BinarySearch(buckets, secs)
	h.counts[i]++
	h.sum += secs
	h.count++
	if rec.Redactions > 0 {
		r.redactions[rec.Server] += uint64(rec.Redactions)
	}
}

// nameLocked returns the name label of a record: the name of a listed tool or prompt within the
// cap, Other for any other tool or prompt, empty for a resource read.
func (r *Registry) nameLocked(rec audit.Record) string {
	if rec.Kind == audit.Resource {
		return ""
	}
	if !rec.Listed {
		return Other
	}
	sc := scope{rec.Server, rec.Kind}
	set := r.names[sc]
	if set[rec.Name] {
		return rec.Name
	}
	if len(set) >= MaxNames {
		return Other
	}
	if set == nil {
		set = map[string]bool{}
		r.names[sc] = set
	}
	set[rec.Name] = true
	return rec.Name
}

// Restarted counts a connection attempt of a server's supervisor after its first.
func (r *Registry) Restarted(server string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.restarts[server]++
}

// Reloaded counts a reload that applied its config (ok) or did not.
func (r *Registry) Reloaded(ok bool) {
	result := "failure"
	if ok {
		result = "success"
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reloads[result]++
}

// Rejected counts a request to route refused with 401 for want of an accepted token.
func (r *Registry) Rejected(route string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rejected[route]++
}

// State is what a scrape reads from the gate as it is now.
type State struct {
	Version string
	// States are every state a server can be in, in order.
	States []string
	// Servers are the enabled servers, sorted, with the state each is in.
	Servers []Server
	// Escrow is nil when the escrow is off.
	Escrow *Escrow
}

// Server is an enabled server and its supervisor's state.
type Server struct {
	Name, State string
}

// Escrow is what the escrow reports.
type Escrow struct {
	Entries      int
	Stored       uint64
	AuthFailures uint64
}

// counts is a copy of a registry's counts.
type counts struct {
	requests                                map[requestKey]uint64
	durations                               map[entryKey]histogram
	redactions, restarts, reloads, rejected map[string]uint64
}

// snapshot copies the counts under the lock, which every request takes; sorting and rendering
// happen after it is released.
func (r *Registry) snapshot() counts {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := counts{
		requests: maps.Clone(r.requests), durations: make(map[entryKey]histogram, len(r.durations)),
		redactions: maps.Clone(r.redactions), restarts: maps.Clone(r.restarts),
		reloads: maps.Clone(r.reloads), rejected: maps.Clone(r.rejected),
	}
	for k, h := range r.durations {
		c.durations[k] = histogram{counts: slices.Clone(h.counts), sum: h.sum, count: h.count}
	}
	return c
}

// Expose writes the metrics and st to w in the text exposition format, families and series in a
// fixed order. The counts are copied under the registry's lock and rendered into memory after
// it, so neither the rendering nor a slow reader holds up the requests.
func (r *Registry) Expose(w io.Writer, st State) error {
	c := r.snapshot()
	e := &encoder{}
	e.family("mcp_gate_build_info", "gauge", "The version of the running mcp-gate.")
	e.sample("mcp_gate_build_info", labels{{"version", st.Version}}, "1")

	e.family("mcp_gate_requests_total", "counter", "Tool calls, prompt gets and resource reads, by server, kind, entry name, token name and outcome.")
	for _, k := range sortedKeys(c.requests, compareRequest) {
		e.sample("mcp_gate_requests_total", append(k.labels(), label{"token", k.token}, label{"outcome", k.outcome}), formatUint(c.requests[k]))
	}

	e.family("mcp_gate_request_duration_seconds", "histogram", "Duration of tool calls, prompt gets and resource reads.")
	for _, k := range sortedKeys(c.durations, compareEntry) {
		h := c.durations[k]
		var cum uint64
		for i, c := range h.counts {
			cum += c
			le := "+Inf"
			if i < len(buckets) {
				le = formatFloat(buckets[i])
			}
			e.sample("mcp_gate_request_duration_seconds_bucket", append(k.labels(), label{"le", le}), formatUint(cum))
		}
		e.sample("mcp_gate_request_duration_seconds_sum", k.labels(), formatFloat(h.sum))
		e.sample("mcp_gate_request_duration_seconds_count", k.labels(), formatUint(h.count))
	}

	e.family("mcp_gate_redactions_total", "counter", "Findings replaced and files withheld in results.")
	e.byLabel("mcp_gate_redactions_total", "server", c.redactions)

	e.family("mcp_gate_downstream_restarts_total", "counter", "Connection attempts of downstream servers after the first.")
	e.byLabel("mcp_gate_downstream_restarts_total", "server", c.restarts)

	e.family("mcp_gate_downstream_state", "gauge", "The state of each enabled downstream server: 1 for the state it is in.")
	for _, s := range st.Servers {
		for _, state := range st.States {
			v := "0"
			if state == s.State {
				v = "1"
			}
			e.sample("mcp_gate_downstream_state", labels{{"server", s.Name}, {"state", state}}, v)
		}
	}

	if st.Escrow != nil {
		e.family("mcp_gate_escrow_entries", "gauge", "Entries the secret escrow holds.")
		e.sample("mcp_gate_escrow_entries", nil, strconv.Itoa(st.Escrow.Entries))
		e.family("mcp_gate_escrow_stored_total", "counter", "Entries the secret escrow stored under a new handle.")
		e.sample("mcp_gate_escrow_stored_total", nil, formatUint(st.Escrow.Stored))
	}

	e.family("mcp_gate_reloads_total", "counter", "Config reloads, by result.")
	e.byLabel("mcp_gate_reloads_total", "result", c.reloads)

	rejected := c.rejected
	if st.Escrow != nil && st.Escrow.AuthFailures > 0 {
		rejected[escrowRoute] += st.Escrow.AuthFailures
	}
	e.family("mcp_gate_auth_failures_total", "counter", "Requests refused with 401 for want of an accepted token, by route.")
	e.byLabel("mcp_gate_auth_failures_total", "route", rejected)
	_, err := e.buf.WriteTo(w)
	return err
}

func (k entryKey) labels() labels {
	return labels{{"server", k.server}, {"kind", k.kind}, {"name", k.name}}
}

func compareEntry(a, b entryKey) int {
	return cmp.Or(strings.Compare(a.server, b.server), strings.Compare(a.kind, b.kind), strings.Compare(a.name, b.name))
}

func compareRequest(a, b requestKey) int {
	return cmp.Or(compareEntry(a.entryKey, b.entryKey), strings.Compare(a.token, b.token), strings.Compare(a.outcome, b.outcome))
}

func sortedKeys[K comparable, V any](m map[K]V, compare func(a, b K) int) []K {
	return slices.SortedFunc(maps.Keys(m), compare)
}

type label struct{ name, value string }

type labels []label

// encoder renders the exposition into memory.
type encoder struct {
	buf bytes.Buffer
}

func (e *encoder) write(s string) { e.buf.WriteString(s) }

func (e *encoder) family(name, typ, help string) {
	e.write("# HELP " + name + " " + help + "\n# TYPE " + name + " " + typ + "\n")
}

// sample writes one series with its value as written.
func (e *encoder) sample(name string, ls labels, value string) {
	var b strings.Builder
	b.WriteString(name)
	if len(ls) > 0 {
		b.WriteByte('{')
		for i, l := range ls {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(l.name + `="` + escape(l.value) + `"`)
		}
		b.WriteByte('}')
	}
	b.WriteByte(' ')
	b.WriteString(value)
	b.WriteByte('\n')
	e.write(b.String())
}

// byLabel writes one series per key of m, sorted, under the label name.
func (e *encoder) byLabel(family, name string, m map[string]uint64) {
	for _, k := range slices.Sorted(maps.Keys(m)) {
		e.sample(family, labels{{name, k}}, formatUint(m[k]))
	}
}

// escape escapes a label value: backslash, double quote and line feed.
func escape(s string) string {
	if !strings.ContainsAny(s, "\\\"\n") {
		return s
	}
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

func formatUint(n uint64) string { return strconv.FormatUint(n, 10) }

func formatFloat(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }

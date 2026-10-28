package metrics_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vsem-azamat/mcp-gate/internal/audit"
	"github.com/vsem-azamat/mcp-gate/internal/metrics"
)

func expose(t *testing.T, r *metrics.Registry, st metrics.State) string {
	t.Helper()
	var b strings.Builder
	if err := r.Expose(&b, st); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestExposeGolden(t *testing.T) {
	r := metrics.New()
	r.Write(audit.Record{
		Server: "server-a", Principal: "laptop", Kind: audit.Tool, Name: "echo", Listed: true,
		Duration: 30 * time.Millisecond, Outcome: audit.OK, Redactions: 2,
	})
	r.Write(audit.Record{
		Server: "server-a", Principal: "laptop", Kind: audit.Tool, Name: "secret-name", Outcome: audit.Denied,
	})
	r.Write(audit.Record{Server: "server-a", Kind: audit.Resource, Name: "fake://x", Listed: true, Duration: 2 * time.Second, Outcome: audit.Error})
	r.Write(audit.Record{Principal: "laptop,phone", Kind: audit.Prompt, Name: "p", Outcome: audit.Denied})
	r.Restarted("server-a")
	r.Reloaded(true)
	r.Reloaded(false)
	r.Reloaded(true)
	r.Rejected("/server-a/mcp")
	got := expose(t, r, metrics.State{
		Version: "1.2.3",
		States:  []string{"starting", "ready"},
		Servers: []metrics.Server{{Name: "server-a", State: "ready"}},
		Escrow:  &metrics.Escrow{Entries: 3, Stored: 5, AuthFailures: 1},
	})
	want := `# HELP mcp_gate_build_info The version of the running mcp-gate.
# TYPE mcp_gate_build_info gauge
mcp_gate_build_info{version="1.2.3"} 1
# HELP mcp_gate_requests_total Tool calls, prompt gets and resource reads, by server, kind, entry name, token name and outcome.
# TYPE mcp_gate_requests_total counter
mcp_gate_requests_total{server="",kind="prompt",name="(other)",token="laptop,phone",outcome="denied"} 1
mcp_gate_requests_total{server="server-a",kind="resource",name="",token="",outcome="error"} 1
mcp_gate_requests_total{server="server-a",kind="tool",name="(other)",token="laptop",outcome="denied"} 1
mcp_gate_requests_total{server="server-a",kind="tool",name="echo",token="laptop",outcome="ok"} 1
# HELP mcp_gate_request_duration_seconds Duration of tool calls, prompt gets and resource reads.
# TYPE mcp_gate_request_duration_seconds histogram
mcp_gate_request_duration_seconds_bucket{server="",kind="prompt",name="(other)",le="0.005"} 1
mcp_gate_request_duration_seconds_bucket{server="",kind="prompt",name="(other)",le="0.01"} 1
mcp_gate_request_duration_seconds_bucket{server="",kind="prompt",name="(other)",le="0.025"} 1
mcp_gate_request_duration_seconds_bucket{server="",kind="prompt",name="(other)",le="0.05"} 1
mcp_gate_request_duration_seconds_bucket{server="",kind="prompt",name="(other)",le="0.1"} 1
mcp_gate_request_duration_seconds_bucket{server="",kind="prompt",name="(other)",le="0.25"} 1
mcp_gate_request_duration_seconds_bucket{server="",kind="prompt",name="(other)",le="0.5"} 1
mcp_gate_request_duration_seconds_bucket{server="",kind="prompt",name="(other)",le="1"} 1
mcp_gate_request_duration_seconds_bucket{server="",kind="prompt",name="(other)",le="2.5"} 1
mcp_gate_request_duration_seconds_bucket{server="",kind="prompt",name="(other)",le="5"} 1
mcp_gate_request_duration_seconds_bucket{server="",kind="prompt",name="(other)",le="10"} 1
mcp_gate_request_duration_seconds_bucket{server="",kind="prompt",name="(other)",le="30"} 1
mcp_gate_request_duration_seconds_bucket{server="",kind="prompt",name="(other)",le="60"} 1
mcp_gate_request_duration_seconds_bucket{server="",kind="prompt",name="(other)",le="120"} 1
mcp_gate_request_duration_seconds_bucket{server="",kind="prompt",name="(other)",le="300"} 1
mcp_gate_request_duration_seconds_bucket{server="",kind="prompt",name="(other)",le="+Inf"} 1
mcp_gate_request_duration_seconds_sum{server="",kind="prompt",name="(other)"} 0
mcp_gate_request_duration_seconds_count{server="",kind="prompt",name="(other)"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="resource",name="",le="0.005"} 0
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="resource",name="",le="0.01"} 0
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="resource",name="",le="0.025"} 0
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="resource",name="",le="0.05"} 0
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="resource",name="",le="0.1"} 0
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="resource",name="",le="0.25"} 0
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="resource",name="",le="0.5"} 0
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="resource",name="",le="1"} 0
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="resource",name="",le="2.5"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="resource",name="",le="5"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="resource",name="",le="10"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="resource",name="",le="30"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="resource",name="",le="60"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="resource",name="",le="120"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="resource",name="",le="300"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="resource",name="",le="+Inf"} 1
mcp_gate_request_duration_seconds_sum{server="server-a",kind="resource",name=""} 2
mcp_gate_request_duration_seconds_count{server="server-a",kind="resource",name=""} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="(other)",le="0.005"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="(other)",le="0.01"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="(other)",le="0.025"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="(other)",le="0.05"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="(other)",le="0.1"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="(other)",le="0.25"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="(other)",le="0.5"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="(other)",le="1"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="(other)",le="2.5"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="(other)",le="5"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="(other)",le="10"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="(other)",le="30"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="(other)",le="60"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="(other)",le="120"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="(other)",le="300"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="(other)",le="+Inf"} 1
mcp_gate_request_duration_seconds_sum{server="server-a",kind="tool",name="(other)"} 0
mcp_gate_request_duration_seconds_count{server="server-a",kind="tool",name="(other)"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="echo",le="0.005"} 0
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="echo",le="0.01"} 0
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="echo",le="0.025"} 0
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="echo",le="0.05"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="echo",le="0.1"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="echo",le="0.25"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="echo",le="0.5"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="echo",le="1"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="echo",le="2.5"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="echo",le="5"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="echo",le="10"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="echo",le="30"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="echo",le="60"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="echo",le="120"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="echo",le="300"} 1
mcp_gate_request_duration_seconds_bucket{server="server-a",kind="tool",name="echo",le="+Inf"} 1
mcp_gate_request_duration_seconds_sum{server="server-a",kind="tool",name="echo"} 0.03
mcp_gate_request_duration_seconds_count{server="server-a",kind="tool",name="echo"} 1
# HELP mcp_gate_redactions_total Findings replaced and files withheld in results.
# TYPE mcp_gate_redactions_total counter
mcp_gate_redactions_total{server="server-a"} 2
# HELP mcp_gate_downstream_restarts_total Connection attempts of downstream servers after the first.
# TYPE mcp_gate_downstream_restarts_total counter
mcp_gate_downstream_restarts_total{server="server-a"} 1
# HELP mcp_gate_downstream_state The state of each enabled downstream server: 1 for the state it is in.
# TYPE mcp_gate_downstream_state gauge
mcp_gate_downstream_state{server="server-a",state="starting"} 0
mcp_gate_downstream_state{server="server-a",state="ready"} 1
# HELP mcp_gate_escrow_entries Entries the secret escrow holds.
# TYPE mcp_gate_escrow_entries gauge
mcp_gate_escrow_entries 3
# HELP mcp_gate_escrow_stored_total Entries the secret escrow stored under a new handle.
# TYPE mcp_gate_escrow_stored_total counter
mcp_gate_escrow_stored_total 5
# HELP mcp_gate_reloads_total Config reloads, by result.
# TYPE mcp_gate_reloads_total counter
mcp_gate_reloads_total{result="failure"} 1
mcp_gate_reloads_total{result="success"} 2
# HELP mcp_gate_auth_failures_total Requests refused with 401 for want of an accepted token, by route.
# TYPE mcp_gate_auth_failures_total counter
mcp_gate_auth_failures_total{route="/_escrow/"} 1
mcp_gate_auth_failures_total{route="/server-a/mcp"} 1
`
	if got != want {
		t.Errorf("exposition:\n%s\ndiff from want at line %d", got, firstDiff(got, want))
	}
	if strings.Contains(got, "secret-name") || strings.Contains(got, "fake://x") {
		t.Error("an unlisted name or a URI reached the exposition")
	}
}

func firstDiff(a, b string) int {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := range min(len(al), len(bl)) {
		if al[i] != bl[i] {
			return i + 1
		}
	}
	return min(len(al), len(bl)) + 1
}

func TestEmptyFamiliesAndNoEscrow(t *testing.T) {
	got := expose(t, metrics.New(), metrics.State{Version: "v"})
	for _, absent := range []string{"mcp_gate_escrow_entries", "mcp_gate_escrow_stored_total"} {
		if strings.Contains(got, absent) {
			t.Errorf("%s served with the escrow off", absent)
		}
	}
	// Families with no series keep their HELP and TYPE, so a scraper sees them from the start.
	for _, family := range []string{"mcp_gate_requests_total", "mcp_gate_reloads_total", "mcp_gate_auth_failures_total"} {
		if !strings.Contains(got, "# TYPE "+family+" counter\n") {
			t.Errorf("%s missing", family)
		}
	}
}

func TestNameCap(t *testing.T) {
	r := metrics.New()
	for i := range metrics.MaxNames + 5 {
		r.Write(audit.Record{Server: "s", Kind: audit.Tool, Name: fmt.Sprintf("t%d", i), Listed: true, Outcome: audit.OK})
	}
	// A name counted before the cap keeps its series.
	r.Write(audit.Record{Server: "s", Kind: audit.Tool, Name: "t0", Listed: true, Outcome: audit.OK})
	// Another server and kind have their own budget.
	r.Write(audit.Record{Server: "s", Kind: audit.Prompt, Name: "p", Listed: true, Outcome: audit.OK})
	got := expose(t, r, metrics.State{})
	if !strings.Contains(got, `mcp_gate_requests_total{server="s",kind="tool",name="t0",token="",outcome="ok"} 2`) {
		t.Error("t0 not counted twice")
	}
	if strings.Contains(got, fmt.Sprintf(`name="t%d"`, metrics.MaxNames)) {
		t.Error("a name past the cap has its own series")
	}
	if !strings.Contains(got, `mcp_gate_requests_total{server="s",kind="tool",name="(other)",token="",outcome="ok"} 5`) {
		t.Error("names past the cap not counted as (other)")
	}
	if !strings.Contains(got, `mcp_gate_requests_total{server="s",kind="prompt",name="p",token="",outcome="ok"} 1`) {
		t.Error("prompt not counted")
	}
}

func TestEscaping(t *testing.T) {
	r := metrics.New()
	r.Write(audit.Record{Server: "s", Kind: audit.Tool, Name: "a\"b\\c\nd", Listed: true, Outcome: audit.OK})
	got := expose(t, r, metrics.State{})
	if !strings.Contains(got, `name="a\"b\\c\nd"`) {
		t.Errorf("label not escaped:\n%s", got)
	}
}

// TestExposeWhileWriting runs scrapes alongside requests, for the race detector.
func TestExposeWhileWriting(t *testing.T) {
	r := metrics.New()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 1000 {
			r.Write(audit.Record{Server: "s", Kind: audit.Tool, Name: fmt.Sprintf("t%d", i%10), Listed: true, Outcome: audit.OK})
		}
	}()
	for range 20 {
		expose(t, r, metrics.State{})
	}
	<-done
	if got := expose(t, r, metrics.State{}); !strings.Contains(got, `name="t0",token="",outcome="ok"} 100`) {
		t.Error("lost counts")
	}
}

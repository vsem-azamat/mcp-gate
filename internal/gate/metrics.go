package gate

import (
	"net/http"

	"github.com/vsem-azamat/mcp-gate/internal/downstream"
	"github.com/vsem-azamat/mcp-gate/internal/metrics"
)

// metricsRoute is the path of the metrics, on the listener and on metrics.addr.
const metricsRoute = "/_metrics"

// metricsHandler serves the metrics in the text exposition format, without a token check: on
// the listener it sits behind upstream.RequireAdmin, on metrics.addr behind the loopback address.
func (g *Gate) metricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", metrics.ContentType)
		if r.Method == http.MethodHead {
			return
		}
		_ = g.metrics.Expose(w, g.metricsState())
	})
}

// metricsState is what a scrape reads from the gate as it is now: the enabled servers of the
// current snapshot with their states, and the escrow's counts.
func (g *Gate) metricsState() metrics.State {
	sn := g.snap.Load()
	st := metrics.State{Version: g.opts.Version, States: make([]string, 0, len(downstream.States))}
	for _, s := range downstream.States {
		st.States = append(st.States, s.String())
	}
	for _, name := range sn.names {
		st.Servers = append(st.Servers, metrics.Server{Name: name, State: sn.servers[name].sup.Status().State.String()})
	}
	if g.escrow != nil {
		es := g.escrow.Stats()
		st.Escrow = &metrics.Escrow{Entries: es.Entries, Stored: es.Stored, AuthFailures: es.AuthFailures}
	}
	return st
}

// rejected returns the hook that counts the requests to route refused for want of a token.
func (g *Gate) rejected(route string) func() {
	return func() { g.metrics.Rejected(route) }
}

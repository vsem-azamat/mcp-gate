package upstream

import (
	"encoding/json"
	"net/http"
)

// HealthInfo is the fixed part of the /_healthz and /_readyz body.
type HealthInfo struct {
	Name    string
	Version string
	// ServerCount is the number of enabled servers.
	ServerCount int
}

// Readiness is what /_readyz reports about the servers.
type Readiness struct {
	// Started is false until every enabled server has connected once or the startup grace
	// period has passed.
	Started bool
	// Mounted counts the servers that connected once and so serve their route.
	Mounted int
	// Unhealthy names, sorted, the mounted servers that lost their connection.
	Unhealthy []string
	// NeedsLogin names, sorted, the servers waiting for an OAuth login, mounted or not.
	NeedsLogin []string
}

type healthBody struct {
	Name        string   `json:"name"`
	ServerCount int      `json:"serverCount"`
	Status      string   `json:"status"`
	Unhealthy   []string `json:"unhealthy,omitempty"`
	NeedsLogin  []string `json:"needsLogin,omitempty"`
	Version     string   `json:"version"`
}

// HealthHandler serves /_healthz (readiness nil) or /_readyz. GET gets a JSON body, HEAD only the
// status; it is registered for GET, so the mux answers other methods with 405. /_healthz is 200
// while the process serves. /_readyz is 503 "initializing" before startup completes, 503
// "degraded" with the unhealthy servers named, 503 "unavailable" when servers are enabled but
// none is mounted, 503 "degraded" while a server waits for an OAuth login, and 200 "ok"
// otherwise. The servers waiting for a login are named in every answer after startup.
func HealthHandler(info HealthInfo, readiness func() Readiness) http.HandlerFunc {
	base := healthBody{Name: info.Name, ServerCount: info.ServerCount, Status: "ok", Version: info.Version}
	return func(w http.ResponseWriter, r *http.Request) {
		code, body := http.StatusOK, base
		if readiness != nil {
			rep := readiness()
			if rep.Started {
				body.NeedsLogin = rep.NeedsLogin
			}
			switch {
			case !rep.Started:
				code, body.Status = http.StatusServiceUnavailable, "initializing"
			case len(rep.Unhealthy) > 0:
				code, body.Status, body.Unhealthy = http.StatusServiceUnavailable, "degraded", rep.Unhealthy
			case rep.Mounted == 0 && info.ServerCount > 0:
				code, body.Status = http.StatusServiceUnavailable, "unavailable"
			case len(rep.NeedsLogin) > 0:
				code, body.Status = http.StatusServiceUnavailable, "degraded"
			}
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(code)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(body)
	}
}

// StatusHandler serves /_status to callers holding an admin token, as "Bearer <token>" or the
// bare token, with the JSON encoding of what status returns. Others get 401.
func StatusHandler(admin *Tokens, status func() any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if _, ok := admin.Lookup(Credential(r.Header.Get("Authorization"))); !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodHead {
			return
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(status())
	}
}

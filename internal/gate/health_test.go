package gate_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/vsem-azamat/mcp-gate/internal/downstream"
	"github.com/vsem-azamat/mcp-gate/internal/gate"
	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

// waitFor polls cond for up to 10 s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestHealthAndReadiness(t *testing.T) {
	flaky := testkit.NewFakeHTTP(t, testkit.Fake{}, testkit.FakeHTTPOptions{})
	r := startGate(t, configDoc("name: hub\nstartupGracePeriod: 1s\nadmin:\n  tokens: {owner: \"${ADMIN}\"}\n", map[string]string{
		"good":  stdioServer(t, testkit.Fake{}, ""),
		"flaky": httpServer(flaky.URL(), "probeInterval: 1s\n"),
		"bad":   stdioServer(t, testkit.Fake{ExitAtStart: 1}, ""),
		"off":   stdioServer(t, testkit.Fake{}, "disabled: true\n"),
	}), gateOpts{tune: func(o *downstream.Options) {
		o.ProbeInterval, o.ProbeTimeout, o.ProbeFailures = 50*time.Millisecond, 50*time.Millisecond, 1
	}})
	const prefix = `{"name":"hub","serverCount":3,"status":`
	if code, _, body := r.get(t, http.MethodGet, "/_readyz", ""); code != 503 || body != prefix+`"initializing","version":"test"}`+"\n" {
		t.Errorf("readyz while starting: %d %q", code, body)
	}
	if code, _, body := r.get(t, http.MethodGet, "/_healthz", ""); code != 200 || body != prefix+`"ok","version":"test"}`+"\n" {
		t.Errorf("healthz: %d %q", code, body)
	}
	code, hdr, body := r.get(t, http.MethodPost, "/bad/mcp", "Bearer "+laptopToken)
	if code != 503 || hdr.Get("Retry-After") != "5" {
		t.Errorf("route before connect: %d %q %q", code, hdr.Get("Retry-After"), body)
	}
	if code, _, _ := r.get(t, http.MethodPost, "/bad/mcp", ""); code != 401 {
		t.Errorf("route before connect without a token: %d", code)
	}
	waitFor(t, "ready after the grace period", func() bool {
		code, _, body := r.get(t, http.MethodGet, "/_readyz", "")
		return code == 200 && body == prefix+`"ok","version":"test"}`+"\n"
	})
	if code, _, body := r.get(t, http.MethodHead, "/_readyz", ""); code != 200 || body != "" {
		t.Errorf("HEAD readyz: %d %q", code, body)
	}
	if code, _, _ := r.get(t, http.MethodPost, "/_healthz", ""); code != 405 {
		t.Errorf("POST healthz: %d", code)
	}

	flaky.SetDown(true)
	waitFor(t, "degraded", func() bool {
		code, _, body := r.get(t, http.MethodGet, "/_readyz", "")
		return code == 503 && body == prefix+`"degraded","unhealthy":["flaky"],"version":"test"}`+"\n"
	})
	flaky.SetDown(false)
	waitFor(t, "recovered", func() bool {
		code, _, _ := r.get(t, http.MethodGet, "/_readyz", "")
		return code == 200
	})

	for path, want := range map[string]int{
		"/good/mcp": 405, "/good/": 404, "/good/mcp/": 404, "/good": 404, "/off/mcp": 404, "/nope/mcp": 404,
	} {
		if code, _, _ := r.get(t, http.MethodGet, path, "Bearer "+laptopToken); code != want {
			t.Errorf("GET %s: %d, want %d", path, code, want)
		}
	}

	for _, h := range []string{"", "Bearer " + laptopToken, "Bearer wrong"} {
		if code, _, _ := r.get(t, http.MethodGet, "/_status", h); code != 401 {
			t.Errorf("status with %q: %d", h, code)
		}
	}
	code, hdr, body = r.get(t, http.MethodGet, "/_status", "Bearer "+adminToken)
	if code != 200 || hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("status: %d %v", code, hdr)
	}
	var st gate.Status
	if err := json.Unmarshal([]byte(body), &st); err != nil {
		t.Fatal(err)
	}
	if g := st.Servers["good"]; g.State != "ready" || !g.Mounted || g.Tools == 0 || g.PID == 0 || g.ProtocolVersion == "" {
		t.Errorf("good: %+v", g)
	}
	if b := st.Servers["bad"]; b.Mounted || b.LastError == "" {
		t.Errorf("bad: %+v", b)
	}
	if _, ok := st.Servers["off"]; ok || !st.Started {
		t.Errorf("status: %+v", st)
	}
}

func TestUnavailable(t *testing.T) {
	r := startGate(t, configDoc("startupGracePeriod: 200ms\n", map[string]string{
		"bad": stdioServer(t, testkit.Fake{ExitAtStart: 1}, ""),
	}), gateOpts{})
	waitFor(t, "unavailable", func() bool {
		code, _, body := r.get(t, http.MethodGet, "/_readyz", "")
		return code == 503 && body == `{"name":"mcp-gate","serverCount":1,"status":"unavailable","version":"test"}`+"\n"
	})
	if code, _, _ := r.get(t, http.MethodGet, "/_status", "Bearer "+adminToken); code != 404 {
		t.Errorf("status without admin tokens: %d", code)
	}
}

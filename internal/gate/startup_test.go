package gate_test

import (
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/systemd"
	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

// states records the notifications a gate sends.
type states struct {
	mu   sync.Mutex
	list []string
}

func (s *states) add(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.list = append(s.list, state)
}

func (s *states) get() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.list)
}

// TestCallDuringStartup checks that a request that arrives while its server is still starting,
// as after a restart, is held until the server is up rather than refused, and that the gate
// reports READY=1 once startup is over and STOPPING=1 when it shuts down.
func TestCallDuringStartup(t *testing.T) {
	var notified states
	r := startGate(t, configDoc("startupGracePeriod: 20s\n", map[string]string{
		"slow": stdioServer(t, testkit.Fake{StartDelay: 700 * time.Millisecond}, ""),
	}), gateOpts{notify: notified.add})
	if got := notified.get(); len(got) != 0 {
		t.Errorf("notified %v before startup was over", got)
	}
	begun := time.Now()
	cs := r.connect(t, "slow", clientOpts{})
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "hi"}})
	if err != nil || res.IsError || textOf(t, res) != "hi" {
		t.Fatalf("call during startup: %+v, %v", res, err)
	}
	if took := time.Since(begun); took < 300*time.Millisecond {
		t.Errorf("the first request took %s: it was not held while the server started", took)
	}
	waitFor(t, "READY=1", func() bool { return slices.Equal(notified.get(), []string{systemd.Ready}) })
	r.stop()
	if got := notified.get(); !slices.Equal(got, []string{systemd.Ready, systemd.Stopping}) {
		t.Errorf("notifications = %v", got)
	}
}

// TestHeldRequestEndsWithStartup checks that a request held for a server that does not come up
// gets 503 once the startup grace period is over, not later.
func TestHeldRequestEndsWithStartup(t *testing.T) {
	r := startGate(t, configDoc("startupGracePeriod: 500ms\n", map[string]string{
		"bad": stdioServer(t, testkit.Fake{ExitAtStart: 1}, ""),
	}), gateOpts{})
	begun := time.Now()
	code, hdr, _ := r.get(t, http.MethodPost, "/bad/mcp", "Bearer "+laptopToken)
	if code != http.StatusServiceUnavailable || hdr.Get("Retry-After") != "5" {
		t.Errorf("held request: %d %q", code, hdr.Get("Retry-After"))
	}
	if took := time.Since(begun); took > 5*time.Second {
		t.Errorf("the held request took %s", took)
	}
	// After startup a request is refused at once.
	begun = time.Now()
	if code, _, _ := r.get(t, http.MethodPost, "/bad/mcp", "Bearer "+laptopToken); code != http.StatusServiceUnavailable {
		t.Errorf("after startup: %d", code)
	}
	if took := time.Since(begun); took > time.Second {
		t.Errorf("a request after startup took %s", took)
	}
}

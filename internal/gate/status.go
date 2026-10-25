package gate

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vsem-azamat/mcp-gate/internal/downstream"
)

// stderrTail is how many lines of a child's stderr /_status shows for a server that is not
// ready.
const stderrTail = 20

// Status is what /_status serves.
type Status struct {
	Name    string                  `json:"name"`
	Version string                  `json:"version"`
	Started bool                    `json:"started"`
	Servers map[string]ServerStatus `json:"servers"`
}

// ServerStatus describes one enabled server.
type ServerStatus struct {
	State           string `json:"state"`
	Mounted         bool   `json:"mounted"`
	ProtocolVersion string `json:"protocolVersion,omitempty"`
	AutoPinned      bool   `json:"autoPinned,omitempty"`
	LearnedPin      string `json:"learnedPin,omitempty"`
	Sessions        int    `json:"sessions"`
	Restarts        int    `json:"restarts"`
	LastError       string `json:"lastError,omitempty"`
	LastErrorAt     string `json:"lastErrorAt,omitempty"`
	PID             int    `json:"pid,omitempty"`
	RSSBytes        int64  `json:"rssBytes,omitempty"`
	// Stderr is the end of the child's stderr, shown while the server is not ready.
	Stderr               []string `json:"stderr,omitempty"`
	Tools                int      `json:"tools"`
	Prompts              int      `json:"prompts"`
	Resources            int      `json:"resources"`
	ResourceTemplates    int      `json:"resourceTemplates"`
	LastSync             string   `json:"lastSync,omitempty"`
	Calls                int64    `json:"calls"`
	FailedCalls          int64    `json:"failedCalls"`
	DroppedNotifications int64    `json:"droppedNotifications"`
}

// Status returns the state of every enabled server.
func (g *Gate) Status() Status {
	out := Status{Name: g.cfg.Name, Version: g.opts.Version, Started: g.started.Load(), Servers: map[string]ServerStatus{}}
	for _, name := range g.names {
		s := g.servers[name]
		st := s.sup.Status()
		ms := s.mirror.Stats()
		ss := ServerStatus{
			State: st.State.String(), Mounted: ms.Ready, ProtocolVersion: st.ProtocolVersion,
			AutoPinned: st.AutoPinned, LearnedPin: st.LearnedPin, Sessions: st.Sessions, Restarts: st.Restarts,
			LastError: st.LastError, LastErrorAt: stamp(st.LastErrorAt), PID: st.PID, RSSBytes: rss(st.PID),
			Tools: ms.Tools, Prompts: ms.Prompts, Resources: ms.Resources, ResourceTemplates: ms.Templates,
			LastSync: stamp(ms.LastSync), Calls: ms.Calls, FailedCalls: ms.Failed, DroppedNotifications: ms.DroppedNotifications,
		}
		if st.State != downstream.Ready && len(st.Stderr) > 0 {
			ss.Stderr = st.Stderr[max(0, len(st.Stderr)-stderrTail):]
		}
		out.Servers[name] = ss
	}
	return out
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// rss returns the resident set size of a process from /proc, or 0 where that is not available.
func rss(pid int) int64 {
	if pid <= 0 {
		return 0
	}
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/statm")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0
	}
	pages, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return pages * int64(os.Getpagesize())
}

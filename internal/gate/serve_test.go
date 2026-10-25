package gate_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

func TestAuth(t *testing.T) {
	f := testkit.Fake{}
	r := startGate(t, configDoc("", map[string]string{
		"shared":  stdioServer(t, f, ""),
		"private": stdioServer(t, f, "auth:\n  inherit: false\n  tokens: {phone: \"${PHONE}\"}\n"),
		"open":    stdioServer(t, f, "auth: {public: true}\n"),
	}), gateOpts{})
	for _, s := range []string{"shared", "private", "open"} {
		r.waitReady(t, s)
	}
	cases := []struct {
		server, header string
		noHeader, ok   bool
	}{
		{server: "shared", header: "Bearer " + laptopToken, ok: true},
		{server: "shared", header: "bearer " + laptopToken, ok: true},
		{server: "shared", header: laptopToken, ok: true},
		{server: "shared", header: "Bearer " + phoneToken},
		{server: "shared", header: "Bearer wrong"},
		{server: "shared", noHeader: true},
		{server: "private", header: "Bearer " + laptopToken},
		{server: "private", header: "Bearer " + phoneToken, ok: true},
		{server: "open", noHeader: true, ok: true},
	}
	for _, c := range cases {
		cs, err := r.dial(t, c.server, clientOpts{header: c.header, noHeader: c.noHeader})
		if c.ok != (err == nil) {
			t.Errorf("%s with %q: err = %v, want ok %v", c.server, c.header, err, c.ok)
			continue
		}
		if err == nil {
			if _, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "x"}}); err != nil {
				t.Errorf("%s: call: %v", c.server, err)
			}
		}
	}
	code, _, body := r.get(t, http.MethodPost, "/shared/mcp", "Bearer wrong")
	if code != 401 || body != "Unauthorized\n" {
		t.Errorf("wrong token: %d %q", code, body)
	}
	principals := map[string]bool{}
	for _, l := range r.logs.lines("call") {
		server, _ := l["server"].(string)
		principal, _ := l["principal"].(string)
		principals[server+"/"+principal] = true
	}
	for _, want := range []string{"shared/laptop", "private/phone", "open/"} {
		if !principals[want] {
			t.Errorf("no audit line for %s; have %v", want, principals)
		}
	}
}

func TestProgressGoesToItsCall(t *testing.T) {
	r := startGate(t, configDoc("", map[string]string{"s": stdioServer(t, testkit.Fake{}, "")}), gateOpts{})
	r.waitReady(t, "s")
	var wg sync.WaitGroup
	for i, v := range []string{"2025-11-25", "2026-07-28", "2025-03-26"} {
		wg.Go(func() {
			token := "tok-" + v
			var mu sync.Mutex
			var got []*mcp.ProgressNotificationParams
			cs := r.connect(t, "s", clientOpts{version: v, progress: func(req *mcp.ProgressNotificationClientRequest) {
				mu.Lock()
				got = append(got, req.Params)
				mu.Unlock()
			}})
			params := &mcp.CallToolParams{Name: "progress", Arguments: map[string]any{"steps": 3 + i, "ms": 20}}
			params.SetProgressToken(token)
			if _, err := cs.CallTool(t.Context(), params); err != nil {
				t.Errorf("%s: %v", v, err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if len(got) == 0 {
				t.Errorf("%s: no progress", v)
			}
			for _, p := range got {
				if p.ProgressToken != token || !strings.HasPrefix(p.Message, "step ") {
					t.Errorf("%s: progress %+v", v, p)
				}
			}
		})
	}
	wg.Wait()
}

func TestForwardMeta(t *testing.T) {
	f := testkit.Fake{ProtocolVersions: []string{"2025-11-25"}}
	url := testkit.NewFakeHTTP(t, f, testkit.FakeHTTPOptions{}).URL()
	r := startGate(t, configDoc("", map[string]string{
		"listed":   httpServer(url, "forwardMeta: [example.com/trace]\n"),
		"unlisted": httpServer(url, ""),
	}), gateOpts{})
	for _, name := range []string{"listed", "unlisted"} {
		r.waitReady(t, name)
		cs := r.connect(t, name, clientOpts{version: "2026-07-28"})
		params := &mcp.CallToolParams{Name: "meta", Meta: mcp.Meta{
			"example.com/trace": "abc", "example.com/session": "s-1", "dev.mcp/x": 1,
		}}
		params.SetProgressToken("p1")
		res, err := cs.CallTool(t.Context(), params)
		if err != nil {
			t.Fatal(err)
		}
		var meta map[string]any
		if err := json.Unmarshal([]byte(textOf(t, res)), &meta); err != nil {
			t.Fatal(err)
		}
		if tok, _ := meta["progressToken"].(string); !strings.HasPrefix(tok, "mcp-gate-") {
			t.Errorf("%s: progress token not remapped: %v", name, meta)
		}
		delete(meta, "progressToken")
		want := map[string]any{}
		if name == "listed" {
			want["example.com/trace"] = "abc"
		}
		if fmt.Sprint(meta) != fmt.Sprint(want) {
			t.Errorf("%s: the server got _meta %v, want %v", name, meta, want)
		}
	}
	// Without a progress token, a server that lists nothing gets no _meta at all.
	cs := r.connect(t, "unlisted", clientOpts{version: "2026-07-28"})
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "meta", Meta: mcp.Meta{"example.com/trace": "abc"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := textOf(t, res); got != "null" && got != "{}" {
		t.Errorf("unlisted, no progress: the server got _meta %s", got)
	}
}

// TestCancellation pins down what a client that gives up does to the downstream call. A
// 2026-07-28 request is one POST, so the gate cancels the call when the client goes away. On the
// stateless handler an older client's request is not tied to its POST: the call runs on until
// callTimeout ends it.
func TestCancellation(t *testing.T) {
	for _, c := range []struct {
		version   string
		propagate bool
	}{{"2026-07-28", true}, {"2025-11-25", false}} {
		t.Run(c.version, func(t *testing.T) {
			r := startGate(t, configDoc("", map[string]string{"s": stdioServer(t, testkit.Fake{}, "callTimeout: 2s\n")}), gateOpts{})
			r.waitReady(t, "s")
			cs := r.connect(t, "s", clientOpts{version: c.version})
			probe := r.connect(t, "s", clientOpts{})
			cancelled := func() int {
				res, err := probe.CallTool(t.Context(), &mcp.CallToolParams{Name: "stats"})
				if err != nil {
					t.Fatal(err)
				}
				var st struct{ Cancelled int }
				_ = json.Unmarshal([]byte(textOf(t, res)), &st)
				return st.Cancelled
			}
			start := time.Now()
			ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
			_, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "hang"})
			cancel()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("hang: %v", err)
			}
			for cancelled() == 0 {
				if time.Since(start) > 5*time.Second {
					t.Fatal("the downstream call was never cancelled")
				}
				time.Sleep(50 * time.Millisecond)
			}
			byTimeout := time.Since(start) >= 2*time.Second
			if byTimeout == c.propagate {
				t.Errorf("cancelled after %s; want it cancelled with the client: %v", time.Since(start), c.propagate)
			}
		})
	}
}

func TestListChanged(t *testing.T) {
	r := startGate(t, configDoc("", map[string]string{"s": stdioServer(t, testkit.Fake{}, "")}), gateOpts{})
	r.waitReady(t, "s")
	var changed atomic.Int32
	watcher := r.connect(t, "s", clientOpts{version: "2026-07-28", changed: func() { changed.Add(1) }})
	cs := r.connect(t, "s", clientOpts{version: "2025-11-25"})
	if _, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "addtool", Arguments: map[string]any{"name": "fresh"}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		res, err := cs.ListTools(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, tool := range res.Tools {
			found = found || tool.Name == "fresh"
		}
		if found && changed.Load() > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("fresh listed %v, list_changed seen %d", found, changed.Load())
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = watcher
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "fresh"})
	if err != nil || textOf(t, res) != "fresh" {
		t.Fatalf("fresh: %v %v", res, err)
	}
}

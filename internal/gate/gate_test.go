package gate_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

var eras = []string{"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28"}

func eraName(v string) string { return strings.ReplaceAll(v, "-", "") }

// TestVersionMatrix calls a tool through the gate from a client of every protocol era on a
// server of every era, over stdio and HTTP.
func TestVersionMatrix(t *testing.T) {
	servers := map[string]string{}
	for _, v := range eras {
		f := testkit.Fake{ProtocolVersions: []string{v}}
		servers["stdio-"+eraName(v)] = stdioServer(t, f, "")
		servers["http-"+eraName(v)] = httpServer(testkit.NewFakeHTTP(t, f, testkit.FakeHTTPOptions{}).URL(), "")
	}
	r := startGate(t, configDoc("", servers), gateOpts{})
	for name := range servers {
		r.waitReady(t, name)
	}
	var wg sync.WaitGroup
	for name := range servers {
		for _, client := range eras {
			wg.Go(func() {
				t.Run(fmt.Sprintf("%s/client-%s", name, eraName(client)), func(t *testing.T) {
					cs := r.connect(t, name, clientOpts{version: client})
					if got := cs.InitializeResult().ProtocolVersion; got != client {
						t.Errorf("negotiated %s, want %s", got, client)
					}
					res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "hi"}})
					if err != nil {
						t.Fatal(err)
					}
					if got := textOf(t, res); got != "hi" {
						t.Errorf("echo = %q", got)
					}
				})
			})
		}
	}
	wg.Wait()
}

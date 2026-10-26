package escrow

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vsem-azamat/mcp-gate/internal/redact"
)

// clientFlag starts the test binary as a socket client; the next argument is a clientSpec.
const clientFlag = "-escrow-socket-client"

// clientSpec is what the test binary does as a socket client.
type clientSpec struct {
	Sock, Path string // the socket, and the path to GET without a key
	Out        string // where the status and body are written
	Detach     bool   // start a grandchild that leaves the tree, and exit
	Parent     int    // the PID the grandchild waits to be reparented from
}

// runSocketClient is the test binary's client mode; it returns at once when the arguments do
// not ask for it.
func runSocketClient() {
	if len(os.Args) != 3 || os.Args[1] != clientFlag {
		return
	}
	var c clientSpec
	if err := json.Unmarshal([]byte(os.Args[2]), &c); err != nil {
		os.Exit(2)
	}
	ctx := context.Background()
	if c.Detach {
		// Start a grandchild and exit, so that it is reparented out of the test's tree.
		c.Detach, c.Parent = false, os.Getpid()
		spec, err := json.Marshal(c)
		if err != nil {
			os.Exit(2)
		}
		if err := exec.CommandContext(ctx, os.Args[0], clientFlag, string(spec)).Start(); err != nil {
			os.Exit(3)
		}
		os.Exit(0)
	}
	for deadline := time.Now().Add(10 * time.Second); c.Parent != 0 && os.Getppid() == c.Parent; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			os.Exit(4)
		}
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", c.Sock)
	}}
	out := "error"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://escrow"+c.Path, nil)
	if err == nil {
		if res, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Do(req); err == nil {
			body, _ := io.ReadAll(res.Body)
			_ = res.Body.Close()
			out = strconv.Itoa(res.StatusCode) + " " + string(body)
		}
	}
	if err := os.WriteFile(c.Out, []byte(out), 0o600); err != nil {
		os.Exit(5)
	}
	os.Exit(0)
}

// clientRequest runs the test binary as a client of sock, as a child of the test or, with
// detach, as a process of the same user outside the test's tree, and returns its answer.
func clientRequest(t *testing.T, sock, path string, detach bool) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out")
	spec, err := json.Marshal(clientSpec{Sock: sock, Path: path, Out: out, Detach: detach})
	if err != nil {
		t.Fatal(err)
	}
	if err := exec.CommandContext(t.Context(), os.Args[0], clientFlag, string(spec)).Run(); err != nil {
		t.Fatalf("client: %v", err)
	}
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if data, err := os.ReadFile(out); err == nil && len(data) > 0 {
			return string(data)
		}
		if time.Now().After(deadline) {
			t.Fatal("the client wrote no answer")
		}
	}
}

func TestSocketProcessTree(t *testing.T) {
	t.Parallel()
	e := New(Options{KeyHash: testHash(), AllowUIDs: []int{os.Geteuid()}})
	marker := e.Replacer(Source{Server: "s", Tool: "t"}).Replace(redact.Finding{Kind: "password", Value: "Qwerty-12345"})
	handle := markerRE.FindStringSubmatch(marker)[2]
	sock := filepath.Join(shortDir(t), "escrow.sock")
	serveSocket(t, e, sock)

	// The gate itself and its descendants, such as stdio servers, need the key even when their
	// user ID is listed.
	if code, _ := socketGet(t, sock, http.MethodGet, "/_escrow/"+handle, ""); code != http.StatusUnauthorized {
		t.Errorf("the gate process without a key = %d, want 401", code)
	}
	if got := clientRequest(t, sock, "/_escrow/"+handle, false); !strings.HasPrefix(got, "401 ") {
		t.Errorf("a child of the gate without a key = %q, want 401", got)
	}
	// Wrong keys from inside the tree do not lock out the allowed client outside it.
	for range 25 {
		_, _ = socketGet(t, sock, http.MethodGet, "/_escrow/"+handle, "wrong")
	}
	// Another process of the listed user is served without one.
	if got := clientRequest(t, sock, "/_escrow/"+handle, true); got != "200 Qwerty-12345" {
		t.Errorf("a process outside the gate's tree without a key = %q, want the value", got)
	}
}

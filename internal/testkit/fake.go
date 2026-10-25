package testkit

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Fake describes a scriptable fake MCP server, served over stdio (StdioCommand) or streamable
// HTTP (NewFakeHTTP). Every fake serves these tools:
//
//   - echo {"text": string}: returns the text;
//   - sleep {"ms": number}: waits, then returns "slept";
//   - big {"bytes": number}: returns a text of that many bytes;
//   - hang: never returns (until cancelled);
//   - crash: the stdio fake exits with status 3; the HTTP fake fails the call;
//   - env: returns the process environment, one variable per line, sorted;
//   - pids: returns {"pid", "pgid", "grandchild"} of the stdio fake;
//   - stats: returns {"pingsDuringCalls"}, the pings that arrived while a tool call ran.
type Fake struct {
	Name string `json:"name,omitempty"`
	// ProtocolVersions, if set, narrows the versions the server negotiates.
	ProtocolVersions []string `json:"protocolVersions,omitempty"`
	// SilentDiscover leaves server/discover unanswered, like a legacy server that ignores
	// requests before initialize.
	SilentDiscover bool `json:"silentDiscover,omitempty"`
	// Serial handles one request at a time, like a single-threaded server: a ping waits for a
	// running call.
	Serial bool `json:"serial,omitempty"`
	// FreezeAfter, if set, stops answering any request once the server has run that long.
	FreezeAfter time.Duration `json:"freezeAfter,omitempty"`
	// RefuseProbes answers ping and tools/list with a JSON-RPC error.
	RefuseProbes bool `json:"refuseProbes,omitempty"`
	// StartDelay, for the stdio fake, waits this long before reading stdin, like a server that
	// is slow to start.
	StartDelay time.Duration `json:"startDelay,omitempty"`

	// The stdio fake only:

	// ExitAtStart, if not zero, makes the process exit at once with this status.
	ExitAtStart int `json:"exitAtStart,omitempty"`
	// IgnoreSIGTERM makes the process ignore SIGTERM.
	IgnoreSIGTERM bool `json:"ignoreSigterm,omitempty"`
	// Grandchild starts a child of the fake in the same process group (see the pids tool).
	Grandchild bool `json:"grandchild,omitempty"`
	// Stderr is written to stderr, one line each, at start.
	Stderr []string `json:"stderr,omitempty"`
	// StdoutNoise is written to stdout before serving, as a server that logs to stdout does.
	StdoutNoise string `json:"stdoutNoise,omitempty"`
}

// fakeFlag marks a run of the test binary as a stdio fake.
const fakeFlag = "-testkit.fake"

// RunFake runs the stdio fake and exits when the test binary was started by StdioCommand.
// Packages that use StdioCommand call it first in TestMain.
func RunFake() {
	if len(os.Args) != 3 || os.Args[1] != fakeFlag {
		return
	}
	if os.Args[2] == "sleeper" {
		time.Sleep(time.Hour)
		os.Exit(0)
	}
	var f Fake
	if err := json.Unmarshal([]byte(os.Args[2]), &f); err != nil {
		fmt.Fprintln(os.Stderr, "testkit: bad fake:", err)
		os.Exit(2)
	}
	os.Exit(runStdio(f))
}

// StdioCommand returns the command and arguments that start f as a stdio MCP server: the test
// binary itself, which must call RunFake in TestMain.
func StdioCommand(t testing.TB, f Fake) (string, []string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	spec, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return exe, []string{fakeFlag, string(spec)}
}

func runStdio(f Fake) int {
	if f.ExitAtStart != 0 {
		return f.ExitAtStart
	}
	time.Sleep(f.StartDelay)
	if f.IgnoreSIGTERM {
		signal.Ignore(syscall.SIGTERM)
	}
	for _, line := range f.Stderr {
		fmt.Fprintln(os.Stderr, line)
	}
	if f.StdoutNoise != "" {
		fmt.Fprintln(os.Stdout, f.StdoutNoise)
	}
	grandchild := 0
	if f.Grandchild {
		exe, _ := os.Executable()
		gc := exec.Command(exe, fakeFlag, "sleeper") //nolint:gosec,noctx // the test binary itself, killed with the process group
		if err := gc.Start(); err != nil {
			fmt.Fprintln(os.Stderr, "testkit: grandchild:", err)
			return 2
		}
		grandchild = gc.Process.Pid
	}
	s := newFakeServer(f, func() { os.Exit(3) }, grandchild, nil)
	if err := s.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		return 1
	}
	return 0
}

// FakeHTTPOptions configures how NewFakeHTTP serves a fake.
type FakeHTTPOptions struct {
	// JSONResponse answers with application/json instead of an event stream.
	JSONResponse bool
	// Gzip compresses responses for clients that accept gzip.
	Gzip bool
}

// FakeHTTP serves a fake over stateless streamable HTTP. It is closed when the test ends.
type FakeHTTP struct {
	srv  *httptest.Server
	down atomic.Bool
}

// NewFakeHTTP starts serving f at URL().
func NewFakeHTTP(t testing.TB, f Fake, opts FakeHTTPOptions) *FakeHTTP {
	t.Helper()
	h := &FakeHTTP{}
	stop := make(chan struct{})
	s := newFakeServer(f, nil, 0, stop)
	var handler http.Handler = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: opts.JSONResponse})
	if opts.Gzip {
		handler = gzipHandler(handler)
	}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(h.srv.Close)
	t.Cleanup(func() { close(stop) }) // runs first: releases requests left unanswered
	return h
}

// URL is the MCP endpoint.
func (h *FakeHTTP) URL() string { return h.srv.URL + "/mcp" }

// SetDown makes the server answer every request with 503, or serve again.
func (h *FakeHTTP) SetDown(down bool) { h.down.Store(down) }

// newFakeServer builds the server of f. Requests it leaves unanswered return when stop closes.
func newFakeServer(f Fake, crash func(), grandchild int, stop <-chan struct{}) *mcp.Server {
	name := f.Name
	if name == "" {
		name = "fake"
	}
	s := mcp.NewServer(&mcp.Implementation{Name: name, Version: "test"}, &mcp.ServerOptions{
		SupportedProtocolVersions: f.ProtocolVersions,
	})
	st := &fakeStats{}
	s.AddReceivingMiddleware(behaviour(f, stop, st))
	text := func(s string) *mcp.CallToolResult {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
	}
	tool := func(name string, h func(context.Context, map[string]any) (*mcp.CallToolResult, error)) {
		s.AddTool(&mcp.Tool{Name: name, InputSchema: map[string]any{"type": "object"}},
			func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				args := map[string]any{}
				if len(req.Params.Arguments) > 0 {
					if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
						return nil, err
					}
				}
				return h(ctx, args)
			})
	}
	number := func(args map[string]any, k string) int {
		v, _ := args[k].(float64)
		return int(v)
	}
	tool("echo", func(_ context.Context, args map[string]any) (*mcp.CallToolResult, error) {
		v, _ := args["text"].(string)
		return text(v), nil
	})
	tool("sleep", func(ctx context.Context, args map[string]any) (*mcp.CallToolResult, error) {
		select {
		case <-time.After(time.Duration(number(args, "ms")) * time.Millisecond):
			return text("slept"), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	tool("big", func(_ context.Context, args map[string]any) (*mcp.CallToolResult, error) {
		return text(strings.Repeat("x", number(args, "bytes"))), nil
	})
	tool("hang", func(ctx context.Context, _ map[string]any) (*mcp.CallToolResult, error) {
		return nil, unanswered(ctx, stop)
	})
	tool("crash", func(context.Context, map[string]any) (*mcp.CallToolResult, error) {
		if crash != nil {
			crash()
		}
		return nil, errors.New("crash")
	})
	tool("env", func(context.Context, map[string]any) (*mcp.CallToolResult, error) {
		env := os.Environ()
		sort.Strings(env)
		return text(strings.Join(env, "\n")), nil
	})
	tool("stats", func(context.Context, map[string]any) (*mcp.CallToolResult, error) {
		data, err := json.Marshal(map[string]int64{"pingsDuringCalls": st.pingsDuringCalls.Load()})
		return text(string(data)), err
	})
	tool("pids", func(context.Context, map[string]any) (*mcp.CallToolResult, error) {
		pgid, _ := syscall.Getpgid(os.Getpid())
		data, err := json.Marshal(map[string]int{"pid": os.Getpid(), "pgid": pgid, "grandchild": grandchild})
		return text(string(data)), err
	})
	return s
}

// behaviour applies the scripted request handling of f.
// fakeStats counts what a fake saw.
type fakeStats struct {
	calls            atomic.Int64 // tool calls running, the stats call excluded
	pingsDuringCalls atomic.Int64
}

func behaviour(f Fake, stop <-chan struct{}, st *fakeStats) mcp.Middleware {
	start := time.Now()
	var serial sync.Mutex
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if strings.HasPrefix(method, "notifications/") {
				return next(ctx, method, req)
			}
			if (f.SilentDiscover && method == "server/discover") || (f.FreezeAfter > 0 && time.Since(start) > f.FreezeAfter) {
				return nil, unanswered(ctx, stop)
			}
			switch {
			case method == "ping" && st.calls.Load() > 0:
				st.pingsDuringCalls.Add(1)
			case method == "tools/call":
				if r, ok := req.(*mcp.CallToolRequest); !ok || r.Params.Name != "stats" {
					st.calls.Add(1)
					defer st.calls.Add(-1)
				}
			}
			if f.RefuseProbes && (method == "ping" || method == "tools/list") {
				return nil, &jsonrpc.Error{Code: -32000, Message: "busy"}
			}
			if f.Serial {
				serial.Lock()
				defer serial.Unlock()
			}
			return next(ctx, method, req)
		}
	}
}

// unanswered waits until the request is cancelled or the fake stops.
func unanswered(ctx context.Context, stop <-chan struct{}) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-stop:
		return errors.New("testkit: the fake stopped")
	}
}

// gzipHandler compresses responses for clients that accept gzip, flushing with each write so
// that event streams keep working.
func gzipHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Del("Content-Length")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		next.ServeHTTP(&gzipWriter{ResponseWriter: w, gz: gz}, r)
	})
}

type gzipWriter struct {
	http.ResponseWriter
	gz *gzip.Writer
}

func (g *gzipWriter) Write(p []byte) (int, error) {
	g.Header().Del("Content-Length")
	return g.gz.Write(p)
}

func (g *gzipWriter) Flush() {
	_ = g.gz.Flush()
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

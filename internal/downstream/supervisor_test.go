package downstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.uber.org/goleak"

	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

func TestMain(m *testing.M) {
	testkit.RunFake()
	goleak.VerifyTestMain(m)
}

// fast shortens the supervisor's timings for tests.
func fast(o Options) Options {
	o.InitialBackoff = 20 * time.Millisecond
	o.MaxBackoff = 100 * time.Millisecond
	o.StopGrace = time.Second
	if o.ProbeInterval == 0 {
		o.ProbeInterval = time.Hour
	}
	return o
}

func stdioOptions(t *testing.T, f testkit.Fake) Options {
	t.Helper()
	cmd, args := testkit.StdioCommand(t, f)
	return fast(Options{
		Name: "fake",
		Stdio: &Stdio{
			Command: cmd, Args: args,
			InheritEnv: []string{"PATH", "LC_*"},
			ParentEnv:  []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "GATE_SECRET=gate-secret-value"},
			Env:        map[string]string{"FAKE_MODE": "test"},
		},
	})
}

func httpOptions(t *testing.T, f testkit.Fake, ho testkit.FakeHTTPOptions) (Options, *testkit.FakeHTTP) {
	t.Helper()
	h := testkit.NewFakeHTTP(t, f, ho)
	return fast(Options{Name: "fake", HTTP: &HTTP{URL: h.URL()}}), h
}

func start(t *testing.T, o Options) *Supervisor {
	t.Helper()
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	s.Start(t.Context())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.Stop(ctx); err != nil {
			t.Errorf("Stop: %v", err)
		}
	})
	return s
}

func waitFor(t *testing.T, s *Supervisor, what string, cond func(Status) bool) Status {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	if err := s.Wait(ctx, cond); err != nil {
		t.Fatalf("waiting for %s: %v (status %+v)", what, err, s.Status())
	}
	return s.Status()
}

func waitReady(t *testing.T, s *Supervisor) Status {
	t.Helper()
	return waitFor(t, s, "ready", func(st Status) bool { return st.State == Ready })
}

func callTool(t *testing.T, s *Supervisor, name string, args map[string]any) (string, error) {
	t.Helper()
	var out string
	err := s.Call(t.Context(), func(ctx context.Context, cs *mcp.ClientSession) error {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			return err
		}
		if len(res.Content) > 0 {
			if tc, ok := res.Content[0].(*mcp.TextContent); ok {
				out = tc.Text
			}
		}
		return nil
	})
	return out, err
}

func mustEcho(t *testing.T, s *Supervisor) {
	t.Helper()
	if got, err := callTool(t, s, "echo", map[string]any{"text": "hello"}); err != nil || got != "hello" {
		t.Fatalf("echo = %q, %v", got, err)
	}
}

type transportCase struct {
	name string
	opts func(t *testing.T, f testkit.Fake) Options
}

var transports = []transportCase{
	{"stdio", stdioOptions},
	{"http-sse", func(t *testing.T, f testkit.Fake) Options {
		o, _ := httpOptions(t, f, testkit.FakeHTTPOptions{})
		return o
	}},
	{"http-json", func(t *testing.T, f testkit.Fake) Options {
		o, _ := httpOptions(t, f, testkit.FakeHTTPOptions{JSONResponse: true})
		return o
	}},
}

// TestVersionMatrix connects to servers of every protocol version over every transport.
func TestVersionMatrix(t *testing.T) {
	t.Parallel()
	for _, tr := range transports {
		for _, v := range mcp.SupportedProtocolVersions() {
			t.Run(tr.name+"/"+v, func(t *testing.T) {
				t.Parallel()
				s := start(t, tr.opts(t, testkit.Fake{ProtocolVersions: []string{v}}))
				st := waitReady(t, s)
				if st.ProtocolVersion != v || st.AutoPinned {
					t.Errorf("negotiated %s (auto-pinned %v), want %s", st.ProtocolVersion, st.AutoPinned, v)
				}
				mustEcho(t, s)
			})
		}
	}
}

func TestManualPin(t *testing.T) {
	t.Parallel()
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			t.Parallel()
			o := tr.opts(t, testkit.Fake{})
			o.ProtocolVersion = "2025-06-18"
			s := start(t, o)
			if st := waitReady(t, s); st.ProtocolVersion != "2025-06-18" || st.AutoPinned {
				t.Errorf("status = %+v, want the pinned 2025-06-18", st)
			}
			mustEcho(t, s)
		})
	}
}

func TestAutoPinAfterSilentDiscover(t *testing.T) {
	t.Parallel()
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			t.Parallel()
			o := tr.opts(t, testkit.Fake{SilentDiscover: true})
			// The pinned retry must finish within this to be kept, also on a loaded runner.
			o.DiscoverTimeout = 2 * time.Second
			var mu sync.Mutex
			var learned []string
			o.OnPinLearned = func(v string) {
				mu.Lock()
				learned = append(learned, v)
				mu.Unlock()
			}
			s := start(t, o)
			st := waitReady(t, s)
			if st.ProtocolVersion != AutoPinVersion || !st.AutoPinned {
				t.Errorf("status = %+v, want the automatic pin", st)
			}
			mu.Lock()
			if len(learned) != 1 || learned[0] != AutoPinVersion {
				t.Errorf("OnPinLearned calls = %v", learned)
			}
			mu.Unlock()
			mustEcho(t, s)
		})
	}
}

func TestSlowStartIsNotLearned(t *testing.T) {
	t.Parallel()
	o := stdioOptions(t, testkit.Fake{StartDelay: 700 * time.Millisecond})
	o.DiscoverTimeout = 300 * time.Millisecond
	o.OnPinLearned = func(string) { t.Error("a slow start was learned as a pin") }
	s := start(t, o)
	if st := waitReady(t, s); st.ProtocolVersion != AutoPinVersion || !st.AutoPinned {
		t.Errorf("status = %+v, want this session on the automatic pin", st)
	}
	mustEcho(t, s)
}

func TestErrorsHideTheURL(t *testing.T) {
	t.Parallel()
	o := fast(Options{Name: "remote", HTTP: &HTTP{URL: "http://127.0.0.1:1/s/path-secret-123/mcp?key=query-secret-456"}})
	s := start(t, o)
	st := waitFor(t, s, "backoff", func(st Status) bool { return st.State == Backoff })
	if strings.Contains(st.LastError, "secret-") || !strings.Contains(st.LastError, "<servers.remote.http.url>") {
		t.Errorf("last error = %q", st.LastError)
	}
}

func TestLearnedPinSkipsDiscover(t *testing.T) {
	t.Parallel()
	o := stdioOptions(t, testkit.Fake{SilentDiscover: true})
	o.LearnedPin = AutoPinVersion
	o.DiscoverTimeout = time.Hour // a discover attempt would never finish
	s := start(t, o)
	if st := waitReady(t, s); st.ProtocolVersion != AutoPinVersion || !st.AutoPinned {
		t.Errorf("status = %+v", st)
	}
}

func TestStdioCleanEnvironment(t *testing.T) {
	t.Parallel()
	s := start(t, stdioOptions(t, testkit.Fake{}))
	waitReady(t, s)
	env, err := callTool(t, s, "env", nil)
	if err != nil {
		t.Fatal(err)
	}
	if env != "FAKE_MODE=test\nLC_ALL=C\nPATH=/usr/bin:/bin" {
		t.Errorf("child environment = %q", env)
	}
}

func TestStdioOversizedFrameFailsOnlyItsCall(t *testing.T) {
	t.Parallel()
	o := stdioOptions(t, testkit.Fake{})
	o.MaxMessageBytes = 64 << 10
	s := start(t, o)
	pid := waitReady(t, s).PID
	// A slow call runs while the oversized response arrives; it must not fail.
	slow := make(chan error, 1)
	go func() {
		_, err := callTool(t, s, "sleep", map[string]any{"ms": 300})
		slow <- err
	}()
	_, err := callTool(t, s, "big", map[string]any{"bytes": 1 << 20})
	if err == nil || !strings.Contains(err.Error(), "maxMessageBytes") {
		t.Errorf("big call: err = %v, want the size error", err)
	}
	if err := <-slow; err != nil {
		t.Errorf("concurrent call failed: %v", err)
	}
	mustEcho(t, s)
	if got, err := callTool(t, s, "big", map[string]any{"bytes": 32 << 10}); err != nil || len(got) != 32<<10 {
		t.Errorf("a response under the limit: %d bytes, %v", len(got), err)
	}
	if st := s.Status(); st.PID != pid || st.Restarts != 0 || st.State != Ready {
		t.Errorf("the session did not survive: %+v", st)
	}
}

func TestHTTPOversizedResponseFailsOnlyItsCall(t *testing.T) {
	t.Parallel()
	for _, ho := range []testkit.FakeHTTPOptions{{}, {JSONResponse: true}, {JSONResponse: true, Gzip: true}, {Gzip: true}} {
		t.Run(strconv.FormatBool(ho.JSONResponse)+"-gzip-"+strconv.FormatBool(ho.Gzip), func(t *testing.T) {
			t.Parallel()
			o, _ := httpOptions(t, testkit.Fake{}, ho)
			o.MaxMessageBytes = 64 << 10
			s := start(t, o)
			waitReady(t, s)
			_, err := callTool(t, s, "big", map[string]any{"bytes": 1 << 20})
			if err == nil || !strings.Contains(err.Error(), "maxMessageBytes") {
				t.Errorf("big call: err = %v, want the size error", err)
			}
			mustEcho(t, s)
			if got, err := callTool(t, s, "big", map[string]any{"bytes": 32 << 10}); err != nil || len(got) != 32<<10 {
				t.Errorf("a response under the limit: %d bytes, %v", len(got), err)
			}
			if st := s.Status(); st.Restarts != 0 || st.State != Ready {
				t.Errorf("the session did not survive: %+v", st)
			}
		})
	}
}

func TestStdioNoiseOnStdout(t *testing.T) {
	t.Parallel()
	s := start(t, stdioOptions(t, testkit.Fake{StdoutNoise: "starting up, not JSON"}))
	waitReady(t, s)
	mustEcho(t, s)
}

func TestCrashRestarts(t *testing.T) {
	t.Parallel()
	s := start(t, stdioOptions(t, testkit.Fake{}))
	pid := waitReady(t, s).PID
	if _, err := callTool(t, s, "crash", nil); err == nil {
		t.Error("the crashing call succeeded")
	}
	st := waitFor(t, s, "restart", func(st Status) bool { return st.State == Ready && st.Restarts == 1 })
	if st.PID == pid || !strings.Contains(st.LastError, "exit status 3") && !strings.Contains(st.LastError, "closed") {
		t.Errorf("status after restart = %+v", st)
	}
	mustEcho(t, s)
}

// TestBackoff checks the real delays between restarts of a server that exits at once. Timers
// never fire early, so the time to a number of restarts is at least the sum of the delays; the
// upper bound is far below the sum the delays would reach without MaxBackoff.
func TestBackoff(t *testing.T) {
	t.Parallel()
	o := stdioOptions(t, testkit.Fake{ExitAtStart: 7})
	o.InitialBackoff = 50 * time.Millisecond
	o.MaxBackoff = 100 * time.Millisecond
	const restarts = 7
	var capped, uncapped time.Duration // the delays before the restarts, with and without the cap
	for i := range restarts {
		d := o.InitialBackoff << i
		uncapped += d
		capped += min(d, o.MaxBackoff)
	}
	began := time.Now()
	s := start(t, o)
	st := waitFor(t, s, "several restarts", func(st Status) bool { return st.Restarts >= restarts })
	took := time.Since(began)
	if took < capped {
		t.Errorf("%d restarts took %v, less than the delays (%v)", restarts, took, capped)
	}
	if took > uncapped/2 {
		t.Errorf("%d restarts took %v; without the cap the delays alone are %v", restarts, took, uncapped)
	}
	if st.LastError == "" {
		t.Error("no error recorded")
	}
	waitFor(t, s, "backoff", func(st Status) bool { return st.State == Backoff })
	if _, err := callTool(t, s, "echo", nil); !errors.As(err, new(*NotReadyError)) {
		t.Errorf("call during backoff: err = %v, want NotReadyError", err)
	}
}

// TestBackoffResetsAfterStableSession checks that the backoff grows over sessions that crash
// soon and starts over after a session that lived StableAfter. Each recovery is timed from
// before the crash, so it is at least the delay; without the reset the last recovery would wait
// the grown delay.
func TestBackoffResetsAfterStableSession(t *testing.T) {
	t.Parallel()
	o := stdioOptions(t, testkit.Fake{})
	o.InitialBackoff = 50 * time.Millisecond
	o.MaxBackoff = 5 * time.Second
	o.StableAfter = time.Second
	s := start(t, o)
	waitReady(t, s)
	crash := func(n int) time.Duration {
		t.Helper()
		began := time.Now()
		if _, err := callTool(t, s, "crash", nil); err == nil {
			t.Fatal("the crashing call succeeded")
		}
		waitFor(t, s, "restart", func(st Status) bool { return st.State == Ready && st.Restarts == n })
		return time.Since(began)
	}
	delay := o.InitialBackoff
	const quick = 5
	for n := 1; n <= quick; n++ {
		if took := crash(n); took < delay {
			t.Fatalf("recovery %d took %v, less than its delay %v", n, took, delay)
		}
		delay *= 2
	}
	time.Sleep(o.StableAfter + 100*time.Millisecond)
	if took := crash(quick + 1); took >= delay {
		t.Errorf("recovery after a stable session took %v, the grown delay is %v", took, delay)
	}
}

func TestNoProbesWhileCallsRun(t *testing.T) {
	t.Parallel()
	o := stdioOptions(t, testkit.Fake{ProtocolVersions: []string{"2025-11-25"}}) // probes are pings
	o.ProbeInterval = 20 * time.Millisecond
	s := start(t, o)
	pid := waitReady(t, s).PID
	if _, err := callTool(t, s, "sleep", map[string]any{"ms": 500}); err != nil {
		t.Fatalf("the long call failed: %v", err)
	}
	out, err := callTool(t, s, "stats", nil)
	if err != nil {
		t.Fatal(err)
	}
	var stats struct{ PingsDuringCalls int }
	if err := json.Unmarshal([]byte(out), &stats); err != nil {
		t.Fatal(err)
	}
	if stats.PingsDuringCalls != 0 {
		t.Errorf("%d probes were sent during the call", stats.PingsDuringCalls)
	}
	if st := s.Status(); st.PID != pid || st.Restarts != 0 {
		t.Errorf("the server was restarted during a call: %+v", st)
	}
}

// TestProbeErrorReplyMeansAlive checks that a probe answered with an error reply does not count
// as a failure. The interval is also the probe timeout, so on a loaded machine a reply can come
// too late, which does count; only a failure other than a timeout fails the test.
func TestProbeErrorReplyMeansAlive(t *testing.T) {
	t.Parallel()
	var logs syncBuffer
	o := stdioOptions(t, testkit.Fake{RefuseProbes: true})
	o.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	o.ProbeInterval = 400 * time.Millisecond
	o.ProbeFailures = 1
	s := start(t, o)
	pid := waitReady(t, s).PID
	time.Sleep(1500 * time.Millisecond)
	if st := s.Status(); st.PID == pid && st.Restarts == 0 && st.State == Ready {
		return
	}
	t.Logf("the server was restarted (%+v); checking that only timeouts counted", s.Status())
	for line := range strings.Lines(logs.String()) {
		if strings.Contains(line, `error="probe: `) && !strings.Contains(line, "context deadline exceeded") {
			t.Errorf("an error reply counted as a failure: %s", line)
		}
	}
}

func TestFrozenServerIsRestarted(t *testing.T) {
	t.Parallel()
	for _, tr := range transports[:2] {
		t.Run(tr.name, func(t *testing.T) {
			t.Parallel()
			var logs syncBuffer
			o := tr.opts(t, testkit.Fake{FreezeAfter: 300 * time.Millisecond})
			o.Logger = slog.New(slog.NewTextHandler(&logs, nil))
			o.ProbeInterval = 50 * time.Millisecond
			o.ProbeTimeout = 40 * time.Millisecond
			s := start(t, o)
			// Ready and Degraded are passed quickly once the server freezes, so the test waits
			// for counters, which stay: a session, then a restart after failed probes; and it
			// finds Degraded in the log, which keeps every state change.
			waitFor(t, s, "a session", func(st Status) bool { return st.Sessions >= 1 })
			st := waitFor(t, s, "a restart", func(st Status) bool { return st.Restarts >= 1 })
			if !strings.Contains(logs.String(), "to=degraded") {
				t.Error("the server was restarted without becoming degraded")
			}
			if !strings.Contains(st.LastError, "probe") && !strings.Contains(st.LastError, "probes") {
				t.Errorf("last error = %q", st.LastError)
			}
		})
	}
}

func TestHTTPDownAndUp(t *testing.T) {
	t.Parallel()
	o, h := httpOptions(t, testkit.Fake{}, testkit.FakeHTTPOptions{})
	o.ProbeInterval = 30 * time.Millisecond
	s := start(t, o)
	waitReady(t, s)
	h.SetDown(true)
	waitFor(t, s, "backoff", func(st Status) bool { return st.State == Backoff })
	h.SetDown(false)
	waitFor(t, s, "ready again", func(st Status) bool { return st.State == Ready && st.Restarts >= 1 })
	mustEcho(t, s)
}

func TestStopKillsTheProcessGroup(t *testing.T) {
	t.Parallel()
	o := stdioOptions(t, testkit.Fake{Grandchild: true, IgnoreSIGTERM: true})
	o.StopGrace = 200 * time.Millisecond
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	s.Start(t.Context())
	waitReady(t, s)
	out, err := callTool(t, s, "pids", nil)
	if err != nil {
		t.Fatal(err)
	}
	var pids struct{ PID, PGID, Grandchild int }
	if err := json.Unmarshal([]byte(out), &pids); err != nil {
		t.Fatal(err)
	}
	if pids.PGID != pids.PID || pids.Grandchild == 0 {
		t.Fatalf("pids = %+v: the fake is not a group leader with a grandchild", pids)
	}
	if err := s.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, pid := range []int{pids.PID, pids.Grandchild} {
		if state, ok := processState(t, pid); ok && state != 'Z' {
			t.Errorf("process %d is still running after Stop (state %c)", pid, state)
		}
	}
	if s.Status().State != Stopped {
		t.Errorf("state = %s", s.Status().State)
	}
}

// processState returns the state ps(1) shows for pid, such as 'Z' for a zombie; ok is false
// when there is no such process. The grandchild of a stopped server is left to init (launchd on
// darwin) or a subreaper to reap,
// and on darwin a process group whose only members are zombies is gone for kill(2), so Stop may
// return while the grandchild is still a zombie.
func processState(t *testing.T, pid int) (state byte, ok bool) {
	t.Helper()
	if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
		return 0, false
	}
	out, err := exec.CommandContext(t.Context(), "ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
	stat := strings.TrimSpace(string(out))
	var exit *exec.ExitError
	switch {
	case err == nil && stat != "":
		return stat[0], true
	case errors.As(err, &exit) && stat == "":
		return 0, false // reaped since kill
	}
	t.Fatalf("ps -p %d: %q, %v", pid, out, err)
	return 0, false
}

func TestStderrIsLoggedRedacted(t *testing.T) {
	t.Parallel()
	const token = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
	var logs syncBuffer
	o := stdioOptions(t, testkit.Fake{Stderr: []string{"booting", "using token " + token}})
	o.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	s := start(t, o)
	waitReady(t, s)
	st := waitFor(t, s, "stderr", func(st Status) bool { return len(st.Stderr) == 2 })
	if st.Stderr[0] != "booting" || strings.Contains(st.Stderr[1], token) || !strings.Contains(st.Stderr[1], "[REDACTED:github_token]") {
		t.Errorf("stderr tail = %q", st.Stderr)
	}
	if strings.Contains(logs.String(), token) {
		t.Error("the token reached the log")
	}
}

// TestStderrAfterReadyWakesWait checks that a stderr line wakes Wait: after Ready no state
// change follows, so only the line can.
func TestStderrAfterReadyWakesWait(t *testing.T) {
	t.Parallel()
	o := stdioOptions(t, testkit.Fake{Stderr: []string{"late line"}, StderrAfter: 300 * time.Millisecond})
	s := start(t, o)
	waitReady(t, s)
	if st := s.Status(); len(st.Stderr) != 0 {
		t.Skipf("the line came before Ready (%q), so this run does not check the wakeup", st.Stderr)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := s.Wait(ctx, func(st Status) bool { return len(st.Stderr) == 1 }); err != nil {
		t.Fatalf("Wait missed the stderr line: %v (status %+v)", err, s.Status())
	}
}

func TestOOMScoreAdjOfChild(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	s := start(t, stdioOptions(t, testkit.Fake{}))
	pid := waitReady(t, s).PID
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/oom_score_adj")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "500" {
		t.Errorf("oom_score_adj = %s", data)
	}
}

func TestCallTimeout(t *testing.T) {
	t.Parallel()
	o := stdioOptions(t, testkit.Fake{})
	o.CallTimeout = 100 * time.Millisecond
	s := start(t, o)
	waitReady(t, s)
	_, err := callTool(t, s, "hang", nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want a deadline", err)
	}
	mustEcho(t, s)
}

func TestDisabled(t *testing.T) {
	t.Parallel()
	o := stdioOptions(t, testkit.Fake{})
	o.Disabled = true
	s := start(t, o)
	if st := s.Status(); st.State != Disabled {
		t.Errorf("state = %s", st.State)
	}
	var nr *NotReadyError
	if _, err := callTool(t, s, "echo", nil); !errors.As(err, &nr) || nr.State != Disabled {
		t.Errorf("err = %v", err)
	}
}

func TestStartFailureIsRecorded(t *testing.T) {
	t.Parallel()
	s := start(t, fast(Options{Name: "missing", Stdio: &Stdio{Command: "/nonexistent/mcp-server"}}))
	st := waitFor(t, s, "backoff", func(st Status) bool { return st.State == Backoff })
	if !strings.Contains(st.LastError, "start") {
		t.Errorf("last error = %q", st.LastError)
	}
}

func TestNewRejectsBadOptions(t *testing.T) {
	t.Parallel()
	if _, err := New(Options{Name: "x"}); err == nil {
		t.Error("New without a transport succeeded")
	}
	if _, err := New(Options{Name: "x", Stdio: &Stdio{}, HTTP: &HTTP{}}); err == nil {
		t.Error("New with two transports succeeded")
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestNotifications(t *testing.T) {
	var progress, changed atomic.Int32
	var sessions atomic.Int32
	o := stdioOptions(t, testkit.Fake{})
	o.Notifications = Notifications{
		ToolsChanged: func() { changed.Add(1) },
		Progress:     func(*mcp.ProgressNotificationParams) { progress.Add(1) },
	}
	o.OnSession = func(*mcp.ClientSession) { sessions.Add(1) }
	s := start(t, o)
	waitReady(t, s)
	err := s.Call(t.Context(), func(ctx context.Context, cs *mcp.ClientSession) error {
		params := &mcp.CallToolParams{Name: "progress", Arguments: map[string]any{"steps": 2, "ms": 10}}
		params.SetProgressToken("p")
		if _, err := cs.CallTool(ctx, params); err != nil {
			return err
		}
		_, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "addtool", Arguments: map[string]any{"name": "fresh"}})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for progress.Load() == 0 || changed.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("progress %d, changed %d", progress.Load(), changed.Load())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if sessions.Load() != 1 {
		t.Errorf("OnSession called %d times", sessions.Load())
	}
}

// TestRejectedListen connects to a server that rejects subscriptions/listen without it, and
// reports list changes after every successful probe instead.
func TestRejectedListen(t *testing.T) {
	var changed atomic.Int32
	o := stdioOptions(t, testkit.Fake{RejectListen: true})
	o.ProbeInterval = 50 * time.Millisecond
	o.Notifications = Notifications{ToolsChanged: func() { changed.Add(1) }}
	s := start(t, o)
	if st := waitReady(t, s); st.ProtocolVersion != "2026-07-28" {
		t.Fatalf("status %+v", st)
	}
	deadline := time.Now().Add(10 * time.Second)
	for changed.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("changed %d", changed.Load())
		}
		time.Sleep(20 * time.Millisecond)
	}
	mustEcho(t, s)
}

// TestAcknowledgedListen reports no list change after probes on a session whose server
// acknowledged the subscription.
func TestAcknowledgedListen(t *testing.T) {
	for _, transport := range []string{"stdio", "http"} {
		t.Run(transport, func(t *testing.T) {
			var changed atomic.Int32
			o := stdioOptions(t, testkit.Fake{})
			if transport == "http" {
				o, _ = httpOptions(t, testkit.Fake{}, testkit.FakeHTTPOptions{})
			}
			o.ProbeInterval = 50 * time.Millisecond
			o.Notifications = Notifications{ToolsChanged: func() { changed.Add(1) }}
			s := start(t, o)
			waitReady(t, s)
			time.Sleep(400 * time.Millisecond)
			if n := changed.Load(); n != 0 {
				t.Errorf("changed %d times without a change", n)
			}
		})
	}
}

func TestHideURL(t *testing.T) {
	const u = "https://mcp.example.com/k-secret/mcp?a=1&b=2"
	s, err := New(Options{Name: "remote", HTTP: &HTTP{URL: u}})
	if err != nil {
		t.Fatal(err)
	}
	enc, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{
		"Post " + u, string(enc), strings.ReplaceAll(u, "/", `\/`), strings.ReplaceAll(string(enc), "/", `\/`),
	} {
		if got := s.HideURL(text); strings.Contains(got, "k-secret") || !strings.Contains(got, "<servers.remote.http.url>") {
			t.Errorf("HideURL(%q) = %q", text, got)
		}
	}
}

func TestStatusPredicates(t *testing.T) {
	for _, c := range []struct {
		state                 State
		connected, awaitLogin bool
	}{
		{Starting, false, false},
		{Ready, true, false},
		{Degraded, true, false},
		{Backoff, false, false},
		{Disabled, false, false},
		{Stopped, false, false},
		{NeedsLogin, false, true},
	} {
		st := Status{State: c.state}
		if st.Connected() != c.connected || st.AwaitsLogin() != c.awaitLogin || st.ConnectsOnItsOwn() == c.awaitLogin {
			t.Errorf("%s: connected %v, awaits a login %v, connects on its own %v", c.state, st.Connected(), st.AwaitsLogin(), st.ConnectsOnItsOwn())
		}
	}
}

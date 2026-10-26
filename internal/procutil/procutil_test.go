package procutil

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"go.uber.org/goleak"
)

// The test binary doubles as the child: "-procutil.helper <mode>" runs a helper instead of the
// tests.
const helperFlag = "-procutil.helper"

func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == helperFlag {
		helper(os.Args[2])
		os.Exit(0)
	}
	goleak.VerifyTestMain(m)
}

func helper(mode string) {
	switch mode {
	case "env":
		for _, kv := range os.Environ() {
			fmt.Fprintln(os.Stdout, kv)
		}
	case "sleep":
		time.Sleep(time.Hour)
	case "group":
		// A grandchild in the same process group, then wait.
		gc := exec.Command(os.Args[0], helperFlag, "sleep") //nolint:noctx // killed with the process group
		if err := gc.Start(); err != nil {
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, gc.Process.Pid)
		time.Sleep(time.Hour)
	case "ignoreterm":
		signal.Ignore(syscall.SIGTERM)
		fmt.Fprintln(os.Stdout, "ready")
		time.Sleep(time.Hour)
	case "orphan":
		// A grandchild in a session of its own, which outlives this process briefly.
		gc := exec.Command(os.Args[0], helperFlag, "brief") //nolint:noctx // exits by itself
		gc.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := gc.Start(); err != nil {
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, gc.Process.Pid)
	case "ready":
		fmt.Fprintln(os.Stdout, "ready")
		time.Sleep(time.Hour)
	case "nondumpable":
		if err := SetNonDumpable(); err != nil {
			fmt.Fprintln(os.Stdout, err)
		}
		fmt.Fprintln(os.Stdout, "ready")
		time.Sleep(time.Hour)
	case "brief":
		time.Sleep(300 * time.Millisecond)
	case "stderr":
		fmt.Fprintln(os.Stderr, "first line")
		fmt.Fprintln(os.Stderr, strings.Repeat("x", 3*MaxLineBytes))
		fmt.Fprint(os.Stderr, "last line without newline")
	}
}

func startHelper(t *testing.T, mode string, spec Spec) *Process {
	t.Helper()
	spec.Path = os.Args[0]
	spec.Args = []string{helperFlag, mode}
	p, err := Start(spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Stop(time.Second) })
	return p
}

func readLine(t *testing.T, r io.Reader) string {
	t.Helper()
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(line)
}

func alive(pid int) bool {
	state, _, ok := procStat(pid)
	return ok && state != 'Z'
}

func TestEnviron(t *testing.T) {
	t.Parallel()
	parent := []string{"PATH=/bin", "HOME=/home/u", "LC_ALL=C", "LC_TIME=x", "SECRET=s", "LANGUAGE=en", "=odd", "noequals"}
	got := Environ(parent, []string{"PATH", "HOME", "LC_*", "LANG"}, map[string]string{"HOME": "/srv", "EXTRA": "1"})
	want := []string{"EXTRA=1", "HOME=/srv", "LC_ALL=C", "LC_TIME=x", "PATH=/bin"}
	if !slices.Equal(got, want) {
		t.Errorf("Environ = %v, want %v", got, want)
	}
	if got := Environ(parent, nil, nil); len(got) != 0 {
		t.Errorf("Environ with nothing inherited = %v", got)
	}
}

func TestStartCleanEnvironment(t *testing.T) {
	t.Parallel()
	p := startHelper(t, "env", Spec{Env: []string{"ONLY=this"}})
	out, err := io.ReadAll(p.Stdout())
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(out)); got != "ONLY=this" {
		t.Errorf("child environment = %q, want only ONLY=this", got)
	}
	if err := p.ExitErr(); err != nil {
		t.Errorf("exit: %v", err)
	}
}

func TestStopKillsTheGroup(t *testing.T) {
	t.Parallel()
	p := startHelper(t, "group", Spec{})
	gc, err := strconv.Atoi(readLine(t, p.Stdout()))
	if err != nil {
		t.Fatal(err)
	}
	if pgid, _ := syscall.Getpgid(gc); pgid != p.PID() {
		t.Fatalf("grandchild pgid = %d, want %d", pgid, p.PID())
	}
	if err := p.Stop(time.Second); err != nil {
		t.Fatal(err)
	}
	if alive(gc) {
		t.Error("the grandchild survived Stop")
	}
	select {
	case <-p.Done():
	default:
		t.Error("Done is not closed after Stop")
	}
}

func TestStopEscalatesToKill(t *testing.T) {
	t.Parallel()
	p := startHelper(t, "ignoreterm", Spec{})
	if got := readLine(t, p.Stdout()); got != "ready" {
		t.Fatalf("helper said %q", got)
	}
	start := time.Now()
	if err := p.Stop(200 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
		t.Errorf("Stop returned after %v, before the grace period", elapsed)
	}
	var ee *exec.ExitError
	if !errors.As(p.ExitErr(), &ee) || ee.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL { //nolint:forcetypeassert // Unix wait status
		t.Errorf("exit = %v, want SIGKILL", p.ExitErr())
	}
}

func TestOOMScoreAdj(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	p := startHelper(t, "sleep", Spec{OOMScoreAdj: ChildOOMScoreAdj})
	data, err := os.ReadFile("/proc/" + strconv.Itoa(p.PID()) + "/oom_score_adj")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(data)); got != strconv.Itoa(ChildOOMScoreAdj) {
		t.Errorf("oom_score_adj = %s, want %d", got, ChildOOMScoreAdj)
	}
}

func TestStartFailure(t *testing.T) {
	t.Parallel()
	if _, err := Start(Spec{Path: "/nonexistent/server"}); err == nil {
		t.Error("Start of a missing command succeeded")
	}
}

func TestLineLog(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	var added atomic.Int32
	var ll *LineLog
	ll = NewLineLog(logger, func(s string) string { return strings.ReplaceAll(s, "first", "[F]") }, 0, func() {
		// The line is kept before onLine runs, and no lock of the LineLog is held.
		if n := added.Add(1); len(ll.Tail()) != int(n) {
			t.Errorf("onLine %d sees %d lines", n, len(ll.Tail()))
		}
	})
	p := startHelper(t, "stderr", Spec{Stderr: ll})
	if err := p.ExitErr(); err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(time.Second); err != nil {
		t.Fatal(err)
	}
	tail := ll.Tail()
	if len(tail) != 3 || tail[0] != "[F] line" || !strings.HasSuffix(tail[1], " [truncated]") ||
		len(tail[1]) != MaxLineBytes+len(" [truncated]") || tail[2] != "last line without newline" {
		t.Errorf("tail = %q", tail)
	}
	if n := added.Load(); n != 3 {
		t.Errorf("onLine was called %d times, want 3", n)
	}
	if strings.Contains(logs.String(), "first line") || !strings.Contains(logs.String(), "[F] line") {
		t.Errorf("the filter was not applied to the log: %s", logs.String())
	}
}

func TestLineLogLimits(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	ll := NewLineLog(slog.New(slog.NewTextHandler(&logs, nil)), nil, 100, nil)
	var in strings.Builder
	for i := range 500 {
		fmt.Fprintf(&in, "line %03d\n", i)
	}
	ll.Consume(strings.NewReader(in.String()))
	tail := ll.Tail()
	if len(tail) == 0 || tail[len(tail)-1] != "line 499" || len(strings.Join(tail, "")) > 100 {
		t.Errorf("tail = %q", tail)
	}
	if n := strings.Count(logs.String(), "child stderr\""); n == 0 || n > lineBurst+5 {
		t.Errorf("%d lines logged, want at most about %d", n, lineBurst)
	}
}

func TestSubreaperReapsOrphans(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	// Not parallel: it makes the test process a subreaper.
	r, err := EnableSubreaper()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	p := startHelper(t, "orphan", Spec{})
	gc, err := strconv.Atoi(readLine(t, p.Stdout()))
	if err != nil {
		t.Fatal(err)
	}
	<-p.Done()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, ppid, ok := procStat(gc)
		if !ok {
			break // reaped
		}
		if ppid != os.Getpid() && ppid != gc {
			t.Fatalf("the orphan's parent is %d, not the subreaper %d", ppid, os.Getpid())
		}
		if time.Now().After(deadline) {
			t.Fatal("the orphan was not reaped")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestNonDumpable(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	// The flag is set in a helper, so the test process keeps its own.
	plain := startHelper(t, "ready", Spec{Env: []string{"VISIBLE=1"}})
	readLine(t, plain.Stdout())
	if _, err := os.ReadFile("/proc/" + strconv.Itoa(plain.PID()) + "/environ"); err != nil {
		t.Fatalf("the environment of a dumpable child is not readable: %v", err)
	}
	hidden := startHelper(t, "nondumpable", Spec{Env: []string{"HIDDEN=1"}})
	if got := readLine(t, hidden.Stdout()); got != "ready" {
		t.Fatalf("helper said %q", got)
	}
	if _, err := os.ReadFile("/proc/" + strconv.Itoa(hidden.PID()) + "/environ"); err == nil {
		t.Error("the environment of a non-dumpable process is readable by the same user")
	}
}

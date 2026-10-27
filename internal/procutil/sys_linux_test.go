package procutil

import (
	"errors"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestRetryDenied(t *testing.T) {
	t.Parallel()
	failing := func(errs ...error) (func() error, *int) {
		calls := 0
		return func() error {
			calls++
			if calls <= len(errs) {
				return errs[calls-1]
			}
			return nil
		}, &calls
	}
	pathErr := func(op string, errno syscall.Errno) error {
		return &os.PathError{Op: op, Path: "/proc/1/oom_score_adj", Err: errno}
	}

	// An open refused while the child is still in exec succeeds once exec is done.
	write, calls := failing(pathErr("open", syscall.EACCES), pathErr("open", syscall.EPERM), pathErr("open", syscall.EACCES))
	if err := retryDenied(write, time.Second); err != nil || *calls != 4 {
		t.Errorf("transient denial: %v after %d calls, want success after 4", err, *calls)
	}

	// Other errors, such as a child that is gone, are not retried, and neither is a write the
	// kernel refuses once the file is open.
	for _, e := range []error{pathErr("open", syscall.ENOENT), pathErr("write", syscall.EACCES), errors.New("other")} {
		write, calls = failing(e)
		if err := retryDenied(write, time.Second); !errors.Is(err, e) || *calls != 1 {
			t.Errorf("%v: %v after %d calls, want it after 1", e, err, *calls)
		}
	}

	// A denial that lasts is returned once the time is up.
	const d = 50 * time.Millisecond
	n := 0
	start := time.Now()
	err := retryDenied(func() error { n++; return pathErr("open", syscall.EPERM) }, d)
	if took := time.Since(start); !errors.Is(err, syscall.EPERM) || took > d+200*time.Millisecond || n < 2 {
		t.Errorf("lasting denial: %v after %d calls in %v", err, n, took)
	}
}

// TestOOMScoreAdjRetriesDeniedOpen checks that setOOMScoreAdj retries an open the kernel refuses:
// a child that made itself non-dumpable leaves its /proc files to root for good.
func TestOOMScoreAdjRetriesDeniedOpen(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root may write the files of a non-dumpable process")
	}
	p := startHelper(t, "nondumpable", Spec{})
	if got := readLine(t, p.Stdout()); got != "ready" {
		t.Fatalf("helper: %s", got)
	}
	start := time.Now()
	err := setOOMScoreAdj(p.PID(), ChildOOMScoreAdj)
	if took := time.Since(start); !errors.Is(err, fs.ErrPermission) || took < oomRetryFor/2 {
		t.Errorf("setOOMScoreAdj = %v after %v, want a permission error after retrying for about %v", err, took, oomRetryFor)
	}
}

func TestParseChildren(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		in   string
		want []int
	}{
		{"", nil},
		{"\n", nil},
		{"42 ", []int{42}},
		{"42 7 1003 ", []int{42, 7, 1003}},
		{"42 7\n", []int{42, 7}},
		{"42 x 7 -1 0 ", []int{42, 7}}, // what is not a PID is skipped
	} {
		if got := parseChildren([]byte(c.in)); !slices.Equal(got, c.want) {
			t.Errorf("parseChildren(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestChildPIDs checks that both ways of listing the gate's children find a child.
func TestChildPIDs(t *testing.T) {
	t.Parallel()
	p := startHelper(t, "sleep", Spec{})
	if pids := scanChildren(os.Getpid()); !slices.Contains(pids, p.PID()) {
		t.Errorf("the /proc scan found %v, not the child %d", pids, p.PID())
	}
	if _, err := os.Stat("/proc/self/task/" + strconv.Itoa(os.Getpid()) + "/children"); err != nil {
		t.Skip("the kernel has no /proc/<pid>/task/<tid>/children")
	}
	pids, ok := threadChildren()
	if !ok || !slices.Contains(pids, p.PID()) {
		t.Errorf("the children files list %v (%v), not the child %d", pids, ok, p.PID())
	}
}

package procutil

import (
	"bytes"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// SetNonDumpable marks the gate's process as not dumpable, so processes of the same user (such
// as its children) cannot read its memory or /proc/<pid>/environ, where its secrets are.
func SetNonDumpable() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

func setOOMScoreAdj(pid, adj int) error {
	return os.WriteFile("/proc/"+strconv.Itoa(pid)+"/oom_score_adj", []byte(strconv.Itoa(adj)), 0)
}

// Reaper reaps orphaned descendants that the kernel reparents to the gate once it is a child
// subreaper. Children started by Start are left to their Process.
type Reaper struct {
	stop chan struct{}
	done chan struct{}
}

// reapInterval is how often the reaper scans when no SIGCHLD arrives.
const reapInterval = time.Second

// EnableSubreaper makes the gate a child subreaper, so that grandchildren whose parent exits
// are reparented to the gate instead of init, and starts reaping them. Close undoes both.
func EnableSubreaper() (*Reaper, error) {
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return nil, err
	}
	r := &Reaper{stop: make(chan struct{}), done: make(chan struct{})}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGCHLD)
	go func() {
		defer close(r.done)
		defer signal.Stop(sigs)
		tick := time.NewTicker(reapInterval)
		defer tick.Stop()
		for {
			reapOrphans()
			select {
			case <-r.stop:
				return
			case <-sigs:
			case <-tick.C:
			}
		}
	}()
	return r, nil
}

// Close stops reaping and clears the subreaper flag.
func (r *Reaper) Close() {
	_ = unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0)
	close(r.stop)
	<-r.done
	reapOrphans()
}

// reapOrphans waits for every zombie child of the gate that Start did not start.
func reapOrphans() {
	self := os.Getpid()
	managed.Lock()
	defer managed.Unlock()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || managed.pids[pid] {
			continue
		}
		state, ppid, ok := procStat(pid)
		if !ok || ppid != self || state != 'Z' {
			continue
		}
		var ws unix.WaitStatus
		_, _ = unix.Wait4(pid, &ws, unix.WNOHANG, nil)
	}
}

// procStat reads the state and the parent PID from /proc/<pid>/stat.
func procStat(pid int) (state byte, ppid int, ok bool) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, 0, false
	}
	// The command name in parentheses may contain anything; the fields after the last ')' are
	// " <state> <ppid> ...".
	i := bytes.LastIndexByte(data, ')')
	if i < 0 {
		return 0, 0, false
	}
	fields := bytes.Fields(data[i+1:])
	if len(fields) < 2 || len(fields[0]) != 1 {
		return 0, 0, false
	}
	ppid, err = strconv.Atoi(string(fields[1]))
	if err != nil {
		return 0, 0, false
	}
	return fields[0][0], ppid, true
}

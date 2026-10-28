package procutil

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// Spec describes a child process.
type Spec struct {
	Path string
	Args []string
	// Dir is the working directory; empty is the gate's.
	Dir string
	// Env is the complete environment; nil is an empty one, never the gate's.
	Env []string
	// Stderr receives the child's stderr; nil discards it.
	Stderr *LineLog
	// OOMScoreAdj, if not zero, is written to the child's oom_score_adj after it starts.
	OOMScoreAdj int
}

// ChildOOMScoreAdj is the OOM score adjustment for MCP server children: the kernel kills one of
// them before the gate.
const ChildOOMScoreAdj = 500

// killWait bounds the wait for a process group after SIGKILL.
const killWait = 5 * time.Second

// drainWait bounds the wait, once the group is gone, for the stderr reader to read what is left
// in the pipe, which a process outside the group may still hold.
const drainWait = time.Second

// Process is a running child in a process group of its own, with pipes on stdin and stdout.
type Process struct {
	pid    int
	stdin  *os.File
	stdout *os.File
	stderr *os.File

	oomErr     error
	done       chan struct{} // closed when the leader has exited and been reaped
	exitErr    error
	stderrDone chan struct{}

	stopOnce sync.Once
	stopErr  error
}

// managed holds the PIDs of the children started by Start; the reaper leaves them to their
// Process. mu is held while a child starts and while the reaper scans, so a new child is
// always registered before the reaper can see it.
var managed = struct {
	sync.Mutex
	pids map[int]bool
}{pids: map[int]bool{}}

// groups holds the Processes whose process group may still have members: from Start until the
// group is found empty, after the leader was reaped, by Stop or by the wait for the leader.
// KillAll kills them.
var groups = struct {
	sync.Mutex
	set map[*Process]struct{}
}{set: map[*Process]struct{}{}}

// forget drops p from groups once its group is empty.
func (p *Process) forget() {
	groups.Lock()
	delete(groups.set, p)
	groups.Unlock()
}

// Start starts the child described by spec. Every child of the gate must be started here, so
// that the reaper does not take its exit status.
func Start(spec Spec) (p *Process, err error) {
	var files []*os.File
	pipe := func() (r, w *os.File) {
		if err != nil {
			return nil, nil
		}
		r, w, err = os.Pipe()
		files = append(files, r, w)
		return r, w
	}
	inR, inW := pipe()
	outR, outW := pipe()
	errR, errW := pipe()
	if err != nil {
		closeAll(files)
		return nil, err
	}
	cmd := exec.Command(spec.Path, spec.Args...) //nolint:gosec,noctx // the command is the operator's config; the Process owns its lifetime
	cmd.Dir = spec.Dir
	cmd.Env = spec.Env
	if cmd.Env == nil {
		cmd.Env = []string{}
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inR, outW, errW
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	managed.Lock()
	err = cmd.Start()
	if err == nil {
		managed.pids[cmd.Process.Pid] = true
	}
	managed.Unlock()
	closeAll([]*os.File{inR, outW, errW})
	if err != nil {
		closeAll([]*os.File{inW, outR, errR})
		return nil, err
	}
	p = &Process{
		pid: cmd.Process.Pid, stdin: inW, stdout: outR, stderr: errR,
		done: make(chan struct{}), stderrDone: make(chan struct{}),
	}
	groups.Lock()
	groups.set[p] = struct{}{}
	groups.Unlock()
	if spec.OOMScoreAdj != 0 {
		p.oomErr = setOOMScoreAdj(p.pid, spec.OOMScoreAdj)
	}
	go func() {
		p.exitErr = cmd.Wait()
		managed.Lock()
		delete(managed.pids, p.pid)
		managed.Unlock()
		close(p.done)
		if groupGone(p.pid) {
			p.forget()
		}
	}()
	go func() {
		defer close(p.stderrDone)
		if spec.Stderr == nil {
			_, _ = io.Copy(io.Discard, errR)
			return
		}
		spec.Stderr.Consume(errR)
	}()
	return p, nil
}

func closeAll(files []*os.File) {
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
}

// OOMScoreErr is the error from setting Spec.OOMScoreAdj, if any.
func (p *Process) OOMScoreErr() error { return p.oomErr }

// PID is the child's process ID, which is also its process group ID.
func (p *Process) PID() int { return p.pid }

// Stdin is the write end of the child's stdin.
func (p *Process) Stdin() io.WriteCloser { return p.stdin }

// Stdout is the read end of the child's stdout.
func (p *Process) Stdout() io.ReadCloser { return p.stdout }

// Done is closed when the child (the group leader) has exited.
func (p *Process) Done() <-chan struct{} { return p.done }

// ExitErr is the result of waiting for the child; it is valid once Done is closed.
func (p *Process) ExitErr() error {
	<-p.done
	return p.exitErr
}

// Stop ends the whole process group: it closes stdin, sends SIGTERM to the group, waits up to
// grace for the leader and every other member to exit, then sends SIGKILL to the group and waits
// again. It returns once the group is gone and stderr is drained, or after drainWait more when
// a process outside the group still holds stderr, or with an error if the group survived
// SIGKILL. Stop may be called more than once; later calls return the first result.
// Since it waits for the stderr reader, which runs the LineLog's onLine, it must not be called
// with a lock that onLine takes.
func (p *Process) Stop(grace time.Duration) error {
	p.stopOnce.Do(func() { p.stopErr = p.stop(grace) })
	return p.stopErr
}

func (p *Process) stop(grace time.Duration) error {
	_ = p.stdin.Close()
	p.signal(syscall.SIGTERM)
	gone := p.waitGone(grace)
	if !gone {
		p.signal(syscall.SIGKILL)
		gone = p.waitGone(killWait)
	}
	// Once the group is gone, the stderr reader reads what is left in the pipe and meets EOF;
	// closing the read end before would lose the last lines. Members that left the group
	// (setsid, setpgid) or that the gate cannot signal may still hold the pipe, so after
	// drainWait the read end is closed, which stops the reader; when the group survived SIGKILL
	// it is closed at once. Stdout needs no draining: the connection on it is done.
	_ = p.stdout.Close()
	if gone {
		drain := time.NewTimer(drainWait)
		select {
		case <-p.stderrDone:
		case <-drain.C:
		}
		drain.Stop()
	}
	_ = p.stderr.Close()
	<-p.stderrDone
	if gone {
		p.forget()
	}
	if !gone {
		return fmt.Errorf("process group %d is still running after SIGKILL", p.pid)
	}
	return nil
}

// signal sends sig to the process group. Once the leader is reaped, its PID stays reserved only
// while a member of its group is left; when none is, the PID may already belong to an unrelated
// process, so nothing is sent.
func (p *Process) signal(sig syscall.Signal) {
	select {
	case <-p.done:
		if groupGone(p.pid) {
			return
		}
	default:
	}
	_ = syscall.Kill(-p.pid, sig)
}

// waitGone waits up to d for the leader to be reaped and the group to be empty.
func (p *Process) waitGone(d time.Duration) bool {
	deadline := time.NewTimer(d)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-p.done:
			reapGroup(p.pid)
			if groupGone(p.pid) {
				return true
			}
		default:
		}
		select {
		case <-deadline.C:
			return false
		case <-tick.C:
		}
	}
}

// reapGroup waits for members of the group pgid that exited after being reparented to the
// gate (when it is a subreaper). It must only run after the leader was reaped: the leader is the
// only member Start created, and its status belongs to its Process.
func reapGroup(pgid int) {
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-pgid, &ws, syscall.WNOHANG, nil)
		if pid <= 0 || err != nil {
			return
		}
	}
}

// groupGone reports whether no process is left in the process group pgid. A group whose
// members cannot be signalled (EPERM) counts as gone: the gate cannot end them anyway. Zombies
// count as left on Linux but not on darwin, where kill(2) of a group whose only members are
// zombies fails with EPERM.
func groupGone(pgid int) bool {
	err := syscall.Kill(-pgid, 0)
	return errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.EPERM)
}

// KillAll sends SIGKILL to the process group of every child Start started whose group may still
// have members, its leader exited or not, without waiting, for a forced exit. As Stop does, it
// sends nothing to a group whose leader was reaped and that has no member left, whose ID may
// have been reused.
func KillAll() {
	groups.Lock()
	defer groups.Unlock()
	for p := range groups.set {
		p.signal(syscall.SIGKILL)
	}
}

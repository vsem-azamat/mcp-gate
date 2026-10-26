// Package systemd implements the two parts of the systemd service protocol the gate uses: socket
// activation (a listening socket passed in LISTEN_FDS) and readiness notification (sd_notify on
// NOTIFY_SOCKET). It needs no systemd library; without systemd both are no-ops.
package systemd

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// Environment variables of the protocol. None of them is meant for the gate's children.
const (
	ListenPIDEnv     = "LISTEN_PID"
	ListenFDsEnv     = "LISTEN_FDS"
	ListenFDNamesEnv = "LISTEN_FDNAMES"
	NotifySocketEnv  = "NOTIFY_SOCKET"
)

// Vars lists the protocol's environment variables, which the gate does not pass on.
var Vars = []string{ListenPIDEnv, ListenFDsEnv, ListenFDNamesEnv, NotifySocketEnv}

// listenFDsStart is the first file descriptor systemd passes.
const listenFDsStart = 3

// Notification states the gate sends.
const (
	Ready    = "READY=1"
	Stopping = "STOPPING=1"
)

// Reloading is the notification that a reload of the config begins, with the time on the
// monotonic clock that systemd asks for; READY=1 tells it the reload is over.
func Reloading() string {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return "RELOADING=1"
	}
	return "RELOADING=1\nMONOTONIC_USEC=" + strconv.FormatInt(ts.Nano()/1000, 10)
}

// Listener returns the TCP listening socket systemd passed to this process, or nil when it passed
// none: LISTEN_FDS unset, or LISTEN_PID naming another process (a parent that did not clear the
// variables). Passing more than one socket, or one that is not a listening TCP socket, is an
// error. lookup reads the environment, pid is this process's ID.
func Listener(lookup func(string) (string, bool), pid int) (net.Listener, error) {
	return listener(lookup, pid, listenFDsStart)
}

func listener(lookup func(string) (string, bool), pid, fd int) (net.Listener, error) {
	fds, ok := lookup(ListenFDsEnv)
	if !ok || fds == "" {
		return nil, nil
	}
	if p, _ := lookup(ListenPIDEnv); p != strconv.Itoa(pid) {
		return nil, nil
	}
	n, err := strconv.Atoi(fds)
	switch {
	case err != nil || n < 0:
		return nil, fmt.Errorf("%s=%q is not a number of sockets", ListenFDsEnv, fds)
	case n == 0:
		return nil, nil
	case n > 1:
		return nil, fmt.Errorf("systemd passed %d sockets; the gate serves exactly one (one ListenStream= in the socket unit)", n)
	}
	// FileListener takes a connected socket too, which fails only at the first accept.
	if !listening(fd) {
		return nil, errors.New("the socket systemd passed is not a listening socket (Accept=no in the socket unit)")
	}
	f := os.NewFile(uintptr(fd), "systemd-socket")
	if f == nil {
		return nil, fmt.Errorf("file descriptor %d is not valid", fd)
	}
	// FileListener duplicates the descriptor, close-on-exec, so no child inherits the socket.
	ln, err := net.FileListener(f)
	_ = f.Close()
	if err != nil {
		return nil, fmt.Errorf("the socket systemd passed is not a listening socket: %w", err)
	}
	if _, ok := ln.Addr().(*net.TCPAddr); !ok {
		_ = ln.Close()
		return nil, fmt.Errorf("the socket systemd passed is %s, not TCP: ListenStream= takes an address and port", ln.Addr().Network())
	}
	return ln, nil
}

// Notifier sends state notifications to systemd. The zero value, and a Notifier without a socket,
// send nothing.
type Notifier struct {
	addr *net.UnixAddr
}

// NewNotifier returns a notifier for the socket NOTIFY_SOCKET names: an absolute path, or an
// abstract socket written with a leading @.
func NewNotifier(lookup func(string) (string, bool)) (*Notifier, error) {
	path, ok := lookup(NotifySocketEnv)
	if !ok || path == "" {
		return &Notifier{}, nil
	}
	switch path[0] {
	case '/':
	case '@':
		path = "\x00" + path[1:]
	default:
		return nil, fmt.Errorf("%s is neither an absolute path nor an abstract socket", NotifySocketEnv)
	}
	return &Notifier{addr: &net.UnixAddr{Name: path, Net: "unixgram"}}, nil
}

// Enabled reports whether notifications go anywhere.
func (n *Notifier) Enabled() bool { return n != nil && n.addr != nil }

// Notify sends state, one or more NAME=value lines, to systemd.
func (n *Notifier) Notify(state string) error {
	if !n.Enabled() {
		return nil
	}
	conn, err := net.DialUnix("unixgram", nil, n.addr)
	if err != nil {
		return err
	}
	_, err = conn.Write([]byte(state))
	return errors.Join(err, conn.Close())
}

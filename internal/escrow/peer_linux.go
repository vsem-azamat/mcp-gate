package escrow

import (
	"bytes"
	"errors"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// fdPeerCred reads the peer's user ID and process ID with SO_PEERCRED: the credentials it had
// when it connected.
func fdPeerCred(fd int) (uid, pid int, err error) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, 0, err
	}
	return int(cred.Uid), int(cred.Pid), nil
}

// maxTreeDepth bounds the walk up the process tree.
const maxTreeDepth = 4096

// outsideGateTree reports whether the process pid is neither the gate nor one of its
// descendants, walking up the parent IDs in /proc/<pid>/stat. The gate is a child subreaper, so
// a descendant whose parent exits is reparented to the gate and stays in its tree. When the
// process cannot be read (it has exited, or /proc is hidden), the answer is false: the peer
// then needs the key.
func outsideGateTree(pid int) bool {
	self := os.Getpid()
	for range maxTreeDepth {
		switch {
		case pid == self:
			return false
		case pid <= 1:
			return pid == 1 // pid 0 is no process; reaching init means the chain left the gate
		}
		ppid, err := parentPID(pid)
		if err != nil {
			return false
		}
		pid = ppid
	}
	return false
}

// parentPID reads the parent process ID from /proc/<pid>/stat. The command name, in parentheses,
// may hold any byte, so the fields are read after its last ')'.
func parentPID(pid int) (int, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, err
	}
	i := bytes.LastIndexByte(data, ')')
	if i < 0 {
		return 0, errors.New("unexpected /proc stat")
	}
	fields := bytes.Fields(data[i+1:]) // state, ppid, …
	if len(fields) < 2 {
		return 0, errors.New("unexpected /proc stat")
	}
	return strconv.Atoi(string(fields[1]))
}

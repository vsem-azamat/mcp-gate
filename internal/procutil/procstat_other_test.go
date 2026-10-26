//go:build !linux

package procutil

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
)

// procStat reads the state and the parent PID of a process with ps(1); the tests use it where
// there is no /proc to read.
func procStat(pid int) (state byte, ppid int, ok bool) {
	out, err := exec.CommandContext(context.Background(), "ps", "-o", "stat=", "-o", "ppid=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0, 0, false
	}
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return 0, 0, false
	}
	ppid, err = strconv.Atoi(fields[1])
	if err != nil {
		return 0, 0, false
	}
	return fields[0][0], ppid, true
}

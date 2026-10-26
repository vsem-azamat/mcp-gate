package systemd

import "syscall"

// listening reports whether fd is a socket that listens.
func listening(fd int) bool {
	v, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ACCEPTCONN)
	return err == nil && v != 0
}

package escrow

import "golang.org/x/sys/unix"

// fdPeerUID reads the peer's user ID with SO_PEERCRED: the credentials it had when it connected.
func fdPeerUID(fd int) (int, error) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, err
	}
	return int(cred.Uid), nil
}

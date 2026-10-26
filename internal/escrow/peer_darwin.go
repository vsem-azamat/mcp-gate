package escrow

import "golang.org/x/sys/unix"

// fdPeerCred reads the peer's user ID with LOCAL_PEERCRED: the credentials it had when it
// connected. The process ID is not read.
func fdPeerCred(fd int) (uid, pid int, err error) {
	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, 0, err
	}
	return int(cred.Uid), 0, nil
}

// outsideGateTree is not checked on macOS: a peer of an allowed user ID is served without a key
// even when it is the gate's descendant.
func outsideGateTree(int) bool { return true }

//go:build !linux && !darwin

package escrow

import "errors"

var errNoPeerCred = errors.New("peer credentials are not available on this system")

// fdPeerCred cannot read peer credentials here: every socket peer needs the key.
func fdPeerCred(int) (uid, pid int, err error) { return 0, 0, errNoPeerCred }

func outsideGateTree(int) bool { return false }

// OthersProcVisible is true: without peer credentials no peer is served without a key anyway.
func OthersProcVisible() bool { return true }

//go:build !linux && !darwin

package escrow

import "errors"

var errNoPeerCred = errors.New("peer credentials are not available on this system")

// fdPeerUID cannot read peer credentials here: every socket peer needs the key.
func fdPeerUID(int) (int, error) { return 0, errNoPeerCred }

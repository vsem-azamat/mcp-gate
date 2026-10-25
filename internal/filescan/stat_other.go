//go:build !linux && !darwin

package filescan

import (
	"os"
	"time"
)

// inode cannot read a link count or an inode change time here, so every file under a root fails
// its check and withholds its result.
func inode(os.FileInfo) (links uint64, changed time.Time, ok bool) { return 0, time.Time{}, false }

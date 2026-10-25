package filescan

import (
	"os"
	"syscall"
	"time"
)

// inode returns a file's link count and the time its inode last changed.
func inode(info os.FileInfo) (links uint64, changed time.Time, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, time.Time{}, false
	}
	return uint64(st.Nlink), time.Unix(st.Ctimespec.Unix()), true
}

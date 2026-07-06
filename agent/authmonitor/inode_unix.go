//go:build unix

package authmonitor

import (
	"os"
	"syscall"
)

// inodeOf reports the file's inode, used to detect log rotation (same path,
// new inode → reopen the file).
func inodeOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

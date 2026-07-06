//go:build windows

package authmonitor

import "os"

// inodeOf has no Windows equivalent that matters here: this package tails
// Unix auth logs, which don't exist on Windows (login failures come from the
// Security event log instead). Returning 0 disables the inode-based rotation
// check while keeping the package cross-compilable.
func inodeOf(fi os.FileInfo) uint64 {
	return 0
}

//go:build linux

package disk_usage

import (
	"bufio"
	"os"
	"strings"
	"syscall"
)

// pseudo-filesystems to skip
var skipFSTypes = map[string]bool{
	"proc":        true,
	"sysfs":       true,
	"devtmpfs":    true,
	"tmpfs":       true,
	"devpts":      true,
	"securityfs":  true,
	"cgroup":      true,
	"cgroup2":     true,
	"pstore":      true,
	"debugfs":     true,
	"hugetlbfs":   true,
	"mqueue":      true,
	"configfs":    true,
	"fusectl":     true,
	"binfmt_misc": true,
	"autofs":      true,
	"tracefs":     true,
	"nsfs":        true,
	"overlay":     true,
	"squashfs":    true,
	"efivarfs":    true,
	"bpf":         true,
	"ramfs":       true,
}

// collectFilesystems reads /proc/mounts and stats each real filesystem.
func collectFilesystems() ([]fsUsage, error) {
	mounts, err := getMounts()
	if err != nil {
		return nil, err
	}

	var filesystems []fsUsage
	for _, mount := range mounts {
		var stat syscall.Statfs_t
		if err := syscall.Statfs(mount.mountPoint, &stat); err != nil {
			log.Debug().Msgf("disk_usage.collectFilesystems - failed to statfs %s: %s", mount.mountPoint, err.Error())
			continue
		}

		// Skip filesystems with 0 total blocks (virtual/pseudo)
		if stat.Blocks == 0 {
			continue
		}

		totalBytes := stat.Blocks * uint64(stat.Bsize)
		freeBytes := stat.Bfree * uint64(stat.Bsize)
		availBytes := stat.Bavail * uint64(stat.Bsize)

		filesystems = append(filesystems, fsUsage{
			device:     mount.device,
			mountPoint: mount.mountPoint,
			fsType:     mount.fsType,
			totalBytes: totalBytes,
			usedBytes:  totalBytes - freeBytes,
			freeBytes:  freeBytes,
			availBytes: availBytes,
		})
	}
	return filesystems, nil
}

type mountInfo struct {
	device     string
	mountPoint string
	fsType     string
}

// getMounts reads /proc/mounts and returns real filesystems
func getMounts() ([]mountInfo, error) {
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	seen := make(map[string]bool)
	var mounts []mountInfo

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}

		device := fields[0]
		mountPoint := fields[1]
		fsType := fields[2]

		// Skip pseudo-filesystems
		if skipFSTypes[fsType] {
			continue
		}

		// Skip duplicate mount points (keep first)
		if seen[mountPoint] {
			continue
		}
		seen[mountPoint] = true

		mounts = append(mounts, mountInfo{
			device:     device,
			mountPoint: mountPoint,
			fsType:     fsType,
		})
	}

	return mounts, scanner.Err()
}

// sanitizeMountPath converts a mount path into a safe metric prefix
// e.g. "/" -> "root", "/var/log" -> "var_log"
func sanitizeMountPath(path string) string {
	if path == "/" {
		return "root"
	}
	path = strings.TrimPrefix(path, "/")
	path = strings.ReplaceAll(path, "/", "_")
	path = strings.ReplaceAll(path, "-", "_")
	path = strings.ReplaceAll(path, ".", "_")
	return path
}

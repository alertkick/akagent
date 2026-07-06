//go:build windows

package disk_usage

import (
	"strings"

	"github.com/shirou/gopsutil/disk"
)

// collectFilesystems enumerates local volumes via gopsutil (GetLogicalDrives
// + GetDiskFreeSpaceEx under the hood). Removable/CD-ROM drives with no
// media surface as Usage errors and are skipped.
func collectFilesystems() ([]fsUsage, error) {
	partitions, err := disk.Partitions(false)
	if err != nil {
		return nil, err
	}

	var filesystems []fsUsage
	for _, p := range partitions {
		usage, err := disk.Usage(p.Mountpoint)
		if err != nil {
			log.Debug().Msgf("disk_usage.collectFilesystems - failed to stat %s: %s", p.Mountpoint, err.Error())
			continue
		}
		if usage.Total == 0 {
			continue
		}

		filesystems = append(filesystems, fsUsage{
			device:     p.Device,
			mountPoint: p.Mountpoint,
			fsType:     p.Fstype,
			totalBytes: usage.Total,
			usedBytes:  usage.Used,
			freeBytes:  usage.Free,
			availBytes: usage.Free,
		})
	}
	return filesystems, nil
}

// sanitizeMountPath converts a Windows mount path into a safe metric prefix
// e.g. `C:\` -> "c", `D:\data` -> "d_data"
func sanitizeMountPath(path string) string {
	path = strings.ToLower(path)
	path = strings.ReplaceAll(path, ":", "")
	path = strings.Trim(path, `\`)
	path = strings.ReplaceAll(path, `\`, "_")
	path = strings.ReplaceAll(path, "/", "_")
	path = strings.ReplaceAll(path, "-", "_")
	path = strings.ReplaceAll(path, ".", "_")
	path = strings.ReplaceAll(path, " ", "_")
	return path
}

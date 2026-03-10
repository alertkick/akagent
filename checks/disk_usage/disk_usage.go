//go:build linux

package disk_usage

import (
	"apagent/checks"
	"apagent/internal/api"
	"apagent/logger"
	"bufio"
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	log = logger.Sublogger("host.disk_usages")
)

// pseudo-filesystems to skip
var skipFSTypes = map[string]bool{
	"proc":       true,
	"sysfs":      true,
	"devtmpfs":   true,
	"tmpfs":      true,
	"devpts":     true,
	"securityfs": true,
	"cgroup":     true,
	"cgroup2":    true,
	"pstore":     true,
	"debugfs":    true,
	"hugetlbfs":  true,
	"mqueue":     true,
	"configfs":   true,
	"fusectl":    true,
	"binfmt_misc": true,
	"autofs":     true,
	"tracefs":    true,
	"nsfs":       true,
	"overlay":    true,
	"squashfs":   true,
	"efivarfs":   true,
	"bpf":        true,
	"ramfs":      true,
}

func init() {
	checks.Add("host.disk_usages", func() api.Check {
		return &DiskUsageCheck{
			UUID:      "host.disk_usages",
			Name:      "host.disk_usages",
			Label:     "host.disk_usages",
			CheckType: "host.disk_usages",
			interval:  60,
		}
	})
	checks.AddConfig("host.disk_usages")
}

// DiskUsageCheck monitors disk usage on all mounted filesystems
type DiskUsageCheck struct {
	UUID        string
	Name        string
	Label       string
	CheckType   string
	resultsChan chan api.CheckMetricParams
	lock        sync.Mutex
	debug       bool
	interval    int
	Details     interface{} `json:"details"`
}

func (c *DiskUsageCheck) Init(resultsQueue chan api.CheckMetricParams, check api.AgentCheck) error {
	c.resultsChan = resultsQueue
	c.UUID = check.UUID
	c.Label = check.Label
	c.Details = check.Details
	if check.Period != 0 {
		c.interval = check.Period
	}
	return nil
}

func (c *DiskUsageCheck) Start(stopCtx context.Context, debug bool) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	log.Debug().Msgf("disk_usage.Start - %s monitor started with %d seconds interval", c.Name, c.interval)

	ticker := time.NewTicker(time.Duration(c.interval) * time.Second)
	defer ticker.Stop()

	for {
		if err := c.RunAndSend(); err != nil {
			log.Info().Msgf("disk_usage.Start - can not collect and send metrics, exiting: %s\n", err.Error())
		}
		select {
		case <-stopCtx.Done():
			log.Info().Msgf("disk_usage.Start - %s monitor stopped", c.Name)
			return nil
		case <-ticker.C:
			continue
		}
	}
}

func (c *DiskUsageCheck) Stop() error {
	return nil
}

func (c *DiskUsageCheck) RunAndSend() error {
	mounts, err := getMounts()
	if err != nil {
		return err
	}

	var metricGroups []api.MetricGroup
	fsCount := 0

	for _, mount := range mounts {
		var stat syscall.Statfs_t
		if err := syscall.Statfs(mount.mountPoint, &stat); err != nil {
			log.Debug().Msgf("disk_usage.RunAndSend - failed to statfs %s: %s", mount.mountPoint, err.Error())
			continue
		}

		// Skip filesystems with 0 total blocks (virtual/pseudo)
		if stat.Blocks == 0 {
			continue
		}

		totalBytes := stat.Blocks * uint64(stat.Bsize)
		freeBytes := stat.Bfree * uint64(stat.Bsize)
		availBytes := stat.Bavail * uint64(stat.Bsize)
		usedBytes := totalBytes - freeBytes

		var percentUsed float64
		if totalBytes > 0 {
			percentUsed = float64(usedBytes) / float64(totalBytes) * 100
		}

		metrics := make(map[string]api.Metric)
		metrics["total_bytes"] = api.Metric{Type: "total_bytes", Value: strconv.FormatUint(totalBytes, 10), Unit: "uint64"}
		metrics["used_bytes"] = api.Metric{Type: "used_bytes", Value: strconv.FormatUint(usedBytes, 10), Unit: "uint64"}
		metrics["free_bytes"] = api.Metric{Type: "free_bytes", Value: strconv.FormatUint(freeBytes, 10), Unit: "uint64"}
		metrics["avail_bytes"] = api.Metric{Type: "avail_bytes", Value: strconv.FormatUint(availBytes, 10), Unit: "uint64"}
		metrics["percent_used"] = api.Metric{Type: "percent_used", Value: strconv.FormatFloat(percentUsed, 'f', 2, 64), Unit: "float64"}
		metrics["mount_point"] = api.Metric{Type: "mount_point", Value: mount.mountPoint, Unit: "string"}
		metrics["fs_type"] = api.Metric{Type: "fs_type", Value: mount.fsType, Unit: "string"}
		metrics["device"] = api.Metric{Type: "device", Value: mount.device, Unit: "string"}

		prefix := "disk." + sanitizeMountPath(mount.mountPoint)
		metricGroups = append(metricGroups, api.MetricGroup{
			Prefix:  prefix,
			Metrics: metrics,
		})
		fsCount++
	}

	// Summary metric group
	summaryMetrics := make(map[string]api.Metric)
	summaryMetrics["filesystem_count"] = api.Metric{Type: "filesystem_count", Value: strconv.Itoa(fsCount), Unit: "int"}
	metricGroups = append(metricGroups, api.MetricGroup{
		Prefix:  "disk",
		Metrics: summaryMetrics,
	})

	result := api.CheckMetricParams{
		Timestamp:      time.Now().UnixNano() / int64(time.Millisecond),
		CheckID:        "host.disk_usages",
		CheckType:      "host.disk_usages",
		State:          "ok",
		Status:         "ok",
		MinCheckPeriod: int64(c.interval),
		MetricGroups:   metricGroups,
	}

	log.Debug().Msgf("disk_usage.RunAndSend - submitting: %s, %d filesystems", c.Label, fsCount)
	c.resultsChan <- result

	return nil
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

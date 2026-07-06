//go:build linux || windows

package disk_usage

import (
	"akagent/checks"
	"akagent/internal/api"
	"akagent/logger"
	"context"
	"strconv"
	"sync"
	"time"
)

var (
	log = logger.Sublogger("host.disk_usages")
)

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

// fsUsage is one mounted filesystem's usage snapshot, produced by the
// platform-specific collectFilesystems.
type fsUsage struct {
	device     string
	mountPoint string
	fsType     string
	totalBytes uint64
	usedBytes  uint64
	freeBytes  uint64
	availBytes uint64
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
	filesystems, err := collectFilesystems()
	if err != nil {
		return err
	}

	var metricGroups []api.MetricGroup
	fsCount := 0

	for _, fs := range filesystems {
		var percentUsed float64
		if fs.totalBytes > 0 {
			percentUsed = float64(fs.usedBytes) / float64(fs.totalBytes) * 100
		}

		metrics := make(map[string]api.Metric)
		metrics["total_bytes"] = api.Metric{Type: "total_bytes", Value: strconv.FormatUint(fs.totalBytes, 10), Unit: "uint64"}
		metrics["used_bytes"] = api.Metric{Type: "used_bytes", Value: strconv.FormatUint(fs.usedBytes, 10), Unit: "uint64"}
		metrics["free_bytes"] = api.Metric{Type: "free_bytes", Value: strconv.FormatUint(fs.freeBytes, 10), Unit: "uint64"}
		metrics["avail_bytes"] = api.Metric{Type: "avail_bytes", Value: strconv.FormatUint(fs.availBytes, 10), Unit: "uint64"}
		metrics["percent_used"] = api.Metric{Type: "percent_used", Value: strconv.FormatFloat(percentUsed, 'f', 2, 64), Unit: "float64"}
		metrics["mount_point"] = api.Metric{Type: "mount_point", Value: fs.mountPoint, Unit: "string"}
		metrics["fs_type"] = api.Metric{Type: "fs_type", Value: fs.fsType, Unit: "string"}
		metrics["device"] = api.Metric{Type: "device", Value: fs.device, Unit: "string"}

		prefix := "disk." + sanitizeMountPath(fs.mountPoint)
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

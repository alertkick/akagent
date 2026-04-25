//go:build linux

package memory

import (
	"akagent/checks"
	"akagent/internal/api"
	"akagent/logger"
	"bufio"
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	log = logger.Sublogger("host.memory")
)

func init() {
	checks.Add("host.memory", func() api.Check {
		return &MemoryUsageCheck{
			UUID:      "host.memory",
			Name:      "host.memory",
			Label:     "host.memory",
			CheckType: "host.memory",
			interval:  30,
		}
	})
	checks.AddConfig("host.memory")
}

// MemoryUsageCheck - struct for memory usage check
type MemoryUsageCheck struct {
	UUID        string
	Name        string
	Label       string
	CheckType   string
	resultsChan chan api.CheckMetricParams
	// goroutine management
	lock     sync.Mutex
	debug    bool
	interval int
	Details  interface{} `json:"details"`
}

func (c *MemoryUsageCheck) Init(resultsQueue chan api.CheckMetricParams, check api.AgentCheck) error {
	c.resultsChan = resultsQueue
	c.UUID = check.UUID
	c.Label = check.Label
	c.Details = check.Details
	if check.Period != 0 {
		c.interval = check.Period
	}
	return nil
}

func (c *MemoryUsageCheck) Start(stopCtx context.Context, debug bool) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	log.Debug().Msgf("memory.Start - %s monitor started with %d seconds interval", c.Name, c.interval)

	ticker := time.NewTicker(time.Duration(c.interval) * time.Second)
	defer ticker.Stop()

	for {
		if err := c.RunAndSend(); err != nil {
			log.Info().Msgf("memory.Start - can not collect and send metrics, exiting: %s\n", err.Error())
		}
		select {
		case <-stopCtx.Done():
			log.Info().Msgf("memory.Start - %s monitor stopped", c.Name)
			return nil
		case <-ticker.C:
			continue
		}
	}
}

func (c *MemoryUsageCheck) Stop() error {
	return nil
}

func (c *MemoryUsageCheck) RunAndSend() error {
	memoryMetricsGroup := api.MetricGroup{
		Prefix:  "memory",
		Metrics: memoryUsages(),
	}

	result := api.CheckMetricParams{
		Timestamp:      time.Now().UnixNano() / int64(time.Millisecond),
		CheckID:        "host.memory",
		CheckType:      "host.memory",
		State:          "ok",
		Status:         "ok",
		MinCheckPeriod: int64(c.interval),
		MetricGroups: []api.MetricGroup{
			memoryMetricsGroup,
		},
	}

	log.Debug().Msgf("memory.RunAndSend - submitting: %s, %v", c.Label, result)
	c.resultsChan <- result

	return nil
}

// memoryUsages - return a map with memory usages stats
func memoryUsages() map[string]api.Metric {
	metrics := make(map[string]api.Metric)

	mInfo, err := getMemInfo()
	if err != nil {
		return metrics
	}

	total := (*mInfo)["MemTotal"]
	used := (*mInfo)["MemTotal"] - (*mInfo)["MemFree"] - (*mInfo)["Buffers"] - (*mInfo)["Cached"]
	free := (*mInfo)["MemFree"]
	shared := (*mInfo)["Shmem"]
	buffers := (*mInfo)["Buffers"]
	cached := (*mInfo)["Cached"]
	swapUsed := (*mInfo)["SwapTotal"] - (*mInfo)["SwapFree"]
	swapFree := (*mInfo)["SwapFree"]

	metrics["total"] = api.Metric{Type: "total", Value: strconv.FormatFloat(total, 'f', -1, 64), Unit: "float64"}
	metrics["used"] = api.Metric{Type: "used", Value: strconv.FormatFloat(used, 'f', -1, 64), Unit: "float64"}
	metrics["free"] = api.Metric{Type: "free", Value: strconv.FormatFloat(free, 'f', -1, 64), Unit: "float64"}
	metrics["shared"] = api.Metric{Type: "shared", Value: strconv.FormatFloat(shared, 'f', -1, 64), Unit: "float64"}
	metrics["buffers"] = api.Metric{Type: "buffers", Value: strconv.FormatFloat(buffers, 'f', -1, 64), Unit: "float64"}
	metrics["cached"] = api.Metric{Type: "cached", Value: strconv.FormatFloat(cached, 'f', -1, 64), Unit: "float64"}
	metrics["swap_used"] = api.Metric{Type: "swap_used", Value: strconv.FormatFloat(swapUsed, 'f', -1, 64), Unit: "float64"}
	metrics["swap_free"] = api.Metric{Type: "swap_free", Value: strconv.FormatFloat(swapFree, 'f', -1, 64), Unit: "float64"}

	return metrics
}

func getMemInfo() (*map[string]float64, error) {
	m := make(map[string]float64)

	path := "/proc/meminfo"

	file, err := os.Open(path)
	if err != nil {
		return &m, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()

		n := strings.Index(text, ":")
		if n == -1 {
			continue
		}

		key := text[:n]
		data := strings.Split(strings.Trim(text[(n+1):], " "), " ")
		if len(data) == 1 {
			value, err := strconv.ParseFloat(data[0], 10)
			if err != nil {
				continue
			}
			m[key] = value
		} else if len(data) == 2 {
			if data[1] == "kB" {
				value, err := strconv.ParseFloat(data[0], 10)
				if err != nil {
					continue
				}

				m[key] = value
			}
		}
	}

	return &m, nil
}

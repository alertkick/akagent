//go:build linux || windows

package memory

import (
	"akagent/checks"
	"akagent/internal/api"
	"akagent/logger"
	"context"
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

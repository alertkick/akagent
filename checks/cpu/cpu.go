package cpu

import (
	"apagent/checks"
	"apagent/internal/api"
	"apagent/logger"
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"time"

	"github.com/shirou/gopsutil/cpu"
)

var (
	log = logger.Sublogger("host.cpu")
)

func init() {
	checks.Add("host.cpu", func() api.Check {
		return &CPUCheck{
			UUID:      "host.cpu",
			Name:      "host.cpu",
			Label:     "host.cpu",
			CheckType: "host.cpu",
			interval:  30,
		}
	})
	checks.AddConfig("host.cpu")
}

// CPUCheck monitors CPU usage metrics including user, system, idle, and iowait
type CPUCheck struct {
	UUID        string
	Name        string
	Label       string
	CheckType   string
	resultsChan chan api.CheckMetricParams
	// goroutine management
	lock     sync.Mutex
	debug    bool
	interval int
}

func (c *CPUCheck) Init(resultsQueue chan api.CheckMetricParams, agentCheck api.AgentCheck) error {
	c.resultsChan = resultsQueue
	c.Label = agentCheck.Label
	if agentCheck.Period != 0 {
		c.interval = agentCheck.Period
	}
	return nil
}

func (c *CPUCheck) Start(stopCtx context.Context, debug bool) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	log.Debug().Msgf("cpu.Start - %s monitor started with %d seconds interval", c.Name, c.interval)

	ticker := time.NewTicker(time.Duration(c.interval) * time.Second)
	defer ticker.Stop()

	for {
		if err := c.RunAndSend(); err != nil {
			log.Info().Msgf("cpu.Start - can not collect and send metrics, exiting: %s\n", err.Error())
		}
		select {
		case <-stopCtx.Done():
			log.Info().Msgf("cpu.Start - %s monitor stopped", c.Name)
			return nil
		case <-ticker.C:
			continue
		}
	}
}

func (c *CPUCheck) Stop() error {
	return nil
}

func (c *CPUCheck) RunAndSend() error {
	log.Debug().Msg("cpu.RunAndSend - started collecting")
	cpuMetricsGroup := api.MetricGroup{
		Prefix:  "cpu",
		Metrics: CPUUsage(),
	}

	result := api.CheckMetricParams{
		Timestamp:      time.Now().UnixNano() / int64(time.Millisecond),
		CheckID:        "host.cpu",
		CheckType:      "host.cpu",
		State:          "ok",
		Status:         "ok",
		MinCheckPeriod: int64(c.interval),
		MetricGroups: []api.MetricGroup{
			cpuMetricsGroup,
		},
	}

	log.Debug().Msgf("cpu.RunAndSend - submitting: %s, %v", c.Label, result)
	c.resultsChan <- result
	return nil
}

// CPUUsageStruct - returns CPU usage stats
type CPUUsageStruct struct {
	User   float64 `json:"user"`
	Idle   float64 `json:"idle"`
	Nice   float64 `json:"nice"`
	Steal  float64 `json:"steal"`
	System float64 `json:"system"`
	IOWait float64 `json:"iowait"`
}

func (p CPUUsageStruct) String() string {
	s, _ := json.Marshal(p)
	return string(s)
}

// totalCPUTime calculates the total CPU time from all CPU states
func totalCPUTime(t cpu.TimesStat) float64 {
	total := t.User + t.System + t.Nice + t.Iowait + t.Irq + t.Softirq + t.Steal +
		t.Guest + t.GuestNice + t.Idle
	return total
}

// CPUUsage - return a map with CPU usage stats
func CPUUsage() map[string]api.Metric {
	cpuTimes1, err := cpu.Times(false)
	if err != nil {
		log.Err(err).Msg("cpu.CPUUsage - error getting CPU info")
	}

	metrics := make(map[string]api.Metric)
	for i, lastCts := range cpuTimes1 {
		lastTotal := totalCPUTime(lastCts)
		time.Sleep(1 * time.Second)

		cpuTimes2, _ := cpu.Times(false)
		cts := cpuTimes2[i]
		total := totalCPUTime(cts)

		totalDelta := total - lastTotal

		system := 100 * (cts.System - lastCts.System) / totalDelta
		nice := 100 * (cts.Nice - lastCts.Nice) / totalDelta
		user := 100 * (cts.User - lastCts.User) / totalDelta
		idle := 100 * (cts.Idle - lastCts.Idle) / totalDelta
		iowait := 100 * (cts.Iowait - lastCts.Iowait) / totalDelta
		steal := 100 * (cts.Steal - lastCts.Steal) / totalDelta

		systemPercent, _ := checks.FloatDecimalPoint(system, 2)
		nicePercent, _ := checks.FloatDecimalPoint(nice, 2)
		userPercent, _ := checks.FloatDecimalPoint(user, 2)
		idlePercent, _ := checks.FloatDecimalPoint(idle, 2)
		iowaitPercent, _ := checks.FloatDecimalPoint(iowait, 2)
		stealPercent, _ := checks.FloatDecimalPoint(steal, 2)

		metrics["user"] = api.Metric{Type: "user", Value: strconv.FormatFloat(userPercent, 'f', -1, 64), Unit: "float64"}
		metrics["idle"] = api.Metric{Type: "idle", Value: strconv.FormatFloat(idlePercent, 'f', -1, 64), Unit: "float64"}
		metrics["nice"] = api.Metric{Type: "nice", Value: strconv.FormatFloat(nicePercent, 'f', -1, 64), Unit: "float64"}
		metrics["steal"] = api.Metric{Type: "steal", Value: strconv.FormatFloat(stealPercent, 'f', -1, 64), Unit: "float64"}
		metrics["system"] = api.Metric{Type: "system", Value: strconv.FormatFloat(systemPercent, 'f', -1, 64), Unit: "float64"}
		metrics["iowait"] = api.Metric{Type: "iowait", Value: strconv.FormatFloat(iowaitPercent, 'f', -1, 64), Unit: "float64"}
	}

	return metrics
}

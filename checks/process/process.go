//go:build linux || windows

package process

import (
	"akagent/checks"
	"akagent/internal/api"
	"akagent/logger"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	log = logger.Sublogger("host.monitor_process")
)

func init() {
	checks.Add("host.monitor_process", func() api.Check {
		return &ProcessCheck{
			UUID:      "host.monitor_process",
			Name:      "host.monitor_process",
			Label:     "host.monitor_process",
			CheckType: "host.monitor_process",
			interval:  30,
			firstRun:  true,
		}
	})
	checks.AddConfig("host.monitor_process")
}

// ProcessCheckDetails is the configuration parsed from AgentCheck.Details
type ProcessCheckDetails struct {
	ProcessName string `json:"process_name"`
}

// ProcessCheck monitors a named process on the system
type ProcessCheck struct {
	UUID        string
	Name        string
	Label       string
	CheckType   string
	resultsChan chan api.CheckMetricParams
	lock        sync.Mutex
	debug       bool
	interval    int
	processName string
	prevRunning bool
	firstRun    bool
}

func (c *ProcessCheck) Init(resultsQueue chan api.CheckMetricParams, agentCheck api.AgentCheck) error {
	c.resultsChan = resultsQueue
	c.UUID = agentCheck.UUID
	c.Label = agentCheck.Label
	if agentCheck.Period != 0 {
		c.interval = agentCheck.Period
	}

	// Parse process_name from Details
	if len(agentCheck.Details) > 0 {
		var details ProcessCheckDetails
		if err := json.Unmarshal(agentCheck.Details, &details); err != nil {
			return fmt.Errorf("failed to parse process check details: %w", err)
		}
		c.processName = details.ProcessName
	}

	if c.processName == "" {
		return fmt.Errorf("process_name is required in check details")
	}

	return nil
}

func (c *ProcessCheck) Start(stopCtx context.Context, debug bool) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	log.Debug().Msgf("process.Start - %s monitor started for '%s' with %d seconds interval", c.Name, c.processName, c.interval)

	ticker := time.NewTicker(time.Duration(c.interval) * time.Second)
	defer ticker.Stop()

	for {
		if err := c.RunAndSend(); err != nil {
			log.Info().Msgf("process.Start - can not collect and send metrics, exiting: %s\n", err.Error())
		}
		select {
		case <-stopCtx.Done():
			log.Info().Msgf("process.Start - %s monitor stopped", c.Name)
			return nil
		case <-ticker.C:
			continue
		}
	}
}

func (c *ProcessCheck) Stop() error {
	return nil
}

func (c *ProcessCheck) RunAndSend() error {
	pids := c.findProcessPIDs()
	running := len(pids) > 0

	metrics := make(map[string]api.Metric)
	metrics["process_name"] = api.Metric{Type: "process_name", Value: c.processName, Unit: "string"}

	if running {
		metrics["running"] = api.Metric{Type: "running", Value: "1", Unit: "int"}
		metrics["pid_count"] = api.Metric{Type: "pid_count", Value: strconv.Itoa(len(pids)), Unit: "int"}

		// Aggregate CPU and memory across all PIDs
		var totalCPU float64
		var totalRSS uint64
		for _, pid := range pids {
			cpu := readProcCPU(pid)
			rss := readProcRSS(pid)
			totalCPU += cpu
			totalRSS += rss
		}
		metrics["cpu_percent"] = api.Metric{Type: "cpu_percent", Value: strconv.FormatFloat(totalCPU, 'f', 2, 64), Unit: "float64"}
		metrics["memory_rss"] = api.Metric{Type: "memory_rss", Value: strconv.FormatUint(totalRSS, 10), Unit: "uint64"}
	} else {
		metrics["running"] = api.Metric{Type: "running", Value: "0", Unit: "int"}
		metrics["pid_count"] = api.Metric{Type: "pid_count", Value: "0", Unit: "int"}
		metrics["cpu_percent"] = api.Metric{Type: "cpu_percent", Value: "0", Unit: "float64"}
		metrics["memory_rss"] = api.Metric{Type: "memory_rss", Value: "0", Unit: "uint64"}
	}

	state := "ok"
	status := "ok"
	if !running {
		state = "critical"
		status = "CRITICAL"
	}

	processMetricGroup := api.MetricGroup{
		Prefix:  "process",
		Metrics: metrics,
	}

	result := api.CheckMetricParams{
		Timestamp:      time.Now().UnixNano() / int64(time.Millisecond),
		CheckID:        c.UUID,
		CheckType:      "host.monitor_process",
		State:          state,
		Status:         status,
		MinCheckPeriod: int64(c.interval),
		MetricGroups: []api.MetricGroup{
			processMetricGroup,
		},
	}

	log.Debug().Msgf("process.RunAndSend - submitting: %s, process=%s running=%v pids=%d", c.Label, c.processName, running, len(pids))
	c.resultsChan <- result

	// Detect state changes and send host events
	if !c.firstRun {
		if c.prevRunning && !running {
			c.sendHostEvent("process_stopped", "WARNING",
				fmt.Sprintf("Process '%s' has stopped", c.processName))
		} else if !c.prevRunning && running {
			c.sendHostEvent("process_started", "NOTICE",
				fmt.Sprintf("Process '%s' has started (PIDs: %s)", c.processName, joinPIDs(pids)))
		}
	}

	c.prevRunning = running
	c.firstRun = false

	return nil
}

// sendHostEvent sends a host event for process state changes
func (c *ProcessCheck) sendHostEvent(eventType, priority, description string) {
	log.Info().Msgf("process.sendHostEvent - %s: %s", eventType, description)

	metrics := make(map[string]api.Metric)
	metrics["event_type"] = api.Metric{Type: "event_type", Value: eventType, Unit: "string"}
	metrics["process_name"] = api.Metric{Type: "process_name", Value: c.processName, Unit: "string"}
	metrics["description"] = api.Metric{Type: "description", Value: description, Unit: "string"}
	metrics["priority"] = api.Metric{Type: "priority", Value: priority, Unit: "string"}

	hostEventGroup := api.MetricGroup{
		Prefix:  "host_event",
		Metrics: metrics,
	}

	result := api.CheckMetricParams{
		Timestamp:      time.Now().UnixNano() / int64(time.Millisecond),
		CheckID:        "host.process_change",
		CheckType:      "host.process_change",
		State:          eventType,
		Status:         priority,
		MinCheckPeriod: int64(c.interval),
		MetricGroups: []api.MetricGroup{
			hostEventGroup,
		},
	}

	c.resultsChan <- result
}

func joinPIDs(pids []int) string {
	strs := make([]string, len(pids))
	for i, pid := range pids {
		strs[i] = strconv.Itoa(pid)
	}
	return strings.Join(strs, ",")
}

package load_avg

import (
	"akagent/checks"
	"akagent/internal/api"
	"akagent/logger"
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/shirou/gopsutil/load"
)

var (
	log = logger.Sublogger("host.load_avg")
)

func init() {
	checks.Add("host.load_avg", func() api.Check {
		return &LoadAverageCheck{
			UUID:      "host.load_avg",
			Name:      "host.load_avg",
			Label:     "host.load_avg",
			CheckType: "host.load_avg",
			interval:  30,
		}
	})
	checks.AddConfig("host.load_avg")
}

// LoadAverageCheck - XXX
type LoadAverageCheck struct {
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

func (c *LoadAverageCheck) Init(resultsQueue chan api.CheckMetricParams, agentCheck api.AgentCheck) error {
	c.resultsChan = resultsQueue
	c.UUID = agentCheck.UUID
	c.Label = agentCheck.Label
	if agentCheck.Period != 0 {
		c.interval = agentCheck.Period
	}
	return nil
}

func (c *LoadAverageCheck) Start(stopCtx context.Context, debug bool) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	log.Debug().Msgf("load_avg.Start - %s monitor started with %d seconds interval", c.Name, c.interval)

	ticker := time.NewTicker(time.Duration(c.interval) * time.Second)
	defer ticker.Stop()

	for {
		if err := c.RunAndSend(); err != nil {
			log.Info().Msgf("load_avg.Start - can not collect and send metrics, exiting: %s\n", err.Error())
		}
		select {
		case <-stopCtx.Done():
			log.Info().Msgf("load_avg.Start - %s monitor stopped", c.Name)
			return nil
		case <-ticker.C:
			continue
		}
	}
}

func (c *LoadAverageCheck) Stop() error {
	return nil
}

func (c *LoadAverageCheck) RunAndSend() error {
	log.Debug().Msg("load_avg.RunAndSend - started collecting")
	loadMetricsGroup := api.MetricGroup{
		Prefix:  "load_avg",
		Metrics: LoadAverage(),
	}

	result := api.CheckMetricParams{
		Timestamp:      time.Now().UnixNano() / int64(time.Millisecond),
		CheckID:        c.Label,
		CheckType:      c.CheckType,
		State:          "ok",
		Status:         "ok",
		MinCheckPeriod: int64(c.interval),
		MetricGroups: []api.MetricGroup{
			loadMetricsGroup,
		},
	}

	log.Debug().Msgf("load_avg.RunAndSend - submitting: %s, %v", c.Label, result)
	c.resultsChan <- result
	return nil
}

// LoadAverage - returns load avg
func LoadAverage() map[string]api.Metric {

	// cores, _ := cpu.Counts(true)
	load, _ := load.Avg()

	metrics := make(map[string]api.Metric)

	metrics["1m"] = api.Metric{
		Type:  "1m",
		Value: strconv.FormatFloat(load.Load1, 'f', -1, 64),
		Unit:  "float64",
	}
	metrics["5m"] = api.Metric{
		Type:  "5m",
		Value: strconv.FormatFloat(load.Load5, 'f', -1, 64),
		Unit:  "float64",
	}
	metrics["15m"] = api.Metric{
		Type:  "15m",
		Value: strconv.FormatFloat(load.Load15, 'f', -1, 64),
		Unit:  "float64",
	}

	return metrics
}

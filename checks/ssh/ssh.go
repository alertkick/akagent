package ssh

import (
	"apagent/checks"
	"apagent/internal/api"
	"apagent/logger"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	log = logger.Sublogger("remote.ssh")
)

func init() {
	checks.Add("remote.ssh", func() api.Check {
		return &SSHCheck{
			Name:      "remote.ssh",
			Label:     "remote.ssh",
			CheckType: "remote.ssh",
			interval:  60,
		}
	})
	checks.AddConfig("remote.ssh")
}

type SSHCheck struct {
	UUID        string
	Name        string
	Label       string
	CheckType   string
	resultsChan chan api.CheckMetricParams
	interval    int
	config      SSHCheckConfig

	lock sync.Mutex
}

type SSHCheckConfig struct {
	Hostname string `json:"hostname"`
	Port     int    `json:"port"`
}

func (c *SSHCheck) Init(resultsQueue chan api.CheckMetricParams, check api.AgentCheck) error {
	c.resultsChan = resultsQueue
	c.UUID = check.UUID
	c.Label = check.Label
	if check.Period != 0 {
		c.interval = check.Period
	}

	var config SSHCheckConfig
	err := json.Unmarshal(check.Details, &config)
	if err != nil {
		return err
	}

	if config.Port == 0 {
		config.Port = 22
	}

	c.config = config
	return nil
}

func (c *SSHCheck) Start(stopCtx context.Context, debug bool) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	log.Debug().Msgf("%s monitor started with %d seconds interval", c.Name, c.interval)

	ticker := time.NewTicker(time.Duration(c.interval) * time.Second)
	defer ticker.Stop()

	for {
		if err := c.RunAndSend(); err != nil {
			log.Info().Msgf("Can not collect and send metrics, exiting: %s\n", err.Error())
		}
		select {
		case <-stopCtx.Done():
			log.Info().Msgf("%s monitor stopped", c.Name)
			return nil
		case <-ticker.C:
			continue
		}
	}
}

func (c *SSHCheck) Stop() error {
	return nil
}

func (c *SSHCheck) RunAndSend() error {
	metrics, state, status := c.RunCheck()

	sshMetricsGroup := api.MetricGroup{
		Prefix:  c.Label + ".ssh",
		Metrics: metrics,
	}

	result := api.CheckMetricParams{
		Timestamp:      time.Now().UnixNano() / int64(time.Millisecond),
		CheckID:        c.UUID,
		CheckType:      "remote.ssh",
		State:          state,
		Status:         status,
		MinCheckPeriod: int64(c.interval),
		MetricGroups: []api.MetricGroup{
			sshMetricsGroup,
		},
	}

	log.Debug().Msgf("RunAndSend submitting: %s, %v", c.Label+".ssh", result)
	c.resultsChan <- result

	return nil
}

func (c *SSHCheck) RunCheck() (map[string]api.Metric, string, string) {
	metrics := make(map[string]api.Metric)

	addr := fmt.Sprintf("%s:%d", c.config.Hostname, c.config.Port)

	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	connectTime := time.Since(start)

	statusVal := 0.0
	state := "ok"
	status := "ok"

	if err != nil {
		state = "failed"
		status = "failed"
		metrics["fail_reason"] = api.Metric{Type: "fail_reason", Value: err.Error(), Unit: "string"}
	} else {
		// Read the SSH banner to verify it's actually an SSH server
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 256)
		n, readErr := conn.Read(buf)
		conn.Close()

		if readErr != nil {
			state = "failed"
			status = "failed"
			metrics["fail_reason"] = api.Metric{Type: "fail_reason", Value: "no_ssh_banner", Unit: "string"}
		} else {
			banner := strings.TrimSpace(string(buf[:n]))
			if strings.HasPrefix(banner, "SSH-") {
				statusVal = 1.0
				metrics["banner"] = api.Metric{Type: "banner", Value: banner, Unit: "string"}
			} else {
				state = "failed"
				status = "failed"
				metrics["fail_reason"] = api.Metric{Type: "fail_reason", Value: "not_ssh_server", Unit: "string"}
			}
		}
	}

	metrics["status"] = api.Metric{Type: "status", Value: strconv.FormatFloat(statusVal, 'f', -1, 64), Unit: "float64"}
	metrics["connect_time"] = api.Metric{Type: "connect_time", Value: strconv.FormatFloat(float64(connectTime.Milliseconds()), 'f', -1, 64), Unit: "float64"}

	return metrics, state, status
}

package memory

import (
	"akagent/checks"
	"akagent/internal/api"
	"akagent/logger"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"
)

var (
	log = logger.Sublogger("remote.http")
)

func init() {
	checks.Add("remote.http", func() api.Check {
		return &HTTPCheck{
			Name:      "remote.http",
			Label:     "remote.http",
			CheckType: "remote.http",
			interval:  30,
		}
	})
	checks.AddConfig("remote.http")
}

// HTTPCheck - struct for memory usage check
type HTTPCheck struct {
	UUID        string
	Name        string
	Label       string
	CheckType   string
	resultsChan chan api.CheckMetricParams
	interval    int
	URL         string
	Method      string
	Timeout     int

	// goroutine management
	lock sync.Mutex
}

type HTTPCheckConfig struct {
	Method string
	URL    string
}

func (c *HTTPCheck) Init(resultsQueue chan api.CheckMetricParams, check api.AgentCheck) error {
	c.resultsChan = resultsQueue
	c.UUID = check.UUID
	c.Label = check.Label
	if check.Period != 0 {
		c.interval = check.Period
	}

	// parse check.Details to HTTPCheckConfig
	var config HTTPCheckConfig
	err := json.Unmarshal(check.Details, &config)
	if err != nil {
		return err
	}

	c.URL = config.URL
	c.Method = config.Method
	return nil
}

func (c *HTTPCheck) Start(stopCtx context.Context, debug bool) error {
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

func (c *HTTPCheck) Stop() error {
	return nil
}

func (c *HTTPCheck) RunAndSend() error {
	httpMetricsGroup := api.MetricGroup{
		Prefix:  c.Label + ".http",
		Metrics: c.RunCheck(),
	}

	result := api.CheckMetricParams{
		Timestamp:      time.Now().UnixNano() / int64(time.Millisecond),
		CheckID:        c.UUID,
		CheckType:      "remote.http",
		State:          "ok",
		Status:         "ok",
		MinCheckPeriod: int64(c.interval),
		MetricGroups: []api.MetricGroup{
			httpMetricsGroup,
		},
	}

	log.Debug().Msgf("RunAndSend submitting: %s, %v", c.Label+".http", result)
	c.resultsChan <- result

	return nil
}

// httpOutput - return a map with memory usages stats
func (c *HTTPCheck) RunCheck() map[string]api.Metric {
	metrics := make(map[string]api.Metric)

	result := CheckURL(c.URL, c.Method)

	status := 0.0
	responseTime := 0.0
	timeToFirstByte := 0.0

	if result.Status == "ok" {
		status = 1.0
		responseTime = float64(result.ResponseTime.Milliseconds())
		timeToFirstByte = float64(result.TimeToFirstByte.Milliseconds())
	}
	metrics["status"] = api.Metric{Type: "status", Value: strconv.FormatFloat(status, 'f', -1, 64), Unit: "float64"}
	metrics["response_time"] = api.Metric{Type: "response_time", Value: strconv.FormatFloat(responseTime, 'f', -1, 64), Unit: "float64"}
	metrics["time_to_first_byte"] = api.Metric{Type: "time_to_first_byte", Value: strconv.FormatFloat(timeToFirstByte, 'f', -1, 64), Unit: "float64"}

	return metrics
}

// Result struct to hold the HTTP check result
type Result struct {
	URL             string
	Status          string
	ResponseTime    time.Duration
	TimeToFirstByte time.Duration
}

// CheckURL function to perform the HTTP check
func CheckURL(url, method string) Result {
	result := Result{URL: url}

	start := time.Now()
	req, _ := http.NewRequest(method, url, nil)

	// Measure the time to first byte
	ttfbStart := time.Now()
	reqTtfb := req.Clone(req.Context())
	reqTtfb.Header.Set("Connection", "close")
	tr := &http.Transport{}
	client := &http.Client{Transport: tr}
	ttfbResp, err := client.Do(reqTtfb)
	if err != nil {
		result.Status = "failed"
		return result
	}
	defer ttfbResp.Body.Close()
	ttfbDuration := time.Since(ttfbStart)
	result.TimeToFirstByte = ttfbDuration

	// Measure the total response time
	resp, err := client.Do(req)
	if err != nil {
		result.Status = "failed"
		return result
	}
	defer resp.Body.Close()
	result.ResponseTime = time.Since(start)

	if resp.StatusCode == http.StatusOK {
		result.Status = "ok"
	} else {
		result.Status = "failed"
	}

	return result
}

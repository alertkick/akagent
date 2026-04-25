package http

import (
	"akagent/checks"
	"akagent/internal/api"
	"akagent/logger"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
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

type HTTPCheck struct {
	UUID        string
	Name        string
	Label       string
	CheckType   string
	resultsChan chan api.CheckMetricParams
	interval    int
	config      HTTPCheckConfig
	Timeout     int

	lock sync.Mutex
}

type HTTPCheckConfig struct {
	URL                string `json:"url"`
	Method             string `json:"method"`
	Body               string `json:"body"`
	ExpectedStatusCode int    `json:"expected_status_code"`
	ExpectedOutput     string `json:"expected_output"`
	AuthType           string `json:"auth_type"`
	AuthUsername        string `json:"auth_username"`
	AuthPassword       string `json:"auth_password"`
	AuthToken          string `json:"auth_token"`
	AuthHeaderName     string `json:"auth_header_name"`
	AuthHeaderValue    string `json:"auth_header_value"`
}

func (c *HTTPCheck) Init(resultsQueue chan api.CheckMetricParams, check api.AgentCheck) error {
	c.resultsChan = resultsQueue
	c.UUID = check.UUID
	c.Label = check.Label
	if check.Period != 0 {
		c.interval = check.Period
	}

	var config HTTPCheckConfig
	err := json.Unmarshal(check.Details, &config)
	if err != nil {
		return err
	}

	if config.Method == "" {
		config.Method = "GET"
	}
	if config.ExpectedStatusCode == 0 {
		config.ExpectedStatusCode = 200
	}

	c.config = config
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
	metrics, state, status := c.RunCheck()

	httpMetricsGroup := api.MetricGroup{
		Prefix:  c.Label + ".http",
		Metrics: metrics,
	}

	result := api.CheckMetricParams{
		Timestamp:      time.Now().UnixNano() / int64(time.Millisecond),
		CheckID:        c.UUID,
		CheckType:      "remote.http",
		State:          state,
		Status:         status,
		MinCheckPeriod: int64(c.interval),
		MetricGroups: []api.MetricGroup{
			httpMetricsGroup,
		},
	}

	log.Debug().Msgf("RunAndSend submitting: %s, %v", c.Label+".http", result)
	c.resultsChan <- result

	return nil
}

func (c *HTTPCheck) RunCheck() (map[string]api.Metric, string, string) {
	metrics := make(map[string]api.Metric)

	result := CheckURL(c.config)

	statusVal := 0.0
	responseTime := 0.0
	timeToFirstByte := 0.0
	state := "ok"
	status := "ok"

	if result.Status == "ok" {
		statusVal = 1.0
		responseTime = float64(result.ResponseTime.Milliseconds())
		timeToFirstByte = float64(result.TimeToFirstByte.Milliseconds())
	} else {
		state = "failed"
		status = "failed"
	}

	metrics["status"] = api.Metric{Type: "status", Value: strconv.FormatFloat(statusVal, 'f', -1, 64), Unit: "float64"}
	metrics["response_time"] = api.Metric{Type: "response_time", Value: strconv.FormatFloat(responseTime, 'f', -1, 64), Unit: "float64"}
	metrics["time_to_first_byte"] = api.Metric{Type: "time_to_first_byte", Value: strconv.FormatFloat(timeToFirstByte, 'f', -1, 64), Unit: "float64"}
	metrics["status_code"] = api.Metric{Type: "status_code", Value: strconv.Itoa(result.StatusCode), Unit: "int"}

	if result.FailReason != "" {
		metrics["fail_reason"] = api.Metric{Type: "fail_reason", Value: result.FailReason, Unit: "string"}
	}

	return metrics, state, status
}

type Result struct {
	URL             string
	Status          string
	StatusCode      int
	ResponseTime    time.Duration
	TimeToFirstByte time.Duration
	FailReason      string
}

func CheckURL(cfg HTTPCheckConfig) Result {
	result := Result{URL: cfg.URL}

	// Build request body
	var bodyReader io.Reader
	if cfg.Body != "" && (cfg.Method == "POST" || cfg.Method == "PUT") {
		bodyReader = strings.NewReader(cfg.Body)
	}

	req, err := http.NewRequest(cfg.Method, cfg.URL, bodyReader)
	if err != nil {
		result.Status = "failed"
		result.FailReason = "invalid_request"
		return result
	}

	// Set auth headers
	switch cfg.AuthType {
	case "Basic":
		if cfg.AuthUsername != "" {
			req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(cfg.AuthUsername+":"+cfg.AuthPassword)))
		}
	case "Bearer Token":
		if cfg.AuthToken != "" {
			req.Header.Set("Authorization", "Bearer "+cfg.AuthToken)
		}
	case "Custom Header":
		if cfg.AuthHeaderName != "" {
			req.Header.Set(cfg.AuthHeaderName, cfg.AuthHeaderValue)
		}
	}

	if bodyReader != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	tr := &http.Transport{}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	// Measure time to first byte
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		result.Status = "failed"
		result.FailReason = "connection_error"
		return result
	}
	defer resp.Body.Close()
	result.TimeToFirstByte = time.Since(start)
	result.StatusCode = resp.StatusCode

	// Read body for expected output check and total response time
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // limit to 1MB
	result.ResponseTime = time.Since(start)

	// Check expected status code
	if resp.StatusCode != cfg.ExpectedStatusCode {
		result.Status = "failed"
		result.FailReason = "unexpected_status_code"
		return result
	}

	// Check expected output in response body
	if cfg.ExpectedOutput != "" {
		if err != nil {
			result.Status = "failed"
			result.FailReason = "body_read_error"
			return result
		}
		if !strings.Contains(string(bodyBytes), cfg.ExpectedOutput) {
			result.Status = "failed"
			result.FailReason = "expected_output_not_found"
			return result
		}
	}

	result.Status = "ok"
	return result
}

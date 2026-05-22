package dns

import (
	"akagent/checks"
	"akagent/internal/api"
	"akagent/logger"
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
	log = logger.Sublogger("remote.dns")
)

func init() {
	checks.Add("remote.dns", func() api.Check {
		return &DNSCheck{
			Name:      "remote.dns",
			Label:     "remote.dns",
			CheckType: "remote.dns",
			interval:  60,
		}
	})
	checks.AddConfig("remote.dns")
}

type DNSCheck struct {
	UUID        string
	Name        string
	Label       string
	CheckType   string
	resultsChan chan api.CheckMetricParams
	interval    int
	config      DNSCheckConfig

	lock sync.Mutex
}

type DNSCheckConfig struct {
	Hostname   string `json:"hostname"`
	RecordType string `json:"record_type"`
}

func (c *DNSCheck) Init(resultsQueue chan api.CheckMetricParams, check api.AgentCheck) error {
	c.resultsChan = resultsQueue
	c.UUID = check.UUID
	c.Label = check.Label
	if check.Period != 0 {
		c.interval = check.Period
	}

	var config DNSCheckConfig
	err := json.Unmarshal(check.Details, &config)
	if err != nil {
		return err
	}

	if config.RecordType == "" {
		config.RecordType = "A"
	}

	c.config = config
	return nil
}

func (c *DNSCheck) Start(stopCtx context.Context, debug bool) error {
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

func (c *DNSCheck) Stop() error {
	return nil
}

func (c *DNSCheck) RunAndSend() error {
	metrics, state, status := c.RunCheck()

	dnsMetricsGroup := api.MetricGroup{
		Prefix:  c.Label + ".dns",
		Metrics: metrics,
	}

	result := api.CheckMetricParams{
		Timestamp:      time.Now().UnixNano() / int64(time.Millisecond),
		CheckID:        c.UUID,
		CheckType:      "remote.dns",
		State:          state,
		Status:         status,
		MinCheckPeriod: int64(c.interval),
		MetricGroups: []api.MetricGroup{
			dnsMetricsGroup,
		},
	}

	log.Debug().Msgf("RunAndSend submitting: %s, %v", c.Label+".dns", result)
	c.resultsChan <- result

	return nil
}

func (c *DNSCheck) RunCheck() (map[string]api.Metric, string, string) {
	metrics := make(map[string]api.Metric)

	start := time.Now()
	records, err := resolveDNS(c.config.Hostname, c.config.RecordType)
	queryTime := time.Since(start)

	statusVal := 0.0
	state := "ok"
	status := "ok"

	if err != nil {
		state = "failed"
		status = "failed"
		metrics["fail_reason"] = api.Metric{Type: "fail_reason", Value: err.Error(), Unit: "string"}
	} else if len(records) == 0 {
		state = "failed"
		status = "failed"
		metrics["fail_reason"] = api.Metric{Type: "fail_reason", Value: "no_records_found", Unit: "string"}
	} else {
		statusVal = 1.0
		metrics["records"] = api.Metric{Type: "records", Value: strings.Join(records, ","), Unit: "string"}
		metrics["record_count"] = api.Metric{Type: "record_count", Value: strconv.Itoa(len(records)), Unit: "int"}
	}

	metrics["status"] = api.Metric{Type: "status", Value: strconv.FormatFloat(statusVal, 'f', -1, 64), Unit: "float64"}
	metrics["query_time"] = api.Metric{Type: "query_time", Value: strconv.FormatFloat(float64(queryTime.Milliseconds()), 'f', -1, 64), Unit: "float64"}
	metrics["record_type"] = api.Metric{Type: "record_type", Value: c.config.RecordType, Unit: "string"}

	return metrics, state, status
}

func resolveDNS(hostname, recordType string) ([]string, error) {
	switch strings.ToUpper(recordType) {
	case "A":
		ips, err := net.LookupHost(hostname)
		if err != nil {
			return nil, err
		}
		// Filter to IPv4 only
		var v4 []string
		for _, ip := range ips {
			if net.ParseIP(ip).To4() != nil {
				v4 = append(v4, ip)
			}
		}
		return v4, nil

	case "AAAA":
		ips, err := net.LookupHost(hostname)
		if err != nil {
			return nil, err
		}
		// Filter to IPv6 only
		var v6 []string
		for _, ip := range ips {
			if net.ParseIP(ip).To4() == nil {
				v6 = append(v6, ip)
			}
		}
		return v6, nil

	case "CNAME":
		cname, err := net.LookupCNAME(hostname)
		if err != nil {
			return nil, err
		}
		return []string{cname}, nil

	case "MX":
		mxs, err := net.LookupMX(hostname)
		if err != nil {
			return nil, err
		}
		var results []string
		for _, mx := range mxs {
			results = append(results, fmt.Sprintf("%s:%d", mx.Host, mx.Pref))
		}
		return results, nil

	case "TXT":
		txts, err := net.LookupTXT(hostname)
		if err != nil {
			return nil, err
		}
		return txts, nil

	default:
		return nil, fmt.Errorf("unsupported record type: %s", recordType)
	}
}

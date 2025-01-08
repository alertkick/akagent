package api

import (
	"context"
	"encoding/json"
)

type ConfiguredCheck struct {
	Name      string
	Check     Check
	CheckType string
	Details   json.RawMessage
}

type EnabledCheck struct {
	Name        string
	Label       string
	Check       Check
	CheckType   string
	Details     json.RawMessage
	DisplayName string
}

type CheckConfig struct {
	CheckType string
}

type Check interface {
	Init(resultsQueue chan CheckMetricParams, check AgentCheck) error
	Start(stopCtx context.Context, debug bool) error
	Stop() error
}

type CheckRegistry func() Check

type Metric struct {
	Type  string `json:"t"`
	Value string `json:"v"`
	Unit  string `json:"u"`
}

type MetricGroup struct {
	Prefix  string            `json:"prefix"`
	Metrics map[string]Metric `json:"metrics,omitempty"`
}

type CheckMetricParams struct {
	Timestamp      int64         `json:"timestamp,omitempty"`
	CheckID        string        `json:"check_id"`
	CheckType      string        `json:"check_type"`
	State          string        `json:"state"`
	Status         string        `json:"status"`
	MinCheckPeriod int64         `json:"min_check_period"`
	MetricGroups   []MetricGroup `json:"metric_groups,omitempty"`
}

// ChecksSchedule - struct for the checks message
// Example:
//
//	map[checks:[
//		map[details:map[] enabled:true id:memory period:30 timeout:10 type:agent.memory]
//		map[details:map[] enabled:true id:cpu period:30 timeout:10 type:agent.cpu]
//		map[details:map[] enabled:true id:load_average period:30 timeout:10 type:agent.load_average]]
//	]
type AgentChecks struct {
	Checks []AgentCheck `json:"checks"`
}

type AgentCheck struct {
	UUID      string          `json:"uuid"`
	Name      string          `json:"name"`
	Label     string          `json:"label"`
	CheckType string          `json:"check_type"`
	Period    int             `json:"period"`
	Timeout   int             `json:"timeout"`
	Enabled   bool            `json:"enabled"`
	Details   json.RawMessage `json:"details"`
}

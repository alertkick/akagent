package client

import (
	"akagent/internal/api"
	"encoding/json"
	"time"
)

// Error is the errors used in the protocol. Use GetErr to convert from error
// to *Error.
type Error struct {
	Field   string `json:"field"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type Message struct {
	ID        string `json:"id" bson:"id"`
	Version   string `json:"v" bson:"v"`
	Target    string `json:"target" bson:"target"`
	Source    string `json:"source" bson:"source"`
	Tenant    string `json:"tenant" bson:"tenant"`
	Subdomain string `json:"subdomain" bson:"subdomain"`
}

type Response struct {
	ID        string          `json:"id" bson:"id"`
	Version   string          `json:"v" bson:"v"`
	Target    string          `json:"target" bson:"target"`
	Source    string          `json:"source" bson:"source"`
	Tenant    string          `json:"tenant" bson:"tenant"`
	Subdomain string          `json:"subdomain" bson:"subdomain"`
	Result    json.RawMessage `json:"result" bson:"result"`
	Err       Error           `json:"error"`
}

type Request struct {
	ID        string          `json:"id" bson:"id"`
	Version   string          `json:"v" bson:"v"`
	Target    string          `json:"target" bson:"target"`
	Source    string          `json:"source" bson:"source"`
	Tenant    string          `json:"tenant" bson:"tenant"`
	Subdomain string          `json:"subdomain" bson:"subdomain"`
	Params    json.RawMessage `json:"params" bson:"params"`
	Method    string          `json:"method" bson:"method"`
}

// Heartbeat is the Params and Result for heartbeat message.
type HeartbeatMessage struct {
	Timestamp int64  `json:"timestamp"`
	CheckID   string `json:"check_id"`
	CheckType string `json:"check_type"`
	State     string `json:"state"`
	Status    string `json:"status"`
}

type FalcoEventsPost struct {
	ID        string          `json:"id" bson:"id"`
	Version   string          `json:"v" bson:"v"`
	Timestamp int64           `json:"timestamp"`
	Params    json.RawMessage `json:"params" bson:"params"`
	Source    string          `json:"source" bson:"source"`
	Tenant    string          `json:"tenant" bson:"tenant"`
	Subdomain string          `json:"subdomain" bson:"subdomain"`
	Method    string          `json:"method" bson:"method"`
}

type FalcoToggleStatus struct {
	Enabled       bool   `json:"enabled"`
	ServiceStatus string `json:"service_status"`
	Error         string `json:"error"`
}

func (f FalcoToggleStatus) String() string {
	s, _ := json.Marshal(f)
	return string(s)
}

type GeneralCommandResponse struct {
	Message string `json:"message"`
	Status  string `json:"status"`
	Error   string `json:"error"`
}

func (g GeneralCommandResponse) String() string {
	s, _ := json.Marshal(g)
	return string(s)
}

// FalcoServiceResponse represents the response for Falco service operations
type FalcoServiceResponse struct {
	Action        string `json:"action"`         // start, stop, restart, status
	Status        string `json:"status"`         // success, failed
	ServiceStatus string `json:"service_status"` // running, stopped, unknown
	Message       string `json:"message"`
	Error         string `json:"error,omitempty"`
}

func (f FalcoServiceResponse) String() string {
	s, _ := json.Marshal(f)
	return string(s)
}

// FalcoLogsResponse represents the response for Falco logs request
type FalcoLogsResponse struct {
	Logs    string `json:"logs"`
	Lines   int    `json:"lines"`
	Status  string `json:"status"` // success, failed
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
}

func (f FalcoLogsResponse) String() string {
	s, _ := json.Marshal(f)
	return string(s)
}

// FalcoConfigFile represents a single config file
type FalcoConfigFile struct {
	Path    string `json:"path"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Size    int64  `json:"size"`
	IsDir   bool   `json:"is_dir"`
}

// FalcoConfigResponse represents the response for Falco config get request
type FalcoConfigResponse struct {
	Status        string            `json:"status"` // success, failed
	ConfigFiles   []FalcoConfigFile `json:"config_files"`
	FolderListing []FalcoConfigFile `json:"folder_listing"`
	Error         string            `json:"error,omitempty"`
	Message       string            `json:"message,omitempty"`
}

func (f FalcoConfigResponse) String() string {
	s, _ := json.Marshal(f)
	return string(s)
}

// FalcoConfigTestResponse represents the response for Falco config test request
type FalcoConfigTestResponse struct {
	Status   string `json:"status"` // success, failed
	Valid    bool   `json:"valid"`
	Output   string `json:"output"`
	Error    string `json:"error,omitempty"`
	Message  string `json:"message,omitempty"`
	ExitCode int    `json:"exit_code"`
}

func (f FalcoConfigTestResponse) String() string {
	s, _ := json.Marshal(f)
	return string(s)
}

type CheckResultsPost struct {
	ID        string                `json:"id" bson:"id"`
	Version   string                `json:"v" bson:"v"`
	Target    string                `json:"target" bson:"target"`
	Source    string                `json:"source" bson:"source"`
	Tenant    string                `json:"tenant" bson:"tenant"`
	Subdomain string                `json:"subdomain" bson:"subdomain"`
	Params    api.CheckMetricParams `json:"params" bson:"params"`
	Method    string                `json:"method" bson:"method"`
}

type Params struct {
	Timestamp      time.Time     `json:"timestamp"`
	CheckID        string        `json:"check_id"`
	CheckType      string        `json:"check_type"`
	State          string        `json:"state"`
	Status         string        `json:"status"`
	MinCheckPeriod int64         `json:"min_check_period"`
	MetricGroup    []metricGroup `json:"metric_group"`
}

type metric struct {
	Type  string `json:"t"`
	Value string `json:"v"`
	Unit  string `json:"u"`
}

type metricGroup struct {
	Prefix  string            `json:"prefix"`
	Metrics map[string]metric `json:"metrics"`
}

// ChecksSchedule - struct for the checks message
// Example:
//
//	map[checks:[
//		map[details:map[] disabled:false id:memory period:30 timeout:10 type:agent.memory]
//		map[details:map[] disabled:false id:cpu period:30 timeout:10 type:agent.cpu]
//		map[details:map[] disabled:false id:load_average period:30 timeout:10 type:agent.load_average]]
//	]
type ChecksSchedule struct {
	Checks []Check `json:"checks"`
}

type Check struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Period   int                    `json:"period"`
	Timeout  int                    `json:"timeout"`
	Disabled bool                   `json:"disabled"`
	Label    string                 `json:"label"`
	Details  map[string]interface{} `json:"details"`
}

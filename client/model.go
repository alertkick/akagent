package client

import (
	"apagent/internal/api"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// GenerateCorrelationID creates a new unique correlation ID for request tracing
func GenerateCorrelationID() string {
	return uuid.New().String()
}

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
	ID            string          `json:"id" bson:"id"`
	Version       string          `json:"v" bson:"v"`
	Target        string          `json:"target" bson:"target"`
	Source        string          `json:"source" bson:"source"`
	Tenant        string          `json:"tenant" bson:"tenant"`
	Subdomain     string          `json:"subdomain" bson:"subdomain"`
	Result        json.RawMessage `json:"result" bson:"result"`
	Err           Error           `json:"error"`
	CorrelationID string          `json:"correlation_id,omitempty" bson:"correlation_id,omitempty"`
}

type Request struct {
	ID            string          `json:"id" bson:"id"`
	Version       string          `json:"v" bson:"v"`
	Target        string          `json:"target" bson:"target"`
	Source        string          `json:"source" bson:"source"`
	Tenant        string          `json:"tenant" bson:"tenant"`
	Subdomain     string          `json:"subdomain" bson:"subdomain"`
	Params        json.RawMessage `json:"params" bson:"params"`
	Method        string          `json:"method" bson:"method"`
	CorrelationID string          `json:"correlation_id,omitempty" bson:"correlation_id,omitempty"`
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

// SecurityEventsPost represents a unified security event post from any eBPF agent
type SecurityEventsPost struct {
	ID        string          `json:"id" bson:"id"`
	Version   string          `json:"v" bson:"v"`
	Timestamp int64           `json:"timestamp"`
	Params    json.RawMessage `json:"params" bson:"params"`
	Source    string          `json:"source" bson:"source"`
	Tenant    string          `json:"tenant" bson:"tenant"`
	Subdomain string          `json:"subdomain" bson:"subdomain"`
	Method    string          `json:"method" bson:"method"`
	AgentType string          `json:"agent_type" bson:"agent_type"`
}

// EBPFAgentResponse represents the response for eBPF agent operations
type EBPFAgentResponse struct {
	Action        string `json:"action"`
	AgentType     string `json:"agent_type"`
	Status        string `json:"status"`
	ServiceStatus string `json:"service_status"`
	Message       string `json:"message"`
	Error         string `json:"error,omitempty"`
}

func (e EBPFAgentResponse) String() string {
	s, _ := json.Marshal(e)
	return string(s)
}

// EBPFAgentsListResponse represents the response for listing all eBPF agents
type EBPFAgentsListResponse struct {
	Agents  []EBPFAgentInfo `json:"agents"`
	Status  string          `json:"status"`
	Message string          `json:"message,omitempty"`
	Error   string          `json:"error,omitempty"`
}

func (e EBPFAgentsListResponse) String() string {
	s, _ := json.Marshal(e)
	return string(s)
}

// EBPFAgentInfo represents information about an eBPF agent
type EBPFAgentInfo struct {
	Type          string   `json:"type"`
	Name          string   `json:"name"`
	Version       string   `json:"version,omitempty"`
	Installed     bool     `json:"installed"`
	Enabled       bool     `json:"enabled"`
	ServiceStatus string   `json:"service_status"`
	BinaryPath    string   `json:"binary_path,omitempty"`
	ConfigPath    string   `json:"config_path,omitempty"`
	RulesDir      string   `json:"rules_dir,omitempty"`
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

// NativeAgentConfigResponse represents the response for native agent config get
type NativeAgentConfigResponse struct {
	Status  string                 `json:"status"` // success, failed
	Config  NativeAgentConfig      `json:"config"`
	Error   string                 `json:"error,omitempty"`
	Message string                 `json:"message,omitempty"`
}

func (n NativeAgentConfigResponse) String() string {
	s, _ := json.Marshal(n)
	return string(s)
}

// NativeAgentConfig represents the configuration pushed from apweb to the native agent
type NativeAgentConfig struct {
	// Enabled indicates if the agent should be active
	Enabled bool `json:"enabled" yaml:"enabled"`

	// ---- UID Filtering ----
	FilterUIDs  []int `json:"filter_uids,omitempty" yaml:"filter_uids,omitempty"`
	ExcludeUIDs []int `json:"exclude_uids,omitempty" yaml:"exclude_uids,omitempty"`

	// ---- Process Name Filtering ----
	FilterComms  []string `json:"filter_comms,omitempty" yaml:"filter_comms,omitempty"`
	ExcludeComms []string `json:"exclude_comms,omitempty" yaml:"exclude_comms,omitempty"`

	// ---- Path Filtering ----
	ExcludePaths []string `json:"exclude_paths,omitempty" yaml:"exclude_paths,omitempty"`

	// ---- Category Filtering ----
	EnableProcess bool `json:"enable_process" yaml:"enable_process"`
	EnableFile    bool `json:"enable_file" yaml:"enable_file"`
	EnableNetwork bool `json:"enable_network" yaml:"enable_network"`

	// ---- Compliance Category Filtering (SOX/PCI) ----
	EnablePrivilege  bool `json:"enable_privilege" yaml:"enable_privilege"`
	EnableFilesystem bool `json:"enable_filesystem" yaml:"enable_filesystem"`
	EnableKernel     bool `json:"enable_kernel" yaml:"enable_kernel"`
	EnableMemory     bool `json:"enable_memory" yaml:"enable_memory"`

	// ---- Event Enrichment ----
	EnableEnrichment          bool `json:"enable_enrichment" yaml:"enable_enrichment"`
	EnrichmentCacheTTLSeconds int  `json:"enrichment_cache_ttl_seconds,omitempty" yaml:"enrichment_cache_ttl_seconds,omitempty"`

	// ---- Alerting ----
	EnableAlerts bool                     `json:"enable_alerts" yaml:"enable_alerts"`
	AlertRules   []NativeAgentAlertRule   `json:"alert_rules,omitempty" yaml:"alert_rules,omitempty"`

	// ---- Compliance Profile ----
	ComplianceProfile string `json:"compliance_profile,omitempty" yaml:"compliance_profile,omitempty"` // "pci-dss-4.0", "sox", "custom"
}

// NativeAgentAlertRule represents an alert rule configuration from apweb
type NativeAgentAlertRule struct {
	Name        string                   `json:"name" yaml:"name"`
	Description string                   `json:"description,omitempty" yaml:"description,omitempty"`
	Enabled     bool                     `json:"enabled" yaml:"enabled"`
	Conditions  NativeAgentRuleCondition `json:"conditions" yaml:"conditions"`
	Priority    string                   `json:"priority,omitempty" yaml:"priority,omitempty"`
	Tags        []string                 `json:"tags,omitempty" yaml:"tags,omitempty"`
	Action      string                   `json:"action,omitempty" yaml:"action,omitempty"` // "alert", "drop"
}

// NativeAgentRuleCondition represents the conditions for an alert rule
type NativeAgentRuleCondition struct {
	Category                  string   `json:"category,omitempty" yaml:"category,omitempty"`
	EventTypes                []int    `json:"event_types,omitempty" yaml:"event_types,omitempty"`
	ProcessNames              []string `json:"process_names,omitempty" yaml:"process_names,omitempty"`
	ProcessNamesRegex         []string `json:"process_names_regex,omitempty" yaml:"process_names_regex,omitempty"`
	UIDs                      []int    `json:"uids,omitempty" yaml:"uids,omitempty"`
	RootOnly                  bool     `json:"root_only,omitempty" yaml:"root_only,omitempty"`
	PathPatterns              []string `json:"path_patterns,omitempty" yaml:"path_patterns,omitempty"`
	ContainerOnly             bool     `json:"container_only,omitempty" yaml:"container_only,omitempty"`
	PrivilegeEscalationToRoot bool     `json:"privilege_escalation_to_root,omitempty" yaml:"privilege_escalation_to_root,omitempty"`
}

// NativeAgentStatusPost represents the native agent status sent to apweb
type NativeAgentStatusPost struct {
	ID        string          `json:"id"`
	Version   string          `json:"v"`
	Timestamp int64           `json:"timestamp"`
	Source    string          `json:"source"`
	Tenant    string          `json:"tenant"`
	Subdomain string          `json:"subdomain"`
	Method    string          `json:"method"`
	Params    json.RawMessage `json:"params"`
}

// NativeAgentStatus represents the current status of the native agent
type NativeAgentStatus struct {
	Enabled       bool     `json:"enabled"`
	Running       bool     `json:"running"`
	Listening     bool     `json:"listening"`
	Version       string   `json:"version"`
	ConfigPath    string   `json:"config_path"`
	FilterStats   FilterStats   `json:"filter_stats"`
	AlertStats    AlertStats    `json:"alert_stats"`
	Categories    CategoryStats `json:"categories"`
}

// FilterStats represents filtering statistics
type FilterStats struct {
	TotalProcessed uint64  `json:"total_processed"`
	FilteredOut    uint64  `json:"filtered_out"`
	FilterRate     float64 `json:"filter_rate"`
}

// AlertStats represents alerting statistics
type AlertStats struct {
	RulesEvaluated uint64 `json:"rules_evaluated"`
	RulesMatched   uint64 `json:"rules_matched"`
}

// CategoryStats represents which event categories are enabled
type CategoryStats struct {
	Process    bool `json:"process"`
	File       bool `json:"file"`
	Network    bool `json:"network"`
	Privilege  bool `json:"privilege"`
	Filesystem bool `json:"filesystem"`
	Kernel     bool `json:"kernel"`
	Memory     bool `json:"memory"`
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

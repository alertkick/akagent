package ebpf

import (
	"context"
)

// AgentType represents the type of eBPF security agent
type AgentType string

const (
	AgentTypeFalco    AgentType = "falco"
	AgentTypeTetragon AgentType = "tetragon"
	AgentTypePixie    AgentType = "pixie"
	AgentTypeNative   AgentType = "native"
)

// String returns the string representation of the agent type
func (t AgentType) String() string {
	return string(t)
}

// ServiceStatus represents the status of an eBPF agent's service
type ServiceStatus struct {
	ActiveState string `json:"active_state"`
	SubState    string `json:"sub_state"`
	Running     bool   `json:"running"`
	Error       string `json:"error,omitempty"`
}

// AgentConfig represents configuration for an eBPF agent
type AgentConfig struct {
	Enabled    bool              `json:"enabled"`
	ConfigPath string            `json:"config_path"`
	Options    map[string]string `json:"options,omitempty"`
}

// RuleFile represents a rule file for an eBPF agent
type RuleFile struct {
	Filename string `json:"filename"`
	MD5Sum   string `json:"md5sum"`
	Content  string `json:"content"`
	Size     int64  `json:"size"`
}

// EBPFAgent defines the interface that all eBPF security agents must implement
type EBPFAgent interface {
	// Identification
	Type() AgentType
	Name() string
	Version() (string, error)

	// Lifecycle Management
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	IsRunning() bool

	// Event Handling
	StartEventListener(ctx context.Context) error
	StopEventListener() error
	EventChannel() <-chan SecurityEvent
	IsListening() bool

	// Configuration Management
	LoadConfig() error
	UpdateConfig(config AgentConfig) error
	GetConfigPath() string

	// Rule Management
	GetRules() ([]RuleFile, error)
	UpdateRules(rules []RuleFile) error
	GetRulesDir() string

	// Service Management (systemd)
	ServiceName() string
	GetServiceStatus() (ServiceStatus, error)
	StartService() error
	StopService() error
	RestartService() error
	GetServiceLogs(lines int) (string, error)

	// Installation Detection
	IsInstalled() bool
	GetBinaryPath() string
}

// AgentInfo provides basic information about an eBPF agent
type AgentInfo struct {
	Type          AgentType `json:"type"`
	Name          string    `json:"name"`
	Version       string    `json:"version"`
	Installed     bool      `json:"installed"`
	Enabled       bool      `json:"enabled"`
	ServiceStatus string    `json:"service_status"`
	BinaryPath    string    `json:"binary_path"`
	ConfigPath    string    `json:"config_path"`
	RulesDir      string    `json:"rules_dir"`
}

// GetInfo returns the current state information for an agent
func GetInfo(agent EBPFAgent) AgentInfo {
	version, _ := agent.Version()
	status, _ := agent.GetServiceStatus()

	serviceStatusStr := "unknown"
	if status.Running {
		serviceStatusStr = "running"
	} else if status.ActiveState == "inactive" {
		serviceStatusStr = "stopped"
	} else if status.ActiveState != "" {
		serviceStatusStr = status.ActiveState + "/" + status.SubState
	}

	return AgentInfo{
		Type:          agent.Type(),
		Name:          agent.Name(),
		Version:       version,
		Installed:     agent.IsInstalled(),
		Enabled:       agent.IsRunning(),
		ServiceStatus: serviceStatusStr,
		BinaryPath:    agent.GetBinaryPath(),
		ConfigPath:    agent.GetConfigPath(),
		RulesDir:      agent.GetRulesDir(),
	}
}

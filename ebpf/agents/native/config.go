package native

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultConfigPath is the default location for the native agent config
	DefaultConfigPath = "/etc/apagent/native.yaml"
	// DefaultConfigDir is the default directory for config files
	DefaultConfigDir = "/etc/apagent"
)

// Config holds configuration options for the native eBPF agent
type Config struct {
	// RingBufferSize is the size of the BPF ring buffer in bytes
	// Default is 256KB. Increase for high-volume systems.
	RingBufferSize int `yaml:"ring_buffer_size"`

	// EventChannelSize is the buffer size for the Go event channel
	// Default is 1000 events
	EventChannelSize int `yaml:"event_channel_size"`

	// Enabled indicates if the agent should be active
	Enabled bool `yaml:"enabled"`

	// ---- UID Filtering ----

	// FilterUIDs if set, only include events from these UIDs (whitelist)
	// Empty means no UID whitelist filtering
	FilterUIDs []int `yaml:"filter_uids,omitempty"`

	// ExcludeUIDs exclude events from these UIDs (blacklist)
	// Example: [0] to exclude root processes
	ExcludeUIDs []int `yaml:"exclude_uids,omitempty"`

	// ---- Process Name Filtering ----

	// FilterComms if set, only include events from these process names (whitelist)
	// Empty means no process name whitelist filtering
	FilterComms []string `yaml:"filter_comms,omitempty"`

	// ExcludeComms exclude events from these process names (blacklist)
	// Example: ["systemd", "journald", "sshd"]
	ExcludeComms []string `yaml:"exclude_comms,omitempty"`

	// ---- Path Filtering (file events only) ----

	// ExcludePaths exclude file events matching these path prefixes
	// Example: ["/proc/", "/sys/", "/dev/"]
	ExcludePaths []string `yaml:"exclude_paths,omitempty"`

	// ---- Category Filtering ----

	// EnableProcess enables process-related events (execve, clone, kill, ptrace)
	EnableProcess bool `yaml:"enable_process"`

	// EnableFile enables file-related events (openat, unlinkat, renameat2, fchmodat)
	EnableFile bool `yaml:"enable_file"`

	// EnableNetwork enables network-related events (connect, accept4, bind, socket)
	EnableNetwork bool `yaml:"enable_network"`

	// ---- Compliance Category Filtering (SOX/PCI) ----

	// EnablePrivilege enables privilege escalation events (setuid, setgid, setreuid, setregid)
	EnablePrivilege bool `yaml:"enable_privilege"`

	// EnableFilesystem enables filesystem mount/unmount events
	EnableFilesystem bool `yaml:"enable_filesystem"`

	// EnableKernel enables kernel module operations (init_module, finit_module, delete_module)
	EnableKernel bool `yaml:"enable_kernel"`

	// EnableMemory enables memory protection change events (mprotect with PROT_EXEC)
	EnableMemory bool `yaml:"enable_memory"`

	// ---- Tracepoint Selection ----

	// Tracepoints allows enabling/disabling specific tracepoints
	// If nil, all tracepoints for enabled categories are active
	Tracepoints *TracepointConfig `yaml:"tracepoints,omitempty"`

	// ---- Event Enrichment ----

	// EnableEnrichment enables container, cgroup, and namespace enrichment
	EnableEnrichment bool `yaml:"enable_enrichment"`

	// EnrichmentCacheTTLSeconds is how long to cache enrichment data (default 30)
	EnrichmentCacheTTLSeconds int `yaml:"enrichment_cache_ttl_seconds,omitempty"`

	// ---- Alerting Rules ----

	// EnableAlerts enables the alert rule engine
	EnableAlerts bool `yaml:"enable_alerts"`

	// AlertRules is the list of custom alert rules
	// If nil, default security rules are used
	AlertRules []AlertRule `yaml:"alert_rules,omitempty"`

	// ---- Compliance Profiles ----

	// ComplianceProfiles is the list of compliance profiles to apply
	// Options: "sox", "pci-dss-4.0"
	// When set, the profiles' rules and settings are merged and applied
	ComplianceProfiles []string `yaml:"compliance_profiles,omitempty"`
}

// TracepointConfig allows fine-grained control over which tracepoints are enabled
type TracepointConfig struct {
	// Process tracepoints
	Execve bool `yaml:"execve"`
	Clone  bool `yaml:"clone"`
	Kill   bool `yaml:"kill"`
	Ptrace bool `yaml:"ptrace"`

	// File tracepoints
	Openat    bool `yaml:"openat"`
	Unlinkat  bool `yaml:"unlinkat"`
	Renameat2 bool `yaml:"renameat2"`
	Fchmodat  bool `yaml:"fchmodat"`

	// Network tracepoints
	Connect bool `yaml:"connect"`
	Accept4 bool `yaml:"accept4"`
	Bind    bool `yaml:"bind"`
	Socket  bool `yaml:"socket"`

	// Privilege escalation tracepoints (SOX/PCI compliance)
	Setuid   bool `yaml:"setuid"`
	Setgid   bool `yaml:"setgid"`
	Setreuid bool `yaml:"setreuid"`
	Setregid bool `yaml:"setregid"`

	// Filesystem tracepoints (SOX/PCI compliance)
	Mount   bool `yaml:"mount"`
	Umount2 bool `yaml:"umount2"`

	// Kernel module tracepoints (SOX/PCI compliance)
	InitModule   bool `yaml:"init_module"`
	FinitModule  bool `yaml:"finit_module"`
	DeleteModule bool `yaml:"delete_module"`

	// Memory protection tracepoints (code injection detection)
	Mprotect bool `yaml:"mprotect"`
}

// DefaultConfig returns the default configuration for the native agent
// These defaults are used when no config file is present or endpoint is unreachable
func DefaultConfig() Config {
	return Config{
		RingBufferSize:   256 * 1024, // 256 KB
		EventChannelSize: 1000,
		Enabled:          true,

		// No UID filtering by default
		FilterUIDs:  nil,
		ExcludeUIDs: nil,

		// No process name filtering by default
		FilterComms:  nil,
		ExcludeComms: nil,

		// Default path exclusions to reduce noise
		ExcludePaths: []string{
			"/proc/",
			"/sys/",
			"/dev/",
		},

		// All categories enabled by default
		EnableProcess: true,
		EnableFile:    true,
		EnableNetwork: true,

		// Compliance categories enabled by default (SOX/PCI)
		EnablePrivilege:  true,
		EnableFilesystem: true,
		EnableKernel:     true,
		EnableMemory:     true,

		// All tracepoints enabled by default (nil means all enabled)
		Tracepoints: nil,

		// Enrichment enabled by default
		EnableEnrichment:          true,
		EnrichmentCacheTTLSeconds: 30,

		// Alerting enabled with default rules
		EnableAlerts: true,
		AlertRules:   nil, // nil means use DefaultAlertRules()
	}
}

// DefaultTracepointConfig returns a TracepointConfig with all tracepoints enabled
func DefaultTracepointConfig() TracepointConfig {
	return TracepointConfig{
		// Process
		Execve: true,
		Clone:  true,
		Kill:   true,
		Ptrace: true,
		// File
		Openat:    true,
		Unlinkat:  true,
		Renameat2: true,
		Fchmodat:  true,
		// Network
		Connect: true,
		Accept4: true,
		Bind:    true,
		Socket:  true,
		// Privilege (SOX/PCI)
		Setuid:   true,
		Setgid:   true,
		Setreuid: true,
		Setregid: true,
		// Filesystem (SOX/PCI)
		Mount:   true,
		Umount2: true,
		// Kernel modules (SOX/PCI)
		InitModule:   true,
		FinitModule:  true,
		DeleteModule: true,
		// Memory (code injection)
		Mprotect: true,
	}
}

// Validate checks if the configuration is valid and applies defaults
func (c *Config) Validate() error {
	if c.RingBufferSize < 4096 {
		c.RingBufferSize = 4096 // Minimum 4KB
	}
	if c.EventChannelSize < 10 {
		c.EventChannelSize = 10 // Minimum 10 events
	}
	return nil
}

// LoadConfigFromFile loads configuration from a YAML file
// If the file doesn't exist, returns default config with no error
func LoadConfigFromFile(path string) (Config, error) {
	config := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, use defaults
			return config, nil
		}
		return config, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		return DefaultConfig(), fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := config.Validate(); err != nil {
		return DefaultConfig(), fmt.Errorf("invalid config: %w", err)
	}

	return config, nil
}

// SaveConfigToFile saves the configuration to a YAML file
func SaveConfigToFile(config Config, path string) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := yaml.Marshal(&config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Add header comment
	header := []byte("# Native eBPF Agent Configuration\n# Managed by AlertPriority Agent\n# Manual changes may be overwritten by endpoint sync\n\n")
	data = append(header, data...)

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// MergeConfig merges endpoint config into local config
// Endpoint values take precedence over local values
func MergeConfig(local, endpoint Config) Config {
	// Start with endpoint config as base
	merged := endpoint

	// Keep local ring buffer and channel sizes if endpoint doesn't specify
	if merged.RingBufferSize == 0 {
		merged.RingBufferSize = local.RingBufferSize
	}
	if merged.EventChannelSize == 0 {
		merged.EventChannelSize = local.EventChannelSize
	}

	return merged
}

// GenerateDefaultConfigFile creates a default config file if it doesn't exist
func GenerateDefaultConfigFile() error {
	if _, err := os.Stat(DefaultConfigPath); err == nil {
		// File already exists
		return nil
	}

	return SaveConfigToFile(DefaultConfig(), DefaultConfigPath)
}

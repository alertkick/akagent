package ebpf

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultConfigPath is the default location for the native agent config
	DefaultConfigPath = "/etc/alertkick-agent/native.yaml"
	// DefaultConfigDir is the default directory for config files
	DefaultConfigDir = "/etc/alertkick-agent"
)

// NativeConfig holds configuration options for the native eBPF agent
// Note: The agent only captures and enriches events. All compliance logic,
// alert rules, and business intelligence is handled by apapi.
type NativeConfig struct {
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

	// EnablePrivilege enables privilege escalation events (setuid, setgid, setreuid, setregid)
	EnablePrivilege bool `yaml:"enable_privilege"`

	// EnableFilesystem enables filesystem mount/unmount events
	EnableFilesystem bool `yaml:"enable_filesystem"`

	// EnableKernel enables kernel module operations (init_module, finit_module, delete_module)
	EnableKernel bool `yaml:"enable_kernel"`

	// EnableMemory enables memory protection change events (mprotect with PROT_EXEC)
	EnableMemory bool `yaml:"enable_memory"`

	// EnableNamespace enables namespace operation events (setns, unshare)
	EnableNamespace bool `yaml:"enable_namespace"`

	// EnableCaps enables capability change events (capset)
	EnableCaps bool `yaml:"enable_caps"`

	// ---- Tracepoint Selection ----

	// Tracepoints allows enabling/disabling specific tracepoints
	// If nil, all tracepoints for enabled categories are active
	Tracepoints *TracepointConfig `yaml:"tracepoints,omitempty"`

	// ---- Event Enrichment ----

	// EnableEnrichment enables container, cgroup, and namespace enrichment
	EnableEnrichment bool `yaml:"enable_enrichment"`

	// EnrichmentCacheTTLSeconds is how long to cache enrichment data (default 30)
	EnrichmentCacheTTLSeconds int `yaml:"enrichment_cache_ttl_seconds,omitempty"`

	// ---- Alert Filtering ----

	// AlertFilter controls the noise filter that drops obviously
	// uninteresting events at the source. Classification and rule
	// evaluation happen at the endpoint, not here.
	AlertFilter AlertFilterConfig `yaml:"alert_filter"`

	// ---- Rate Limiting ----

	// RateLimiter controls per-rule token bucket rate limiting
	// Prevents a single noisy rule from drowning out critical alerts
	RateLimiter RateLimiterConfig `yaml:"rate_limiter"`

	// ---- Native Lists Configuration ----
	// NativeLists controls comprehensive binary/path exclusions and detections
	NativeLists NativeListConfig `yaml:"native_lists"`

	// ---- File Integrity Monitoring (FIM) ----
	// FileIntegrity baselines checksums of system binaries and /etc and
	// raises a finding when a monitored file's content changes. Requires
	// EnableFile (file events) to be active.
	FileIntegrity FileIntegrityConfig `yaml:"file_integrity"`

	// ---- Event Scoping ----
	// FileMonitor scopes which file events are emitted to security-relevant
	// paths, so high-volume reads/writes elsewhere are dropped at the source.
	FileMonitor FileMonitorConfig `yaml:"file_monitor"`

	// SignalMonitor scopes which process-signal events are emitted to the
	// consequential signal numbers, dropping benign high-frequency signals.
	SignalMonitor SignalMonitorConfig `yaml:"signal_monitor"`
}

// FileMonitorConfig scopes file-event emission to security-relevant paths.
// When either list is non-empty, a file event is emitted only when it matches:
// a write-type operation under a WriteDir, or any operation (including a
// read-only open) on a ReadFile. Every other file event is dropped at the
// source. Both lists empty disables scoping (all file events that pass the
// other filters are emitted). The lists are the agent's own defaults and can
// be overridden per server by the endpoint. Entries are directory prefixes or
// shell globs (e.g. "/home/*/.ssh"); evaluation is the endpoint's job — these
// only decide what the sensor reports.
type FileMonitorConfig struct {
	WriteDirs []string `yaml:"write_dirs,omitempty"`
	ReadFiles []string `yaml:"read_files,omitempty"`
}

// SignalMonitorConfig scopes process-signal emission. When EmitSignals is
// non-empty, only those signal numbers are reported; all other signals are
// dropped at the source. Empty means emit all signals.
type SignalMonitorConfig struct {
	EmitSignals []int `yaml:"emit_signals,omitempty"`
}

// FileIntegrityConfig controls checksum-based file integrity monitoring.
// On enable the agent baselines every file under Paths (minus Exclude),
// then re-hashes a file when an eBPF write/rename/chmod/unlink touches it
// and emits a finding if the digest changed from the baseline.
type FileIntegrityConfig struct {
	// Enabled toggles FIM. Off by default.
	Enabled bool `yaml:"enabled"`

	// Paths are the directories whose files are baselined (recursive).
	Paths []string `yaml:"paths,omitempty"`

	// Exclude drops files whose path has any of these prefixes (churny
	// files that legitimately change, e.g. /etc/resolv.conf).
	Exclude []string `yaml:"exclude,omitempty"`

	// HashAlgo is "sha256" (default, tamper-resistant) or "md5".
	HashAlgo string `yaml:"hash_algo,omitempty"`

	// SuppressPkgMgr, when true, treats changes made by a package manager
	// (apt/dpkg/rpm/yum/dnf/apk) as expected: silently re-baseline and emit
	// an informational audit event instead of a critical finding.
	SuppressPkgMgr bool `yaml:"suppress_pkg_mgr"`

	// DebounceMs coalesces the burst of events from a single edit before
	// re-hashing the path. Default 750ms.
	DebounceMs int `yaml:"debounce_ms,omitempty"`
}

// AlertFilterConfig controls the agent's noise filter. The filter drops
// events that match configured exclusion sets (comm names, file path
// prefixes) before they leave the host. All classification and rule
// evaluation is the endpoint's responsibility.
type AlertFilterConfig struct {
	// Enabled toggles the noise filter. When false, all events pass.
	Enabled bool `yaml:"enabled"`
}

// TracepointConfig allows fine-grained control over which tracepoints are enabled
type TracepointConfig struct {
	// Process tracepoints
	Execve bool `yaml:"execve"`
	Clone  bool `yaml:"clone"`
	Kill   bool `yaml:"kill"`
	Ptrace bool `yaml:"ptrace"`

	// File tracepoints
	Openat      bool `yaml:"openat"`
	Unlinkat    bool `yaml:"unlinkat"`
	Renameat2   bool `yaml:"renameat2"`
	Fchmodat    bool `yaml:"fchmodat"`
	Fchownat    bool `yaml:"fchownat"`
	Mkdirat     bool `yaml:"mkdirat"`
	Linkat      bool `yaml:"linkat"`
	Symlinkat   bool `yaml:"symlinkat"`
	Setxattr    bool `yaml:"setxattr"`
	Removexattr bool `yaml:"removexattr"`
	Utimensat   bool `yaml:"utimensat"`

	// Network tracepoints
	Connect bool `yaml:"connect"`
	Accept4 bool `yaml:"accept4"`
	Bind    bool `yaml:"bind"`
	Socket  bool `yaml:"socket"`

	// Privilege escalation tracepoints
	Setuid   bool `yaml:"setuid"`
	Setgid   bool `yaml:"setgid"`
	Setreuid bool `yaml:"setreuid"`
	Setregid bool `yaml:"setregid"`

	// Filesystem tracepoints
	Mount   bool `yaml:"mount"`
	Umount2 bool `yaml:"umount2"`

	// Kernel module tracepoints
	InitModule   bool `yaml:"init_module"`
	FinitModule  bool `yaml:"finit_module"`
	DeleteModule bool `yaml:"delete_module"`

	// Memory protection tracepoints
	Mprotect bool `yaml:"mprotect"`
	Mmap     bool `yaml:"mmap"`

	// Namespace tracepoints
	Setns   bool `yaml:"setns"`
	Unshare bool `yaml:"unshare"`

	// Capability tracepoints
	Capset bool `yaml:"capset"`

	// Extended signal tracepoints
	Tgkill bool `yaml:"tgkill"`
	Tkill  bool `yaml:"tkill"`
}

// DefaultNativeConfig returns the default configuration for the native agent
// These defaults are used when no config file is present or endpoint is unreachable
// Note: Conservative defaults - eBPF is disabled by default and only enabled when
// a compliance profile is assigned via the refresh_compliance command.
// This prevents noisy events from being sent before security rules are configured.
func DefaultNativeConfig() NativeConfig {
	return NativeConfig{
		RingBufferSize:   256 * 1024, // 256 KB
		EventChannelSize: 1000,
		Enabled:          false, // Disabled by default - enabled when profile assigned

		// No UID filtering by default
		FilterUIDs:  nil,
		ExcludeUIDs: nil,

		// Exclude common noisy processes by default
		// Note: Uses prefix matching, so "runc" matches "runc:[2:INIT]", etc.
		FilterComms: nil,
		ExcludeComms: []string{
			// Container runtimes (legitimate setuid/privilege operations)
			"runc",        // Matches runc:[0:PARE], runc:[1:CHIL], runc:[2:INIT], etc.
			"containerd",  // Matches containerd-shim as well
			"dockerd",
			"docker-proxy",
			"crio",
			"podman",
			// Desktop environments (heavy JIT usage from JavaScript/GJS)
			"gnome-shell",
			"gnome-software",
			"gjs",
			"plasmashell",
			"kwin_wayland",
			"kwin_x11",
			// Browsers (heavy JIT usage causes memory/mprotect noise)
			"firefox",
			"chrome",
			"chromium",
			"brave",
			"opera",
			// Browser helpers
			"Web Content",
			"WebExtensions",
			"Isolated Web Co",
			"RDD Process",
			"Socket Process",
			"Utility Process",
			// IDE/Editors (also use JIT)
			"code",
			"code-server",
			"gopls",
			"rust-analyzer",
			// Node.js / Electron apps (JIT)
			"node",
			"electron",
		},

		// Default path exclusions to reduce noise
		ExcludePaths: []string{
			"/proc/",
			"/sys/",
			"/dev/",
		},

		// Conservative defaults: only enable essential security categories
		// Memory events are disabled by default due to high volume from JIT compilers
		EnableProcess:    true,  // Essential: track process execution
		EnableFile:       false, // Noisy: enable via profile for compliance
		EnableNetwork:    true,  // Essential: track network connections
		EnablePrivilege:  true,  // Essential: track privilege escalation
		EnableFilesystem: true,  // Important: track mount operations
		EnableKernel:     true,  // Important: track kernel module loading
		EnableMemory:     false, // Very noisy: enable via profile for compliance
		EnableNamespace:  true,  // Important: detect container breakout via setns/unshare
		EnableCaps:       true,  // Important: detect capability elevation

		// All tracepoints enabled by default (nil means all enabled)
		Tracepoints: nil,

		// Enrichment enabled by default
		EnableEnrichment:          true,
		EnrichmentCacheTTLSeconds: 30,

		// Noise filter enabled by default (drops obvious system noise at the source).
		AlertFilter: AlertFilterConfig{
			Enabled: true,
		},

		// Rate limiting: prevent noisy rules from drowning critical alerts
		RateLimiter: RateLimiterConfig{
			Enabled:       true,
			DefaultRateMs: DefaultRateLimitIntervalMs, // 100ms between events per rule
			DefaultBurst:  DefaultRateLimitBurst,      // 40 event burst allowance
		},

		// Native lists configuration for comprehensive exclusions/detections
		NativeLists: DefaultNativeListConfig(),

		// File integrity monitoring (off until enabled via profile/config)
		FileIntegrity: DefaultFileIntegrityConfig(),

		// Scope file and signal events to security-relevant activity so a
		// busy host doesn't drown the channel in read noise.
		FileMonitor:   DefaultFileMonitorConfig(),
		SignalMonitor: DefaultSignalMonitorConfig(),
	}
}

// DefaultFileIntegrityConfig returns conservative FIM defaults: disabled,
// SHA-256, package-manager changes suppressed, monitoring the standard
// binary directories plus /etc with the usual churny files excluded.
func DefaultFileIntegrityConfig() FileIntegrityConfig {
	return FileIntegrityConfig{
		Enabled: false,
		Paths: []string{
			"/usr/bin", "/usr/sbin", "/bin", "/sbin",
			"/usr/local/bin", "/usr/local/sbin", "/etc",
		},
		Exclude: []string{
			"/etc/mtab", "/etc/resolv.conf", "/etc/ld.so.cache",
			"/etc/adjtime", "/etc/machine-id", "/etc/.updated", "/etc/.pwd.lock",
		},
		HashAlgo:       "sha256",
		SuppressPkgMgr: true,
		DebounceMs:     750,
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
		Openat:      true,
		Unlinkat:    true,
		Renameat2:   true,
		Fchmodat:    true,
		Fchownat:    true,
		Mkdirat:     true,
		Linkat:      true,
		Symlinkat:   true,
		Setxattr:    true,
		Removexattr: true,
		Utimensat:   true,
		// Network
		Connect: true,
		Accept4: true,
		Bind:    true,
		Socket:  true,
		// Privilege
		Setuid:   true,
		Setgid:   true,
		Setreuid: true,
		Setregid: true,
		// Filesystem
		Mount:   true,
		Umount2: true,
		// Kernel modules
		InitModule:   true,
		FinitModule:  true,
		DeleteModule: true,
		// Memory
		Mprotect: true,
		Mmap:     true,
		// Namespace
		Setns:   true,
		Unshare: true,
		// Capability
		Capset: true,
		// Extended signals
		Tgkill: true,
		Tkill:  true,
	}
}

// Validate checks if the configuration is valid and applies defaults
func (c *NativeConfig) Validate() error {
	if c.RingBufferSize < 4096 {
		c.RingBufferSize = 4096 // Minimum 4KB
	}
	if c.EventChannelSize < 10 {
		c.EventChannelSize = 10 // Minimum 10 events
	}
	if c.FileIntegrity.Enabled {
		fi := DefaultFileIntegrityConfig()
		if len(c.FileIntegrity.Paths) == 0 {
			c.FileIntegrity.Paths = fi.Paths
		}
		if c.FileIntegrity.HashAlgo == "" {
			c.FileIntegrity.HashAlgo = fi.HashAlgo
		}
		if c.FileIntegrity.HashAlgo != "sha256" && c.FileIntegrity.HashAlgo != "md5" {
			return fmt.Errorf("file_integrity.hash_algo must be \"sha256\" or \"md5\", got %q", c.FileIntegrity.HashAlgo)
		}
		if c.FileIntegrity.DebounceMs <= 0 {
			c.FileIntegrity.DebounceMs = fi.DebounceMs
		}
	}
	return nil
}

// LoadConfigFromFile loads configuration from a YAML file
// If the file doesn't exist, returns default config with no error
func LoadConfigFromFile(path string) (NativeConfig, error) {
	config := DefaultNativeConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, use defaults
			return config, nil
		}
		return config, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		return DefaultNativeConfig(), fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := config.Validate(); err != nil {
		return DefaultNativeConfig(), fmt.Errorf("invalid config: %w", err)
	}

	return config, nil
}

// SaveConfigToFile saves the configuration to a YAML file
func SaveConfigToFile(config NativeConfig, path string) error {
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
	header := []byte("# Native eBPF Agent Configuration\n# Managed by AlertKick Agent\n# Manual changes may be overwritten by endpoint sync\n\n")
	data = append(header, data...)

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// MergeConfig merges endpoint config into local config
// Endpoint values take precedence over local values
func MergeConfig(local, endpoint NativeConfig) NativeConfig {
	// Start with endpoint config as base
	merged := endpoint

	// Keep local ring buffer and channel sizes if endpoint doesn't specify
	if merged.RingBufferSize == 0 {
		merged.RingBufferSize = local.RingBufferSize
	}
	if merged.EventChannelSize == 0 {
		merged.EventChannelSize = local.EventChannelSize
	}

	// Keep local event-scoping defaults if the endpoint doesn't push its own,
	// so a host that hasn't received a profile still scopes file/signal noise.
	if len(merged.FileMonitor.WriteDirs) == 0 && len(merged.FileMonitor.ReadFiles) == 0 {
		merged.FileMonitor = local.FileMonitor
	}
	if len(merged.SignalMonitor.EmitSignals) == 0 {
		merged.SignalMonitor = local.SignalMonitor
	}

	return merged
}

// GenerateDefaultConfigFile creates a default config file if it doesn't exist
func GenerateDefaultConfigFile() error {
	if _, err := os.Stat(DefaultConfigPath); err == nil {
		// File already exists
		return nil
	}

	return SaveConfigToFile(DefaultNativeConfig(), DefaultConfigPath)
}

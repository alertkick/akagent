//go:build linux

package ebpf

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"akagent/agent/authmonitor"
	"akagent/agent/fim"
	"akagent/agent/rootkitscan"
	"akagent/agent/yarascan"
	"akagent/agent/yarasync"
	"akagent/ebpf/bpfgen"
	"akagent/logger"

	"github.com/cilium/ebpf/link"
)

var nativeLog = logger.Sublogger("native-agent")

const (
	eventChannelBufferSize = 1000
)

// agentVersion is set at build time via -ldflags "-X apagent/ebpf.agentVersion=<version>"
var agentVersion = "0.0.0"

// Event type constants (must match common.h)
const (
	EventTypeExecve  = 1
	EventTypeOpen    = 2
	EventTypeUnlink  = 3
	EventTypeRename  = 4
	EventTypeChmod   = 5
	EventTypeConnect = 6
	EventTypeAccept  = 7
	EventTypeBind    = 8
	EventTypeSocket  = 9
	EventTypeClone   = 10
	EventTypeKill    = 11
	EventTypePtrace  = 12

	// Extended file events
	EventTypeChown       = 13
	EventTypeMkdir       = 14
	EventTypeRmdir       = 15
	EventTypeLink        = 16
	EventTypeSymlink     = 17
	EventTypeSetxattr    = 18
	EventTypeRemovexattr = 19
	EventTypeUtimes      = 25

	// Compliance event types
	EventTypeSetuid       = 20
	EventTypeSetgid       = 21
	EventTypeSetreuid     = 22
	EventTypeSetregid     = 23
	EventTypeMount        = 30
	EventTypeUmount       = 31
	EventTypeInitModule   = 40
	EventTypeFinitModule  = 41
	EventTypeDeleteModule = 42
	EventTypeMprotect     = 50
	EventTypeMmap         = 51
	EventTypeDNSQuery     = 60
	EventTypeIMDSAccess   = 61
	EventTypeBPFCmd       = 70
	EventTypeMemfdCreate     = 71
	EventTypeExecveat        = 72
	EventTypeIoUringSetup    = 80
	EventTypeIoUringRegister = 81
	EventTypeSetns           = 90
	EventTypeUnshare         = 91
	EventTypeCapset          = 92
	EventTypeTgkill          = 93
	EventTypeTkill           = 94

	EventTypeIoUringEnter = 82

	// Extended privilege events
	EventTypeSetresuid = 95
	EventTypeSetresgid = 96
	EventTypeSetfsuid  = 97
	EventTypeSetfsgid  = 98

	// Extended file events
	EventTypeOpenat2        = 100
	EventTypeOpenByHandle   = 101
	EventTypeTruncate       = 102
	EventTypeFtruncate      = 103

	// Data exfiltration events
	EventTypeSplice        = 110
	EventTypeSendfile      = 111
	EventTypeCopyFileRange = 112
	EventTypeTee           = 113

	// Directory operation events
	EventTypeChdir     = 120
	EventTypeFchdir    = 121
	EventTypeChroot    = 122
	EventTypePivotRoot = 123

	// VFS kprobe events
	EventTypeVfsOpen      = 130
	EventTypeVfsUnlink    = 131
	EventTypeVfsRename    = 132
	EventTypeInodeSetattr = 133

	// Credential / process lifecycle events (kprobes)
	EventTypeCommitCreds = 140
	EventTypeProcessExit = 141
)

// NativeEBPFAgent implements the EBPFAgent interface using native BPF programs
type NativeEBPFAgent struct {
	mu            sync.RWMutex
	config        NativeConfig
	configPath    string
	filter        *EventFilter
	alertFilter   *AlertFilter
	rateLimiter   *RateLimiter
	enricher      *EventEnricher
	sshHydrator   *SSHHydrator
	sshdConfig    *SSHDConfigReader
	// sshdConfigCallbacks fire after each successful Refresh. Held
	// behind mu so callers can register/unregister from any goroutine.
	sshdConfigCallbacks []func(*SSHDConfig)
	eventChan     chan SecurityEvent
	running       bool
	listening     bool
	shutdownChan  chan struct{}
	kernelSupport KernelSupport
	outputMode    OutputMode

	// BPF pin manager for lifecycle management
	pinManager *BPFPinManager

	// In-kernel discarder manager for kernel-side event filtering
	discarders *DiscarderManager

	// Process cache for userspace enrichment
	processCacheObjs *bpfgen.ProcesscacheObjects
	processCache     *ProcessCache
	procExecLink     link.Link
	procExitLink     link.Link
	procForkLink     link.Link

	// BPF objects for each program
	execveObjs    *bpfgen.ExecveObjects
	fileopsObjs   *bpfgen.FileopsObjects
	networkObjs   *bpfgen.NetworkObjects
	processObjs   *bpfgen.ProcessObjects
	privilegeObjs *bpfgen.PrivilegeObjects
	mountObjs     *bpfgen.MountObjects
	moduleObjs    *bpfgen.ModuleObjects
	memoryObjs    *bpfgen.MemoryObjects
	dnsObjs        *bpfgen.DnsObjects
	imdsObjs       *bpfgen.ImdsObjects
	bpfsyscallObjs *bpfgen.BpfsyscallObjects
	memfdObjs      *bpfgen.MemfdObjects
	iouringObjs    *bpfgen.IouringObjects
	namespaceObjs  *bpfgen.NamespaceObjects
	capsObjs       *bpfgen.CapsObjects
	dataexfilObjs  *bpfgen.DataexfilObjects
	diropsObjs     *bpfgen.DiropsObjects
	vfshooksObjs   *bpfgen.VfshooksObjects
	credhooksObjs  *bpfgen.CredhooksObjects
	ioctlObjs      *bpfgen.IoctlObjects

	// Perf variant BPF objects (used when outputMode == OutputModePerf)
	perfExecveObjs    *bpfgen.PerfexecveObjects
	perfFileopsObjs   *bpfgen.PerffileopsObjects
	perfNetworkObjs   *bpfgen.PerfnetworkObjects
	perfProcessObjs   *bpfgen.PerfprocessObjects
	perfPrivilegeObjs *bpfgen.PerfprivilegeObjects
	perfMountObjs     *bpfgen.PerfmountObjects
	perfModuleObjs    *bpfgen.PerfmoduleObjects
	perfMemoryObjs    *bpfgen.PerfmemoryObjects
	perfDnsObjs        *bpfgen.PerfdnsObjects
	perfImdsObjs       *bpfgen.PerfimdsObjects
	perfBpfsyscallObjs *bpfgen.PerfbpfsyscallObjects
	perfMemfdObjs      *bpfgen.PerfmemfdObjects
	perfIouringObjs    *bpfgen.PerfiouringObjects
	perfNamespaceObjs  *bpfgen.PerfnamespaceObjects
	perfCapsObjs       *bpfgen.PerfcapsObjects
	perfDataexfilObjs  *bpfgen.PerfdataexfilObjects
	perfDiropsObjs     *bpfgen.PerfdiropsObjects
	perfVfshooksObjs   *bpfgen.PerfvfshooksObjects
	perfCredhooksObjs  *bpfgen.PerfcredhooksObjects
	perfIoctlObjs      *bpfgen.PerfioctlObjects

	// Tracepoint links
	links []link.Link

	// Event readers (wraps either ringbuf.Reader or perf.Reader)
	execveReader    EventReader
	fileopsReader   EventReader
	networkReader   EventReader
	processReader   EventReader
	privilegeReader EventReader
	mountReader     EventReader
	moduleReader    EventReader
	memoryReader    EventReader
	dnsReader        EventReader
	imdsReader       EventReader
	bpfsyscallReader EventReader
	memfdReader      EventReader
	iouringReader    EventReader
	namespaceReader  EventReader
	capsReader       EventReader
	dataexfilReader  EventReader
	diropsReader     EventReader
	vfshooksReader   EventReader
	credhooksReader  EventReader
	ioctlReader      EventReader

	// WaitGroup for reader goroutines
	readerWg sync.WaitGroup

	// File integrity monitor — nil unless FileIntegrity is enabled.
	fimManager *fim.Manager

	// Auth-log brute-force monitor — started with the event listener.
	authMonitor *authmonitor.Monitor

	// Rootkit indicator scanner — started with the event listener.
	rootkitScanner *rootkitscan.Scanner

	// YARA malware scanner — dormant until a ruleset is present.
	yaraScanner *yarascan.Scanner

	// YARA rules syncer — nil unless YARA_SYNC_URL is configured.
	yaraSyncer *yarasync.Syncer
}

// SSHDConfigSnapshot returns the current sshd_config snapshot from the
// agent's reader, or nil if the reader hasn't refreshed yet. Used by
// the SSH lockdown initialiser to seed the LSM BPF map with the host's
// listening ports.
func (a *NativeEBPFAgent) SSHDConfigSnapshot() *SSHDConfig {
	if a.sshdConfig == nil {
		return nil
	}
	return a.sshdConfig.Snapshot()
}

// OnSSHDConfigRefresh registers a callback fired after each successful
// sshd_config refresh. The lockdown initialiser registers a callback
// here so the LSM blocker's port-set map tracks sshd Port directive
// changes without an agent restart.
func (a *NativeEBPFAgent) OnSSHDConfigRefresh(cb func(*SSHDConfig)) {
	a.mu.Lock()
	a.sshdConfigCallbacks = append(a.sshdConfigCallbacks, cb)
	a.mu.Unlock()
}

func (a *NativeEBPFAgent) fireSSHDConfigCallbacks(snap *SSHDConfig) {
	a.mu.RLock()
	cbs := append([]func(*SSHDConfig){}, a.sshdConfigCallbacks...)
	a.mu.RUnlock()
	for _, cb := range cbs {
		cb(snap)
	}
}

// NewNativeAgent creates a new native eBPF agent instance
func NewNativeAgent() (*NativeEBPFAgent, error) {
	return NewNativeAgentWithConfig(DefaultConfigPath)
}

// NewNativeAgentWithConfig creates a new native eBPF agent with a specific config path
func NewNativeAgentWithConfig(configPath string) (*NativeEBPFAgent, error) {
	// Check kernel support
	support := CheckKernelSupport()
	if !support.IsSupported() {
		return nil, fmt.Errorf("kernel does not support native eBPF: %v", support.Error)
	}

	// Load config from file (falls back to defaults if file doesn't exist)
	config, err := LoadConfigFromFile(configPath)
	if err != nil {
		nativeLog.Warn().Err(err).Msg("Failed to load config file, using defaults")
		config = DefaultNativeConfig()
	}

	// Create enricher with config settings
	cacheTTL := time.Duration(config.EnrichmentCacheTTLSeconds) * time.Second
	if cacheTTL <= 0 {
		cacheTTL = 30 * time.Second
	}
	enricher := NewEventEnricherWithTTL(cacheTTL)
	enricher.SetEnabled(config.EnableEnrichment)

	agent := &NativeEBPFAgent{
		config:        config,
		configPath:    configPath,
		filter:        NewEventFilter(&config),
		alertFilter:   NewAlertFilterWithLists(&config.AlertFilter, &config.NativeLists),
		rateLimiter:   NewRateLimiter(config.RateLimiter),
		enricher:      enricher,
		sshHydrator:   NewSSHHydrator(),
		sshdConfig:    NewSSHDConfigReader(),
		eventChan:     make(chan SecurityEvent, eventChannelBufferSize),
		shutdownChan:  make(chan struct{}),
		kernelSupport: support,
		outputMode:    support.OutputMode(),
		pinManager:    NewBPFPinManager(),
		discarders:    NewDiscarderManager(),
	}

	nativeLog.Info().Str("output_mode", agent.outputMode.String()).Msg("Selected BPF output mode")

	// Load persisted detection rules from disk (if any)
	if err := agent.LoadRulesFromDisk(); err != nil {
		nativeLog.Warn().Err(err).Msg("Failed to load persisted detection rules")
	}

	// Start file-integrity monitoring if enabled (baseline scan runs in the
	// background, so this doesn't block startup).
	agent.initFIM()

	return agent, nil
}

// Type returns the agent type
func (a *NativeEBPFAgent) Type() AgentType {
	return AgentTypeNative
}

// Name returns the human-readable name
func (a *NativeEBPFAgent) Name() string {
	return "Native eBPF"
}

// Version returns the agent version
func (a *NativeEBPFAgent) Version() (string, error) {
	return agentVersion, nil
}

// Start starts the native eBPF agent by loading BPF programs
func (a *NativeEBPFAgent) Start(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.running {
		return nil
	}

	// Cleanup any existing pinned programs from previous runs
	// This ensures a clean slate and prevents stale program conflicts
	if err := a.pinManager.CleanupExistingPins(); err != nil {
		nativeLog.Warn().Err(err).Msg("Failed to cleanup existing BPF pins, continuing anyway")
	}

	// Setup pin directories
	if err := a.pinManager.EnsurePinDirectories(); err != nil {
		nativeLog.Warn().Err(err).Msg("Failed to setup BPF pin directories, programs will not be pinned")
	}

	// Load all BPF programs
	if err := a.loadAllPrograms(); err != nil {
		a.closeAllObjects()
		return fmt.Errorf("failed to load BPF programs: %w", err)
	}

	// Register discarder maps from all loaded programs
	a.registerDiscarderMaps()

	// Populate in-kernel discarder maps from config
	if err := a.discarders.SyncFromConfig(&a.config); err != nil {
		nativeLog.Warn().Err(err).Msg("Failed to sync some discarder maps, continuing anyway")
	}

	// Exclude agent's own PID from all BPF programs to prevent self-monitoring noise.
	// This is critical for the BPF syscall monitor to avoid recursive events.
	agentPID := uint32(os.Getpid())
	if err := a.discarders.AddPID(agentPID); err != nil {
		nativeLog.Warn().Err(err).Uint32("pid", agentPID).Msg("Failed to add agent PID to discarder")
	} else {
		nativeLog.Info().Uint32("pid", agentPID).Msg("Added agent PID to in-kernel discarders")
	}

	// Pin all programs for lifecycle management
	if err := a.pinAllPrograms(); err != nil {
		nativeLog.Warn().Err(err).Msg("Failed to pin some BPF programs, continuing anyway")
	}

	// Attach all tracepoints
	if err := a.attachAllTracepoints(); err != nil {
		a.closeAllLinks()
		a.closeAllObjects()
		return fmt.Errorf("failed to attach tracepoints: %w", err)
	}

	a.running = true
	nativeLog.Info().Str("pin_path", BPFPinBasePath).Msg("Native eBPF agent started with pinned programs")
	return nil
}

func (a *NativeEBPFAgent) Stop(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.running {
		return nil
	}

	// Close all tracepoint links first
	a.closeAllLinks()

	// Close all BPF objects
	a.closeAllObjects()

	// Cleanup pinned programs
	if a.pinManager != nil {
		if err := a.pinManager.UnpinAll(); err != nil {
			nativeLog.Warn().Err(err).Msg("Failed to cleanup pinned BPF programs")
		} else {
			nativeLog.Debug().Msg("Cleaned up pinned BPF programs")
		}
	}

	a.running = false
	nativeLog.Info().Msg("Native eBPF agent stopped")
	return nil
}

// IsRunning returns whether the agent is running
func (a *NativeEBPFAgent) IsRunning() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.running
}

func (a *NativeEBPFAgent) LoadConfig() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	config, err := LoadConfigFromFile(a.configPath)
	if err != nil {
		return err
	}

	a.config = config
	a.filter = NewEventFilter(&a.config)

	nativeLog.Info().Str("path", a.configPath).Msg("Loaded native agent config")
	return nil
}

// UpdateConfig updates the agent configuration from endpoint
func (a *NativeEBPFAgent) UpdateConfig(config AgentConfig) error {
	// AgentConfig is a generic interface, we need our specific NativeConfig
	// This method is called by the endpoint sync mechanism
	return nil
}

// UpdateNativeConfig updates the native agent config and persists it
func (a *NativeEBPFAgent) UpdateNativeConfig(newConfig NativeConfig) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Merge with current config (new config takes precedence)
	merged := MergeConfig(a.config, newConfig)

	// Validate
	if err := merged.Validate(); err != nil {
		return err
	}

	// Save to file
	if err := SaveConfigToFile(merged, a.configPath); err != nil {
		nativeLog.Warn().Err(err).Msg("Failed to save config to file")
		// Continue anyway - we can still use the config in memory
	}

	// Apply the new config
	a.config = merged
	a.filter = NewEventFilter(&a.config)
	a.alertFilter.UpdateConfig(&a.config.AlertFilter)
	a.rateLimiter.UpdateConfig(a.config.RateLimiter)

	// Update enricher settings
	a.enricher.SetEnabled(merged.EnableEnrichment)

	// Resync in-kernel discarder maps with new config
	if a.discarders != nil && a.discarders.MapCount() > 0 {
		if err := a.discarders.SyncFromConfig(&a.config); err != nil {
			nativeLog.Warn().Err(err).Msg("Failed to resync discarder maps on config update")
		}
	}

	// Start FIM if this config push enabled it (idempotent — a no-op when
	// already running or still disabled).
	a.initFIM()

	nativeLog.Info().Msg("Updated native agent config")
	return nil
}

// GetNativeConfig returns the current native config
func (a *NativeEBPFAgent) GetNativeConfig() NativeConfig {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.config
}

// UpdateComplianceConfig is a wire-compat no-op. The agent no longer
// evaluates compliance rules locally — the endpoint owns that logic now.
// The handler still accepts the command so older API versions can keep
// using it as a "enable/disable native agent" trigger.
func (a *NativeEBPFAgent) UpdateComplianceConfig(configJSON []byte) error {
	nativeLog.Debug().Int("bytes", len(configJSON)).Msg("UpdateComplianceConfig received (no-op on agent — endpoint owns rule evaluation)")
	return nil
}

// GetConfigPath returns the configuration path
func (a *NativeEBPFAgent) GetConfigPath() string {
	return a.configPath
}

// GetRules returns the rule files (native agent doesn't carry rules anymore)
func (a *NativeEBPFAgent) GetRules() ([]RuleFile, error) {
	return nil, nil
}

// UpdateRules is a wire-compat no-op.
func (a *NativeEBPFAgent) UpdateRules(rules []RuleFile) error {
	return nil
}

// GetRulesDir returns the rules directory (empty — rules live on endpoint).
func (a *NativeEBPFAgent) GetRulesDir() string {
	return ""
}

// UpdateRulesFromYAML is a wire-compat no-op. The agent does not run
// rules locally; the endpoint evaluates each event after it arrives.
func (a *NativeEBPFAgent) UpdateRulesFromYAML(yamlData []byte) error {
	nativeLog.Debug().Int("bytes", len(yamlData)).Msg("UpdateRulesFromYAML received (no-op on agent — endpoint owns rule evaluation)")
	return nil
}

// LoadRulesFromDisk is a wire-compat no-op.
func (a *NativeEBPFAgent) LoadRulesFromDisk() error {
	return nil
}

// ServiceName returns the service name (empty for embedded agent)
func (a *NativeEBPFAgent) ServiceName() string {
	return ""
}

// GetServiceStatus returns the service status
func (a *NativeEBPFAgent) GetServiceStatus() (ServiceStatus, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	status := ServiceStatus{
		ActiveState: "embedded",
		SubState:    "embedded",
		Running:     a.running,
	}

	return status, nil
}

// StartService starts the service (same as Start for native agent)
func (a *NativeEBPFAgent) StartService() error {
	return a.Start(context.Background())
}

// StopService stops the service (same as Stop for native agent)
func (a *NativeEBPFAgent) StopService() error {
	return a.Stop(context.Background())
}

// RestartService restarts the service
func (a *NativeEBPFAgent) RestartService() error {
	if err := a.Stop(context.Background()); err != nil {
		return err
	}
	return a.Start(context.Background())
}

// GetServiceLogs returns service logs (not applicable for native agent)
func (a *NativeEBPFAgent) GetServiceLogs(lines int) (string, error) {
	return "", nil
}

// IsInstalled returns whether the native agent can run on this system
func (a *NativeEBPFAgent) IsInstalled() bool {
	return a.kernelSupport.IsSupported()
}

// GetBinaryPath returns "embedded" for native agent
func (a *NativeEBPFAgent) GetBinaryPath() string {
	return "embedded"
}

// GetKernelSupport returns information about kernel eBPF support
func (a *NativeEBPFAgent) GetKernelSupport() KernelSupport {
	return a.kernelSupport
}

func (a *NativeEBPFAgent) GetDiscarderStats() DiscarderStats {
	return a.discarders.GetStats()
}


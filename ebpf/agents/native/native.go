package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"apagent/ebpf"
	"apagent/ebpf/bpfgen"
	"apagent/logger"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/rs/xid"
)

var log = logger.Sublogger("native-agent")

const (
	eventChannelBufferSize = 1000
	agentVersion           = "1.0.0"
)

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
)

// NativeEBPFAgent implements the EBPFAgent interface using native BPF programs
type NativeEBPFAgent struct {
	mu            sync.RWMutex
	config        Config
	configPath    string
	filter        *EventFilter
	enricher      *EventEnricher
	alertEngine   *AlertEngine
	eventChan     chan ebpf.SecurityEvent
	running       bool
	listening     bool
	shutdownChan  chan struct{}
	kernelSupport KernelSupport

	// BPF objects for each program
	execveObjs    *bpfgen.ExecveObjects
	fileopsObjs   *bpfgen.FileopsObjects
	networkObjs   *bpfgen.NetworkObjects
	processObjs   *bpfgen.ProcessObjects
	privilegeObjs *bpfgen.PrivilegeObjects
	mountObjs     *bpfgen.MountObjects
	moduleObjs    *bpfgen.ModuleObjects
	memoryObjs    *bpfgen.MemoryObjects

	// Tracepoint links
	links []link.Link

	// Ring buffer readers
	execveReader    *ringbuf.Reader
	fileopsReader   *ringbuf.Reader
	networkReader   *ringbuf.Reader
	processReader   *ringbuf.Reader
	privilegeReader *ringbuf.Reader
	mountReader     *ringbuf.Reader
	moduleReader    *ringbuf.Reader
	memoryReader    *ringbuf.Reader

	// WaitGroup for reader goroutines
	readerWg sync.WaitGroup
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
		log.Warn().Err(err).Msg("Failed to load config file, using defaults")
		config = DefaultConfig()
	}

	// Create enricher with config settings
	cacheTTL := time.Duration(config.EnrichmentCacheTTLSeconds) * time.Second
	if cacheTTL <= 0 {
		cacheTTL = 30 * time.Second
	}
	enricher := NewEventEnricherWithTTL(cacheTTL)
	enricher.SetEnabled(config.EnableEnrichment)

	// Create alert engine with config or default rules
	alertRules := config.AlertRules
	if alertRules == nil {
		alertRules = DefaultAlertRules()
	}
	alertEngine := NewAlertEngine(alertRules)

	agent := &NativeEBPFAgent{
		config:        config,
		configPath:    configPath,
		filter:        NewEventFilter(&config),
		enricher:      enricher,
		alertEngine:   alertEngine,
		eventChan:     make(chan ebpf.SecurityEvent, eventChannelBufferSize),
		shutdownChan:  make(chan struct{}),
		kernelSupport: support,
	}

	return agent, nil
}

// Type returns the agent type
func (a *NativeEBPFAgent) Type() ebpf.AgentType {
	return ebpf.AgentTypeNative
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

	// Load all BPF programs
	if err := a.loadAllPrograms(); err != nil {
		a.closeAllObjects()
		return fmt.Errorf("failed to load BPF programs: %w", err)
	}

	// Attach all tracepoints
	if err := a.attachAllTracepoints(); err != nil {
		a.closeAllLinks()
		a.closeAllObjects()
		return fmt.Errorf("failed to attach tracepoints: %w", err)
	}

	a.running = true
	log.Info().Msg("Native eBPF agent started")
	return nil
}

// loadAllPrograms loads all BPF program objects
func (a *NativeEBPFAgent) loadAllPrograms() error {
	var err error

	// Load execve program
	a.execveObjs = &bpfgen.ExecveObjects{}
	if err = bpfgen.LoadExecveObjects(a.execveObjs, nil); err != nil {
		return fmt.Errorf("failed to load execve BPF objects: %w", err)
	}
	log.Debug().Msg("Loaded execve BPF program")

	// Load fileops program
	a.fileopsObjs = &bpfgen.FileopsObjects{}
	if err = bpfgen.LoadFileopsObjects(a.fileopsObjs, nil); err != nil {
		return fmt.Errorf("failed to load fileops BPF objects: %w", err)
	}
	log.Debug().Msg("Loaded fileops BPF program")

	// Load network program
	a.networkObjs = &bpfgen.NetworkObjects{}
	if err = bpfgen.LoadNetworkObjects(a.networkObjs, nil); err != nil {
		return fmt.Errorf("failed to load network BPF objects: %w", err)
	}
	log.Debug().Msg("Loaded network BPF program")

	// Load process program
	a.processObjs = &bpfgen.ProcessObjects{}
	if err = bpfgen.LoadProcessObjects(a.processObjs, nil); err != nil {
		return fmt.Errorf("failed to load process BPF objects: %w", err)
	}
	log.Debug().Msg("Loaded process BPF program")

	// Load compliance programs (SOX/PCI)
	a.privilegeObjs = &bpfgen.PrivilegeObjects{}
	if err = bpfgen.LoadPrivilegeObjects(a.privilegeObjs, nil); err != nil {
		return fmt.Errorf("failed to load privilege BPF objects: %w", err)
	}
	log.Debug().Msg("Loaded privilege BPF program")

	a.mountObjs = &bpfgen.MountObjects{}
	if err = bpfgen.LoadMountObjects(a.mountObjs, nil); err != nil {
		return fmt.Errorf("failed to load mount BPF objects: %w", err)
	}
	log.Debug().Msg("Loaded mount BPF program")

	a.moduleObjs = &bpfgen.ModuleObjects{}
	if err = bpfgen.LoadModuleObjects(a.moduleObjs, nil); err != nil {
		return fmt.Errorf("failed to load module BPF objects: %w", err)
	}
	log.Debug().Msg("Loaded module BPF program")

	a.memoryObjs = &bpfgen.MemoryObjects{}
	if err = bpfgen.LoadMemoryObjects(a.memoryObjs, nil); err != nil {
		return fmt.Errorf("failed to load memory BPF objects: %w", err)
	}
	log.Debug().Msg("Loaded memory BPF program")

	return nil
}

// attachAllTracepoints attaches all tracepoint programs
func (a *NativeEBPFAgent) attachAllTracepoints() error {
	var tp link.Link
	var err error

	// Execve tracepoint
	tp, err = link.Tracepoint("syscalls", "sys_enter_execve", a.execveObjs.TracepointSyscallsSysEnterExecve, nil)
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_execve: %w", err)
	}
	a.links = append(a.links, tp)
	log.Debug().Msg("Attached sys_enter_execve tracepoint")

	// File operation tracepoints
	tp, err = link.Tracepoint("syscalls", "sys_enter_openat", a.fileopsObjs.TracepointSyscallsSysEnterOpenat, nil)
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_openat: %w", err)
	}
	a.links = append(a.links, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_unlinkat", a.fileopsObjs.TracepointSyscallsSysEnterUnlinkat, nil)
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_unlinkat: %w", err)
	}
	a.links = append(a.links, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_renameat2", a.fileopsObjs.TracepointSyscallsSysEnterRenameat2, nil)
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_renameat2: %w", err)
	}
	a.links = append(a.links, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_fchmodat", a.fileopsObjs.TracepointSyscallsSysEnterFchmodat, nil)
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_fchmodat: %w", err)
	}
	a.links = append(a.links, tp)
	log.Debug().Msg("Attached file operation tracepoints")

	// Network tracepoints
	tp, err = link.Tracepoint("syscalls", "sys_enter_connect", a.networkObjs.TracepointSyscallsSysEnterConnect, nil)
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_connect: %w", err)
	}
	a.links = append(a.links, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_accept4", a.networkObjs.TracepointSyscallsSysEnterAccept4, nil)
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_accept4: %w", err)
	}
	a.links = append(a.links, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_bind", a.networkObjs.TracepointSyscallsSysEnterBind, nil)
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_bind: %w", err)
	}
	a.links = append(a.links, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_socket", a.networkObjs.TracepointSyscallsSysEnterSocket, nil)
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_socket: %w", err)
	}
	a.links = append(a.links, tp)
	log.Debug().Msg("Attached network tracepoints")

	// Process tracepoints
	tp, err = link.Tracepoint("syscalls", "sys_enter_clone", a.processObjs.TracepointSyscallsSysEnterClone, nil)
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_clone: %w", err)
	}
	a.links = append(a.links, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_kill", a.processObjs.TracepointSyscallsSysEnterKill, nil)
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_kill: %w", err)
	}
	a.links = append(a.links, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_ptrace", a.processObjs.TracepointSyscallsSysEnterPtrace, nil)
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_ptrace: %w", err)
	}
	a.links = append(a.links, tp)
	log.Debug().Msg("Attached process tracepoints")

	// Privilege escalation tracepoints (SOX/PCI compliance)
	tp, err = link.Tracepoint("syscalls", "sys_enter_setuid", a.privilegeObjs.TracepointSyscallsSysEnterSetuid, nil)
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_setuid: %w", err)
	}
	a.links = append(a.links, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_setgid", a.privilegeObjs.TracepointSyscallsSysEnterSetgid, nil)
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_setgid: %w", err)
	}
	a.links = append(a.links, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_setreuid", a.privilegeObjs.TracepointSyscallsSysEnterSetreuid, nil)
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_setreuid: %w", err)
	}
	a.links = append(a.links, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_setregid", a.privilegeObjs.TracepointSyscallsSysEnterSetregid, nil)
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_setregid: %w", err)
	}
	a.links = append(a.links, tp)
	log.Debug().Msg("Attached privilege escalation tracepoints")

	// Mount tracepoints (SOX/PCI compliance)
	tp, err = link.Tracepoint("syscalls", "sys_enter_mount", a.mountObjs.TracepointSyscallsSysEnterMount, nil)
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_mount: %w", err)
	}
	a.links = append(a.links, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_umount", a.mountObjs.TracepointSyscallsSysEnterUmount, nil)
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_umount: %w", err)
	}
	a.links = append(a.links, tp)
	log.Debug().Msg("Attached mount tracepoints")

	// Kernel module tracepoints (SOX/PCI compliance)
	tp, err = link.Tracepoint("syscalls", "sys_enter_init_module", a.moduleObjs.TracepointSyscallsSysEnterInitModule, nil)
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_init_module: %w", err)
	}
	a.links = append(a.links, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_finit_module", a.moduleObjs.TracepointSyscallsSysEnterFinitModule, nil)
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_finit_module: %w", err)
	}
	a.links = append(a.links, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_delete_module", a.moduleObjs.TracepointSyscallsSysEnterDeleteModule, nil)
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_delete_module: %w", err)
	}
	a.links = append(a.links, tp)
	log.Debug().Msg("Attached kernel module tracepoints")

	// Memory protection tracepoints (code injection detection)
	tp, err = link.Tracepoint("syscalls", "sys_enter_mprotect", a.memoryObjs.TracepointSyscallsSysEnterMprotect, nil)
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_mprotect: %w", err)
	}
	a.links = append(a.links, tp)
	log.Debug().Msg("Attached memory protection tracepoints")

	return nil
}

// closeAllLinks closes all tracepoint links
func (a *NativeEBPFAgent) closeAllLinks() {
	for _, l := range a.links {
		l.Close()
	}
	a.links = nil
}

// closeAllObjects closes all BPF objects
func (a *NativeEBPFAgent) closeAllObjects() {
	if a.execveObjs != nil {
		a.execveObjs.Close()
		a.execveObjs = nil
	}
	if a.fileopsObjs != nil {
		a.fileopsObjs.Close()
		a.fileopsObjs = nil
	}
	if a.networkObjs != nil {
		a.networkObjs.Close()
		a.networkObjs = nil
	}
	if a.processObjs != nil {
		a.processObjs.Close()
		a.processObjs = nil
	}
	// Compliance objects
	if a.privilegeObjs != nil {
		a.privilegeObjs.Close()
		a.privilegeObjs = nil
	}
	if a.mountObjs != nil {
		a.mountObjs.Close()
		a.mountObjs = nil
	}
	if a.moduleObjs != nil {
		a.moduleObjs.Close()
		a.moduleObjs = nil
	}
	if a.memoryObjs != nil {
		a.memoryObjs.Close()
		a.memoryObjs = nil
	}
}

// Stop stops the native eBPF agent
func (a *NativeEBPFAgent) Stop(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.running {
		return nil
	}

	a.closeAllLinks()
	a.closeAllObjects()

	a.running = false
	log.Info().Msg("Native eBPF agent stopped")
	return nil
}

// IsRunning returns whether the agent is running
func (a *NativeEBPFAgent) IsRunning() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.running
}

// StartEventListener starts reading events from all ring buffers
func (a *NativeEBPFAgent) StartEventListener(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.listening {
		return nil
	}

	if a.execveObjs == nil {
		return errors.New("BPF objects not loaded, call Start() first")
	}

	var err error

	// Create ring buffer readers for each program
	a.execveReader, err = ringbuf.NewReader(a.execveObjs.Events)
	if err != nil {
		return fmt.Errorf("failed to create execve ring buffer reader: %w", err)
	}

	a.fileopsReader, err = ringbuf.NewReader(a.fileopsObjs.FileEvents)
	if err != nil {
		a.execveReader.Close()
		return fmt.Errorf("failed to create fileops ring buffer reader: %w", err)
	}

	a.networkReader, err = ringbuf.NewReader(a.networkObjs.NetworkEvents)
	if err != nil {
		a.execveReader.Close()
		a.fileopsReader.Close()
		return fmt.Errorf("failed to create network ring buffer reader: %w", err)
	}

	a.processReader, err = ringbuf.NewReader(a.processObjs.ProcessEvents)
	if err != nil {
		a.execveReader.Close()
		a.fileopsReader.Close()
		a.networkReader.Close()
		return fmt.Errorf("failed to create process ring buffer reader: %w", err)
	}

	// Compliance ring buffer readers
	a.privilegeReader, err = ringbuf.NewReader(a.privilegeObjs.PrivilegeEvents)
	if err != nil {
		a.execveReader.Close()
		a.fileopsReader.Close()
		a.networkReader.Close()
		a.processReader.Close()
		return fmt.Errorf("failed to create privilege ring buffer reader: %w", err)
	}

	a.mountReader, err = ringbuf.NewReader(a.mountObjs.MountEvents)
	if err != nil {
		a.execveReader.Close()
		a.fileopsReader.Close()
		a.networkReader.Close()
		a.processReader.Close()
		a.privilegeReader.Close()
		return fmt.Errorf("failed to create mount ring buffer reader: %w", err)
	}

	a.moduleReader, err = ringbuf.NewReader(a.moduleObjs.ModuleEvents)
	if err != nil {
		a.execveReader.Close()
		a.fileopsReader.Close()
		a.networkReader.Close()
		a.processReader.Close()
		a.privilegeReader.Close()
		a.mountReader.Close()
		return fmt.Errorf("failed to create module ring buffer reader: %w", err)
	}

	a.memoryReader, err = ringbuf.NewReader(a.memoryObjs.MemoryEvents)
	if err != nil {
		a.execveReader.Close()
		a.fileopsReader.Close()
		a.networkReader.Close()
		a.processReader.Close()
		a.privilegeReader.Close()
		a.mountReader.Close()
		a.moduleReader.Close()
		return fmt.Errorf("failed to create memory ring buffer reader: %w", err)
	}

	a.listening = true
	a.shutdownChan = make(chan struct{})

	// Start reader goroutines for each ring buffer
	a.readerWg.Add(8)
	go a.readExecveEvents()
	go a.readFileopsEvents()
	go a.readNetworkEvents()
	go a.readProcessEvents()
	go a.readPrivilegeEvents()
	go a.readMountEvents()
	go a.readModuleEvents()
	go a.readMemoryEvents()

	// Start cache cleanup goroutine
	go a.runCacheCleanup()

	log.Info().Msg("Native eBPF event listener started")
	return nil
}

// StopEventListener stops reading events
func (a *NativeEBPFAgent) StopEventListener() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.listening {
		return nil
	}

	// Signal shutdown
	close(a.shutdownChan)

	// Close all readers to unblock Read() calls
	if a.execveReader != nil {
		a.execveReader.Close()
		a.execveReader = nil
	}
	if a.fileopsReader != nil {
		a.fileopsReader.Close()
		a.fileopsReader = nil
	}
	if a.networkReader != nil {
		a.networkReader.Close()
		a.networkReader = nil
	}
	if a.processReader != nil {
		a.processReader.Close()
		a.processReader = nil
	}
	// Compliance readers
	if a.privilegeReader != nil {
		a.privilegeReader.Close()
		a.privilegeReader = nil
	}
	if a.mountReader != nil {
		a.mountReader.Close()
		a.mountReader = nil
	}
	if a.moduleReader != nil {
		a.moduleReader.Close()
		a.moduleReader = nil
	}
	if a.memoryReader != nil {
		a.memoryReader.Close()
		a.memoryReader = nil
	}

	// Wait for all reader goroutines to finish
	a.readerWg.Wait()

	a.listening = false
	log.Info().Msg("Native eBPF event listener stopped")
	return nil
}

// EventChannel returns the channel for receiving security events
func (a *NativeEBPFAgent) EventChannel() <-chan ebpf.SecurityEvent {
	return a.eventChan
}

// IsListening returns whether the event listener is active
func (a *NativeEBPFAgent) IsListening() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.listening
}

// LoadConfig loads the agent configuration from the config file
func (a *NativeEBPFAgent) LoadConfig() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	config, err := LoadConfigFromFile(a.configPath)
	if err != nil {
		return err
	}

	a.config = config
	a.filter = NewEventFilter(&a.config)

	log.Info().Str("path", a.configPath).Msg("Loaded native agent config")
	return nil
}

// UpdateConfig updates the agent configuration from endpoint
func (a *NativeEBPFAgent) UpdateConfig(config ebpf.AgentConfig) error {
	// AgentConfig is a generic interface, we need our specific Config
	// This method is called by the endpoint sync mechanism
	return nil
}

// UpdateNativeConfig updates the native agent config and persists it
func (a *NativeEBPFAgent) UpdateNativeConfig(newConfig Config) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Check if compliance profiles are being applied
	if len(newConfig.ComplianceProfiles) > 0 {
		mergedConfig := newConfig
		var allRules []AlertRule

		for _, profileName := range newConfig.ComplianceProfiles {
			profileConfig, err := ApplyComplianceProfile(profileName)
			if err != nil {
				log.Warn().Err(err).Str("profile", profileName).Msg("Failed to apply compliance profile")
				continue
			}

			// Merge category enables (enable if any profile enables it)
			mergedConfig.EnableProcess = mergedConfig.EnableProcess || profileConfig.EnableProcess
			mergedConfig.EnableFile = mergedConfig.EnableFile || profileConfig.EnableFile
			mergedConfig.EnableNetwork = mergedConfig.EnableNetwork || profileConfig.EnableNetwork
			mergedConfig.EnablePrivilege = mergedConfig.EnablePrivilege || profileConfig.EnablePrivilege
			mergedConfig.EnableFilesystem = mergedConfig.EnableFilesystem || profileConfig.EnableFilesystem
			mergedConfig.EnableKernel = mergedConfig.EnableKernel || profileConfig.EnableKernel
			mergedConfig.EnableMemory = mergedConfig.EnableMemory || profileConfig.EnableMemory
			mergedConfig.EnableEnrichment = mergedConfig.EnableEnrichment || profileConfig.EnableEnrichment
			mergedConfig.EnableAlerts = mergedConfig.EnableAlerts || profileConfig.EnableAlerts

			// Collect all alert rules from all profiles
			allRules = append(allRules, profileConfig.AlertRules...)

			log.Info().Str("profile", profileName).Int("rules", len(profileConfig.AlertRules)).Msg("Applied compliance profile")
		}

		// Deduplicate rules by name
		ruleMap := make(map[string]AlertRule)
		for _, rule := range allRules {
			ruleMap[rule.Name] = rule
		}
		mergedConfig.AlertRules = make([]AlertRule, 0, len(ruleMap))
		for _, rule := range ruleMap {
			mergedConfig.AlertRules = append(mergedConfig.AlertRules, rule)
		}

		// Keep user's enabled state
		mergedConfig.Enabled = newConfig.Enabled
		newConfig = mergedConfig

		log.Info().Int("profiles", len(newConfig.ComplianceProfiles)).Int("total_rules", len(newConfig.AlertRules)).Msg("Applied multiple compliance profiles")
	}

	// Merge with current config (new config takes precedence)
	merged := MergeConfig(a.config, newConfig)

	// Validate
	if err := merged.Validate(); err != nil {
		return err
	}

	// Save to file
	if err := SaveConfigToFile(merged, a.configPath); err != nil {
		log.Warn().Err(err).Msg("Failed to save config to file")
		// Continue anyway - we can still use the config in memory
	}

	// Apply the new config
	a.config = merged
	a.filter = NewEventFilter(&a.config)

	// Update alert rules
	alertRules := merged.AlertRules
	if alertRules == nil {
		alertRules = DefaultAlertRules()
	}
	a.alertEngine.UpdateRules(alertRules)

	// Update enricher settings
	a.enricher.SetEnabled(merged.EnableEnrichment)

	log.Info().Msg("Updated native agent config")
	return nil
}

// GetNativeConfig returns the current native config
func (a *NativeEBPFAgent) GetNativeConfig() Config {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.config
}

// GetConfigPath returns the configuration path
func (a *NativeEBPFAgent) GetConfigPath() string {
	return a.configPath
}

// GetRules returns the rule files (native agent doesn't use external rules)
func (a *NativeEBPFAgent) GetRules() ([]ebpf.RuleFile, error) {
	return nil, nil
}

// UpdateRules updates the rule files (no-op for native agent)
func (a *NativeEBPFAgent) UpdateRules(rules []ebpf.RuleFile) error {
	return nil
}

// GetRulesDir returns the rules directory (empty for native agent)
func (a *NativeEBPFAgent) GetRulesDir() string {
	return ""
}

// ServiceName returns the service name (empty for embedded agent)
func (a *NativeEBPFAgent) ServiceName() string {
	return ""
}

// GetServiceStatus returns the service status
func (a *NativeEBPFAgent) GetServiceStatus() (ebpf.ServiceStatus, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	status := ebpf.ServiceStatus{
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

// sendEvent sends an event to the channel (non-blocking) after applying filters, enrichment, and alerts
func (a *NativeEBPFAgent) sendEvent(event ebpf.SecurityEvent) {
	// Apply filter
	if !a.filter.ShouldInclude(&event) {
		return
	}

	// Enrich with container and namespace info
	a.enricher.Enrich(&event)

	// Apply alert rules (may modify priority/tags or drop event)
	if a.config.EnableAlerts {
		if !a.alertEngine.Evaluate(&event) {
			return // Event dropped by alert rule
		}
	}

	select {
	case a.eventChan <- event:
		log.Debug().Msgf("Sent event: %s (pid=%d, priority=%s)", event.Rule, event.Process.PID, event.Priority)
	default:
		log.Warn().Msg("Event channel full, dropping event")
	}
}

// GetFilterStats returns the filter statistics (total events, filtered events)
func (a *NativeEBPFAgent) GetFilterStats() (total, filtered uint64) {
	return a.filter.Stats()
}

// GetEnrichmentStats returns enrichment cache statistics
func (a *NativeEBPFAgent) GetEnrichmentStats() (containerCacheSize, namespaceCacheSize int) {
	return a.enricher.CacheSize()
}

// GetAlertStats returns alert engine statistics (rules evaluated, rules matched)
func (a *NativeEBPFAgent) GetAlertStats() (evaluated, matched uint64) {
	return a.alertEngine.Stats()
}

// runCacheCleanup periodically cleans up the enrichment cache
func (a *NativeEBPFAgent) runCacheCleanup() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.shutdownChan:
			return
		case <-ticker.C:
			a.enricher.CleanupCache()
			containers, namespaces := a.enricher.CacheSize()
			log.Debug().Int("containers", containers).Int("namespaces", namespaces).Msg("Cleaned enrichment cache")
		}
	}
}

// readExecveEvents reads events from the execve ring buffer
func (a *NativeEBPFAgent) readExecveEvents() {
	defer a.readerWg.Done()
	log.Debug().Msg("Starting execve event reader")

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		record, err := a.execveReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Warn().Err(err).Msg("Error reading from execve ring buffer")
			continue
		}

		event, err := a.parseExecveEvent(record.RawSample)
		if err != nil {
			log.Debug().Err(err).Msg("Error parsing execve event")
			continue
		}

		a.sendEvent(event)
	}
}

// readFileopsEvents reads events from the fileops ring buffer
func (a *NativeEBPFAgent) readFileopsEvents() {
	defer a.readerWg.Done()
	log.Debug().Msg("Starting fileops event reader")

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		record, err := a.fileopsReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Warn().Err(err).Msg("Error reading from fileops ring buffer")
			continue
		}

		event, err := a.parseFileopsEvent(record.RawSample)
		if err != nil {
			log.Debug().Err(err).Msg("Error parsing fileops event")
			continue
		}

		a.sendEvent(event)
	}
}

// readNetworkEvents reads events from the network ring buffer
func (a *NativeEBPFAgent) readNetworkEvents() {
	defer a.readerWg.Done()
	log.Debug().Msg("Starting network event reader")

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		record, err := a.networkReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Warn().Err(err).Msg("Error reading from network ring buffer")
			continue
		}

		event, err := a.parseNetworkEvent(record.RawSample)
		if err != nil {
			log.Debug().Err(err).Msg("Error parsing network event")
			continue
		}

		a.sendEvent(event)
	}
}

// readProcessEvents reads events from the process ring buffer
func (a *NativeEBPFAgent) readProcessEvents() {
	defer a.readerWg.Done()
	log.Debug().Msg("Starting process event reader")

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		record, err := a.processReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Warn().Err(err).Msg("Error reading from process ring buffer")
			continue
		}

		event, err := a.parseProcessEvent(record.RawSample)
		if err != nil {
			log.Debug().Err(err).Msg("Error parsing process event")
			continue
		}

		a.sendEvent(event)
	}
}

// parseExecveEvent converts a raw execve BPF event to a SecurityEvent
func (a *NativeEBPFAgent) parseExecveEvent(data []byte) (ebpf.SecurityEvent, error) {
	var bpfEvent bpfgen.ExecveEvent

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.TimestampNs); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Pid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Ppid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Uid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Gid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Comm); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Filename); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read filename: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Args); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read args: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.ArgsCount); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read args_count: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.RetCode); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read ret_code: %w", err)
	}

	comm := int8ArrayToString(bpfEvent.Comm[:])
	filename := int8ArrayToString(bpfEvent.Filename[:])
	args := int8ArrayToString(bpfEvent.Args[:])

	event := ebpf.SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: ebpf.AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  ebpf.PriorityInformational,
		Rule:      "Process Execution",
		Source:    "syscall",
		Category:  "process",
		Output:    fmt.Sprintf("Process %s executed: %s %s", comm, filename, args),
		Tags:      []string{"process", "execve"},
		Process: ebpf.ProcessInfo{
			PID:     int(bpfEvent.Pid),
			PPID:    int(bpfEvent.Ppid),
			Name:    comm,
			ExePath: filename,
			Cmdline: args,
			UID:     int(bpfEvent.Uid),
		},
		RawFields: map[string]interface{}{
			"timestamp_ns": bpfEvent.TimestampNs,
			"gid":          bpfEvent.Gid,
			"args_count":   bpfEvent.ArgsCount,
			"ret_code":     bpfEvent.RetCode,
		},
	}

	return event, nil
}

// parseFileopsEvent converts a raw fileops BPF event to a SecurityEvent
func (a *NativeEBPFAgent) parseFileopsEvent(data []byte) (ebpf.SecurityEvent, error) {
	var bpfEvent bpfgen.FileEvent

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.TimestampNs); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.EventType); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Pid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Ppid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Uid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Gid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Comm); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Filename); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read filename: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Filename2); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read filename2: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Flags); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read flags: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.RetCode); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read ret_code: %w", err)
	}

	comm := int8ArrayToString(bpfEvent.Comm[:])
	filename := int8ArrayToString(bpfEvent.Filename[:])
	filename2 := int8ArrayToString(bpfEvent.Filename2[:])

	var rule, output string
	var tags []string

	switch bpfEvent.EventType {
	case EventTypeOpen:
		rule = "File Open"
		output = fmt.Sprintf("Process %s opened file: %s (flags=0x%x)", comm, filename, bpfEvent.Flags)
		tags = []string{"file", "open"}
	case EventTypeUnlink:
		rule = "File Delete"
		output = fmt.Sprintf("Process %s deleted file: %s", comm, filename)
		tags = []string{"file", "unlink", "delete"}
	case EventTypeRename:
		rule = "File Rename"
		output = fmt.Sprintf("Process %s renamed file: %s -> %s", comm, filename, filename2)
		tags = []string{"file", "rename"}
	case EventTypeChmod:
		rule = "File Permission Change"
		output = fmt.Sprintf("Process %s changed permissions: %s (mode=0o%o)", comm, filename, bpfEvent.Flags)
		tags = []string{"file", "chmod", "permission"}
	default:
		rule = "File Operation"
		output = fmt.Sprintf("Process %s performed file operation on: %s", comm, filename)
		tags = []string{"file"}
	}

	event := ebpf.SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: ebpf.AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  ebpf.PriorityInformational,
		Rule:      rule,
		Source:    "syscall",
		Category:  "file",
		Output:    output,
		Tags:      tags,
		Process: ebpf.ProcessInfo{
			PID:  int(bpfEvent.Pid),
			PPID: int(bpfEvent.Ppid),
			Name: comm,
			UID:  int(bpfEvent.Uid),
		},
		RawFields: map[string]interface{}{
			"timestamp_ns": bpfEvent.TimestampNs,
			"event_type":   bpfEvent.EventType,
			"filename":     filename,
			"filename2":    filename2,
			"flags":        bpfEvent.Flags,
			"gid":          bpfEvent.Gid,
			"ret_code":     bpfEvent.RetCode,
		},
	}

	return event, nil
}

// parseNetworkEvent converts a raw network BPF event to a SecurityEvent
func (a *NativeEBPFAgent) parseNetworkEvent(data []byte) (ebpf.SecurityEvent, error) {
	var bpfEvent bpfgen.NetworkEvent

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.TimestampNs); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.EventType); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Pid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Ppid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Uid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Gid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Comm); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Family); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read family: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Sport); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read sport: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Dport); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read dport: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Protocol); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read protocol: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Saddr); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read saddr: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Daddr); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read daddr: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.RetCode); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read ret_code: %w", err)
	}

	comm := int8ArrayToString(bpfEvent.Comm[:])

	// Convert address bytes to IP string
	var daddr string
	if bpfEvent.Family == 2 { // AF_INET
		daddr = net.IP(bpfEvent.Daddr[:4]).String()
	} else if bpfEvent.Family == 10 { // AF_INET6
		daddr = net.IP(bpfEvent.Daddr[:]).String()
	}

	var rule, output string
	var tags []string

	switch bpfEvent.EventType {
	case EventTypeConnect:
		rule = "Network Connect"
		output = fmt.Sprintf("Process %s connecting to %s:%d", comm, daddr, bpfEvent.Dport)
		tags = []string{"network", "connect"}
	case EventTypeAccept:
		rule = "Network Accept"
		output = fmt.Sprintf("Process %s accepting connection", comm)
		tags = []string{"network", "accept"}
	case EventTypeBind:
		rule = "Network Bind"
		output = fmt.Sprintf("Process %s binding to port %d", comm, bpfEvent.Dport)
		tags = []string{"network", "bind"}
	case EventTypeSocket:
		rule = "Socket Create"
		output = fmt.Sprintf("Process %s created socket (family=%d, protocol=%d)", comm, bpfEvent.Family, bpfEvent.Protocol)
		tags = []string{"network", "socket"}
	default:
		rule = "Network Operation"
		output = fmt.Sprintf("Process %s performed network operation", comm)
		tags = []string{"network"}
	}

	event := ebpf.SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: ebpf.AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  ebpf.PriorityInformational,
		Rule:      rule,
		Source:    "syscall",
		Category:  "network",
		Output:    output,
		Tags:      tags,
		Process: ebpf.ProcessInfo{
			PID:  int(bpfEvent.Pid),
			PPID: int(bpfEvent.Ppid),
			Name: comm,
			UID:  int(bpfEvent.Uid),
		},
		RawFields: map[string]interface{}{
			"timestamp_ns": bpfEvent.TimestampNs,
			"event_type":   bpfEvent.EventType,
			"family":       bpfEvent.Family,
			"sport":        bpfEvent.Sport,
			"dport":        bpfEvent.Dport,
			"protocol":     bpfEvent.Protocol,
			"daddr":        daddr,
			"gid":          bpfEvent.Gid,
			"ret_code":     bpfEvent.RetCode,
		},
	}

	return event, nil
}

// parseProcessEvent converts a raw process BPF event to a SecurityEvent
func (a *NativeEBPFAgent) parseProcessEvent(data []byte) (ebpf.SecurityEvent, error) {
	var bpfEvent bpfgen.ProcessEvent

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.TimestampNs); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.EventType); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Pid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Ppid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Uid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Gid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Comm); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.TargetPid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read target_pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Sig); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read sig: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.PtraceRequest); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read ptrace_request: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.CloneFlags); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read clone_flags: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.RetCode); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read ret_code: %w", err)
	}

	comm := int8ArrayToString(bpfEvent.Comm[:])

	var rule, output string
	var tags []string
	priority := ebpf.PriorityInformational

	switch bpfEvent.EventType {
	case EventTypeClone:
		rule = "Process Clone"
		output = fmt.Sprintf("Process %s cloned (flags=0x%x)", comm, bpfEvent.CloneFlags)
		tags = []string{"process", "clone"}
	case EventTypeKill:
		rule = "Process Signal"
		output = fmt.Sprintf("Process %s sent signal %d to PID %d", comm, bpfEvent.Sig, bpfEvent.TargetPid)
		tags = []string{"process", "kill", "signal"}
		if bpfEvent.Sig == 9 { // SIGKILL
			priority = ebpf.PriorityWarning
		}
	case EventTypePtrace:
		rule = "Process Ptrace"
		output = fmt.Sprintf("Process %s used ptrace (request=%d) on PID %d", comm, bpfEvent.PtraceRequest, bpfEvent.TargetPid)
		tags = []string{"process", "ptrace", "debug"}
		priority = ebpf.PriorityWarning // Ptrace is often suspicious
	default:
		rule = "Process Operation"
		output = fmt.Sprintf("Process %s performed operation", comm)
		tags = []string{"process"}
	}

	event := ebpf.SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: ebpf.AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  priority,
		Rule:      rule,
		Source:    "syscall",
		Category:  "process",
		Output:    output,
		Tags:      tags,
		Process: ebpf.ProcessInfo{
			PID:  int(bpfEvent.Pid),
			PPID: int(bpfEvent.Ppid),
			Name: comm,
			UID:  int(bpfEvent.Uid),
		},
		RawFields: map[string]interface{}{
			"timestamp_ns":   bpfEvent.TimestampNs,
			"event_type":     bpfEvent.EventType,
			"target_pid":     bpfEvent.TargetPid,
			"sig":            bpfEvent.Sig,
			"ptrace_request": bpfEvent.PtraceRequest,
			"clone_flags":    bpfEvent.CloneFlags,
			"gid":            bpfEvent.Gid,
			"ret_code":       bpfEvent.RetCode,
		},
	}

	return event, nil
}

// int8ArrayToString converts an int8 array to a string, stopping at the first null byte
func int8ArrayToString(arr []int8) string {
	buf := make([]byte, 0, len(arr))
	for _, c := range arr {
		if c == 0 {
			break
		}
		buf = append(buf, byte(c))
	}
	return string(buf)
}

// nullTerminatedString converts a byte slice to a string, stopping at the first null byte
func nullTerminatedString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// readPrivilegeEvents reads events from the privilege ring buffer
func (a *NativeEBPFAgent) readPrivilegeEvents() {
	defer a.readerWg.Done()
	log.Debug().Msg("Starting privilege event reader")

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		record, err := a.privilegeReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Warn().Err(err).Msg("Error reading from privilege ring buffer")
			continue
		}

		event, err := a.parsePrivilegeEvent(record.RawSample)
		if err != nil {
			log.Debug().Err(err).Msg("Error parsing privilege event")
			continue
		}

		a.sendEvent(event)
	}
}

// readMountEvents reads events from the mount ring buffer
func (a *NativeEBPFAgent) readMountEvents() {
	defer a.readerWg.Done()
	log.Debug().Msg("Starting mount event reader")

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		record, err := a.mountReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Warn().Err(err).Msg("Error reading from mount ring buffer")
			continue
		}

		event, err := a.parseMountEvent(record.RawSample)
		if err != nil {
			log.Debug().Err(err).Msg("Error parsing mount event")
			continue
		}

		a.sendEvent(event)
	}
}

// readModuleEvents reads events from the module ring buffer
func (a *NativeEBPFAgent) readModuleEvents() {
	defer a.readerWg.Done()
	log.Debug().Msg("Starting module event reader")

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		record, err := a.moduleReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Warn().Err(err).Msg("Error reading from module ring buffer")
			continue
		}

		event, err := a.parseModuleEvent(record.RawSample)
		if err != nil {
			log.Debug().Err(err).Msg("Error parsing module event")
			continue
		}

		a.sendEvent(event)
	}
}

// readMemoryEvents reads events from the memory ring buffer
func (a *NativeEBPFAgent) readMemoryEvents() {
	defer a.readerWg.Done()
	log.Debug().Msg("Starting memory event reader")

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		record, err := a.memoryReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Warn().Err(err).Msg("Error reading from memory ring buffer")
			continue
		}

		event, err := a.parseMemoryEvent(record.RawSample)
		if err != nil {
			log.Debug().Err(err).Msg("Error parsing memory event")
			continue
		}

		a.sendEvent(event)
	}
}

// parsePrivilegeEvent converts a raw privilege BPF event to a SecurityEvent
func (a *NativeEBPFAgent) parsePrivilegeEvent(data []byte) (ebpf.SecurityEvent, error) {
	var bpfEvent bpfgen.PrivilegeEvent

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.TimestampNs); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.EventType); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Pid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Ppid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Uid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Gid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Comm); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.NewUid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read new_uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.NewGid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read new_gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.NewEuid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read new_euid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.NewEgid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read new_egid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.RetCode); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read ret_code: %w", err)
	}

	comm := int8ArrayToString(bpfEvent.Comm[:])

	var rule, output string
	var tags []string
	priority := ebpf.PriorityWarning // Privilege changes are high priority

	switch bpfEvent.EventType {
	case EventTypeSetuid:
		rule = "Privilege Escalation: setuid"
		output = fmt.Sprintf("Process %s (pid=%d) called setuid to UID %d", comm, bpfEvent.Pid, bpfEvent.NewUid)
		tags = []string{"privilege", "setuid", "compliance", "sox", "pci"}
	case EventTypeSetgid:
		rule = "Privilege Escalation: setgid"
		output = fmt.Sprintf("Process %s (pid=%d) called setgid to GID %d", comm, bpfEvent.Pid, bpfEvent.NewGid)
		tags = []string{"privilege", "setgid", "compliance", "sox", "pci"}
	case EventTypeSetreuid:
		rule = "Privilege Escalation: setreuid"
		output = fmt.Sprintf("Process %s (pid=%d) called setreuid (ruid=%d, euid=%d)", comm, bpfEvent.Pid, bpfEvent.NewUid, bpfEvent.NewEuid)
		tags = []string{"privilege", "setreuid", "compliance", "sox", "pci"}
	case EventTypeSetregid:
		rule = "Privilege Escalation: setregid"
		output = fmt.Sprintf("Process %s (pid=%d) called setregid (rgid=%d, egid=%d)", comm, bpfEvent.Pid, bpfEvent.NewGid, bpfEvent.NewEgid)
		tags = []string{"privilege", "setregid", "compliance", "sox", "pci"}
	default:
		rule = "Privilege Change"
		output = fmt.Sprintf("Process %s (pid=%d) performed privilege change", comm, bpfEvent.Pid)
		tags = []string{"privilege", "compliance"}
	}

	// Escalation to root is critical
	if bpfEvent.NewUid == 0 || bpfEvent.NewEuid == 0 {
		priority = ebpf.PriorityCritical
		output += " [ESCALATION TO ROOT]"
	}

	event := ebpf.SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: ebpf.AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  priority,
		Rule:      rule,
		Source:    "syscall",
		Category:  "privilege",
		Output:    output,
		Tags:      tags,
		Process: ebpf.ProcessInfo{
			PID:  int(bpfEvent.Pid),
			PPID: int(bpfEvent.Ppid),
			Name: comm,
			UID:  int(bpfEvent.Uid),
		},
		RawFields: map[string]interface{}{
			"timestamp_ns": bpfEvent.TimestampNs,
			"event_type":   bpfEvent.EventType,
			"new_uid":      bpfEvent.NewUid,
			"new_gid":      bpfEvent.NewGid,
			"new_euid":     bpfEvent.NewEuid,
			"new_egid":     bpfEvent.NewEgid,
			"gid":          bpfEvent.Gid,
			"ret_code":     bpfEvent.RetCode,
		},
	}

	return event, nil
}

// parseMountEvent converts a raw mount BPF event to a SecurityEvent
func (a *NativeEBPFAgent) parseMountEvent(data []byte) (ebpf.SecurityEvent, error) {
	var bpfEvent bpfgen.MountEvent

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.TimestampNs); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.EventType); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Pid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Ppid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Uid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Gid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Comm); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Source); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read source: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Target); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read target: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Fstype); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read fstype: %w", err)
	}
	// Skip padding
	var padding [4]byte
	binary.Read(reader, binary.LittleEndian, &padding)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Flags); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read flags: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.RetCode); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read ret_code: %w", err)
	}

	comm := int8ArrayToString(bpfEvent.Comm[:])
	source := int8ArrayToString(bpfEvent.Source[:])
	target := int8ArrayToString(bpfEvent.Target[:])
	fstype := int8ArrayToString(bpfEvent.Fstype[:])

	var rule, output string
	var tags []string
	priority := ebpf.PriorityWarning // Mount operations are security-sensitive

	switch bpfEvent.EventType {
	case EventTypeMount:
		rule = "Filesystem Mount"
		output = fmt.Sprintf("Process %s (pid=%d) mounted %s on %s (type=%s, flags=0x%x)", comm, bpfEvent.Pid, source, target, fstype, bpfEvent.Flags)
		tags = []string{"mount", "filesystem", "compliance", "sox", "pci"}
	case EventTypeUmount:
		rule = "Filesystem Unmount"
		output = fmt.Sprintf("Process %s (pid=%d) unmounted %s", comm, bpfEvent.Pid, target)
		tags = []string{"umount", "filesystem", "compliance", "sox", "pci"}
	default:
		rule = "Filesystem Operation"
		output = fmt.Sprintf("Process %s (pid=%d) performed filesystem operation", comm, bpfEvent.Pid)
		tags = []string{"filesystem", "compliance"}
	}

	event := ebpf.SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: ebpf.AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  priority,
		Rule:      rule,
		Source:    "syscall",
		Category:  "filesystem",
		Output:    output,
		Tags:      tags,
		Process: ebpf.ProcessInfo{
			PID:  int(bpfEvent.Pid),
			PPID: int(bpfEvent.Ppid),
			Name: comm,
			UID:  int(bpfEvent.Uid),
		},
		RawFields: map[string]interface{}{
			"timestamp_ns": bpfEvent.TimestampNs,
			"event_type":   bpfEvent.EventType,
			"source":       source,
			"target":       target,
			"fstype":       fstype,
			"flags":        bpfEvent.Flags,
			"gid":          bpfEvent.Gid,
			"ret_code":     bpfEvent.RetCode,
		},
	}

	return event, nil
}

// parseModuleEvent converts a raw module BPF event to a SecurityEvent
func (a *NativeEBPFAgent) parseModuleEvent(data []byte) (ebpf.SecurityEvent, error) {
	var bpfEvent bpfgen.ModuleEvent

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.TimestampNs); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.EventType); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Pid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Ppid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Uid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Gid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Comm); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.ModuleName); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read module_name: %w", err)
	}
	// Skip padding
	var padding [4]byte
	binary.Read(reader, binary.LittleEndian, &padding)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.ModuleSize); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read module_size: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Flags); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read flags: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.RetCode); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read ret_code: %w", err)
	}

	comm := int8ArrayToString(bpfEvent.Comm[:])
	moduleName := int8ArrayToString(bpfEvent.ModuleName[:])

	var rule, output string
	var tags []string
	priority := ebpf.PriorityCritical // Kernel module operations are critical

	switch bpfEvent.EventType {
	case EventTypeInitModule:
		rule = "Kernel Module Load"
		output = fmt.Sprintf("Process %s (pid=%d) loaded kernel module (size=%d bytes)", comm, bpfEvent.Pid, bpfEvent.ModuleSize)
		tags = []string{"module", "kernel", "init_module", "compliance", "sox", "pci"}
	case EventTypeFinitModule:
		rule = "Kernel Module Load (from file)"
		output = fmt.Sprintf("Process %s (pid=%d) loaded kernel module from file", comm, bpfEvent.Pid)
		tags = []string{"module", "kernel", "finit_module", "compliance", "sox", "pci"}
	case EventTypeDeleteModule:
		rule = "Kernel Module Unload"
		output = fmt.Sprintf("Process %s (pid=%d) unloaded kernel module: %s", comm, bpfEvent.Pid, moduleName)
		tags = []string{"module", "kernel", "delete_module", "compliance", "sox", "pci"}
	default:
		rule = "Kernel Module Operation"
		output = fmt.Sprintf("Process %s (pid=%d) performed kernel module operation", comm, bpfEvent.Pid)
		tags = []string{"module", "kernel", "compliance"}
	}

	event := ebpf.SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: ebpf.AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  priority,
		Rule:      rule,
		Source:    "syscall",
		Category:  "kernel",
		Output:    output,
		Tags:      tags,
		Process: ebpf.ProcessInfo{
			PID:  int(bpfEvent.Pid),
			PPID: int(bpfEvent.Ppid),
			Name: comm,
			UID:  int(bpfEvent.Uid),
		},
		RawFields: map[string]interface{}{
			"timestamp_ns": bpfEvent.TimestampNs,
			"event_type":   bpfEvent.EventType,
			"module_name":  moduleName,
			"module_size":  bpfEvent.ModuleSize,
			"flags":        bpfEvent.Flags,
			"gid":          bpfEvent.Gid,
			"ret_code":     bpfEvent.RetCode,
		},
	}

	return event, nil
}

// parseMemoryEvent converts a raw memory BPF event to a SecurityEvent
func (a *NativeEBPFAgent) parseMemoryEvent(data []byte) (ebpf.SecurityEvent, error) {
	var bpfEvent bpfgen.MemoryEvent

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.TimestampNs); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.EventType); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Pid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Ppid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Uid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Gid); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Comm); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	// Skip padding
	var padding [4]byte
	binary.Read(reader, binary.LittleEndian, &padding)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Addr); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read addr: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Len); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read len: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Prot); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read prot: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.RetCode); err != nil {
		return ebpf.SecurityEvent{}, fmt.Errorf("failed to read ret_code: %w", err)
	}

	comm := int8ArrayToString(bpfEvent.Comm[:])

	// Decode protection flags
	protStr := ""
	if bpfEvent.Prot&0x1 != 0 {
		protStr += "R"
	}
	if bpfEvent.Prot&0x2 != 0 {
		protStr += "W"
	}
	if bpfEvent.Prot&0x4 != 0 {
		protStr += "X"
	}

	rule := "Memory Protection Change"
	output := fmt.Sprintf("Process %s (pid=%d) set memory at 0x%x (len=%d) to %s", comm, bpfEvent.Pid, bpfEvent.Addr, bpfEvent.Len, protStr)
	tags := []string{"memory", "mprotect", "exec", "code_injection"}
	priority := ebpf.PriorityWarning

	// Making memory writable and executable is highly suspicious
	if bpfEvent.Prot&0x2 != 0 && bpfEvent.Prot&0x4 != 0 { // W+X
		priority = ebpf.PriorityCritical
		output += " [W+X - POTENTIAL CODE INJECTION]"
	}

	event := ebpf.SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: ebpf.AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  priority,
		Rule:      rule,
		Source:    "syscall",
		Category:  "memory",
		Output:    output,
		Tags:      tags,
		Process: ebpf.ProcessInfo{
			PID:  int(bpfEvent.Pid),
			PPID: int(bpfEvent.Ppid),
			Name: comm,
			UID:  int(bpfEvent.Uid),
		},
		RawFields: map[string]interface{}{
			"timestamp_ns": bpfEvent.TimestampNs,
			"event_type":   bpfEvent.EventType,
			"addr":         bpfEvent.Addr,
			"len":          bpfEvent.Len,
			"prot":         bpfEvent.Prot,
			"prot_str":     protStr,
			"gid":          bpfEvent.Gid,
			"ret_code":     bpfEvent.RetCode,
		},
	}

	return event, nil
}

// init registers the native agent with the factory
func init() {
	ebpf.Register(ebpf.AgentTypeNative, func() (ebpf.EBPFAgent, error) {
		return NewNativeAgent()
	})
}

package ebpf

import (
	"strings"
	"sync/atomic"
	"time"

	"akagent/ebpf/rules"
)

// AlertFilter provides semantic filtering of security events
// It evaluates events against rules to determine if they should be emitted
// This reduces noise by filtering out events that have no security value
type AlertFilter struct {
	config      *AlertFilterConfig
	nativeLists *NativeListConfig  // Native lists configuration for SOX/PCI detection
	ruleEngine  *rules.RuleEngine  // Database-driven rule engine

	// Statistics
	totalEvents   uint64
	alertedEvents uint64
	droppedEvents uint64
}

// AlertFilterStats contains statistics about alert filtering
type AlertFilterStats struct {
	TotalEvents   uint64
	AlertedEvents uint64
	DroppedEvents uint64
	AlertRate     float64
}

// NewAlertFilter creates a new alert filter from the given configuration
func NewAlertFilter(config *AlertFilterConfig) *AlertFilter {
	defaultLists := DefaultNativeListConfig()
	return &AlertFilter{
		config:      config,
		nativeLists: &defaultLists,
	}
}

// NewAlertFilterWithLists creates an alert filter with native list configuration
func NewAlertFilterWithLists(config *AlertFilterConfig, nativeLists *NativeListConfig) *AlertFilter {
	return &AlertFilter{
		config:      config,
		nativeLists: nativeLists,
	}
}

// NewAlertFilterWithEngine creates an alert filter with a rule engine for database-driven rules
func NewAlertFilterWithEngine(config *AlertFilterConfig, engine *rules.RuleEngine) *AlertFilter {
	defaultLists := DefaultNativeListConfig()
	return &AlertFilter{
		config:      config,
		nativeLists: &defaultLists,
		ruleEngine:  engine,
	}
}

// NewAlertFilterFull creates an alert filter with all configuration options
func NewAlertFilterFull(config *AlertFilterConfig, nativeLists *NativeListConfig, engine *rules.RuleEngine) *AlertFilter {
	return &AlertFilter{
		config:      config,
		nativeLists: nativeLists,
		ruleEngine:  engine,
	}
}

// SetRuleEngine sets the rule engine for database-driven rule evaluation
func (f *AlertFilter) SetRuleEngine(engine *rules.RuleEngine) {
	f.ruleEngine = engine
}

// SetNativeLists sets the native list configuration for SOX/PCI detection
func (f *AlertFilter) SetNativeLists(nativeLists *NativeListConfig) {
	f.nativeLists = nativeLists
}

// ShouldAlert returns true if the event should be emitted as an alert
// Events that don't match any alert rules are dropped as noise
func (f *AlertFilter) ShouldAlert(event *SecurityEvent) bool {
	atomic.AddUint64(&f.totalEvents, 1)

	// If alert filtering is disabled, allow all events
	if !f.config.Enabled {
		atomic.AddUint64(&f.alertedEvents, 1)
		return true
	}

	// If a rules profile has been loaded from the API, ONLY send events that match
	// compiled rules. No priority bypass, no hardcoded fallback. This ensures that
	// when an empty profile is pushed (no policies enabled), the agent goes silent.
	if f.ruleEngine != nil && f.ruleEngine.HasProfile() {
		ctx := f.buildEventContext(event)
		matches := f.ruleEngine.Evaluate(ctx)
		if len(matches) > 0 {
			match := matches[0]
			if event.RawFields == nil {
				event.RawFields = make(map[string]interface{})
			}
			event.RawFields["matched_rule_id"] = match.Rule.RuleID
			event.RawFields["matched_rule_name"] = match.Rule.Name
			if match.Rule.Framework != "" {
				event.RawFields["matched_framework"] = match.Rule.Framework
			}
			if len(match.Rule.Tags) > 0 {
				event.RawFields["matched_tags"] = match.Rule.Tags
			}
			atomic.AddUint64(&f.alertedEvents, 1)
			return true
		}
		atomic.AddUint64(&f.droppedEvents, 1)
		return false
	}

	// No profile loaded yet — use legacy behavior with priority bypass + hardcoded rules
	if event.Priority >= PriorityWarning {
		atomic.AddUint64(&f.alertedEvents, 1)
		return true
	}

	// Evaluate against hardcoded rules
	if f.matchesHardcodedRules(event) {
		atomic.AddUint64(&f.alertedEvents, 1)
		return true
	}

	// Event didn't match any rules - drop it
	atomic.AddUint64(&f.droppedEvents, 1)
	return false
}

// matchesAlertRules checks if the event matches any enabled alert rules
// This is only called in the legacy path (no profile loaded from API)
func (f *AlertFilter) matchesAlertRules(event *SecurityEvent) bool {
	// Use rule engine if available and has rules loaded (legacy path: loaded from disk on startup)
	if f.ruleEngine != nil && f.ruleEngine.IsReady() {
		ctx := f.buildEventContext(event)
		matches := f.ruleEngine.Evaluate(ctx)
		if len(matches) > 0 {
			// Attach rule metadata to the event for downstream consumers
			match := matches[0] // Use highest-priority match
			if event.RawFields == nil {
				event.RawFields = make(map[string]interface{})
			}
			event.RawFields["matched_rule_id"] = match.Rule.RuleID
			event.RawFields["matched_rule_name"] = match.Rule.Name
			if match.Rule.Framework != "" {
				event.RawFields["matched_framework"] = match.Rule.Framework
			}
			if len(match.Rule.Tags) > 0 {
				event.RawFields["matched_tags"] = match.Rule.Tags
			}
			return true
		}
	}

	// Fallback to hardcoded rules (when no profile assigned)
	return f.matchesHardcodedRules(event)
}

// matchesHardcodedRules uses built-in rules when no compliance profile is active
func (f *AlertFilter) matchesHardcodedRules(event *SecurityEvent) bool {
	// Critical rules (always enabled)
	if matchSSHActivity(event) {
		return true
	}
	if matchPrivilegeEscalation(event) {
		return true
	}
	if matchKernelModule(event) {
		return true
	}
	if matchProcessInjection(event) {
		return true
	}
	if matchDangerousSignals(event) {
		return true
	}
	if matchNamespaceOperations(event) {
		return true
	}
	if matchCapabilityChanges(event) {
		return true
	}
	if matchNamespaceClone(event) {
		return true
	}
	if matchSysctlWrite(event) {
		return true
	}
	if matchCredentialChange(event) {
		return true
	}
	if matchContainerEscape(event) {
		return true
	}
	if matchVFSSensitiveFileOps(event) {
		return true
	}
	if matchIoctlAbuse(event) {
		return true
	}
	if matchProcessCrash(event) {
		return true
	}

	// Threat detection rules (enabled by native list config)
	if f.nativeLists != nil {
		// Network reconnaissance detection
		if f.nativeLists.DetectNetworkTools && matchNetworkRecon(event) {
			return true
		}

		// Cryptocurrency mining detection
		if f.nativeLists.DetectMinerActivity && matchCryptoMining(event) {
			return true
		}

		// Shell in container detection
		if f.nativeLists.DetectShellInContainer && matchShellInContainer(event) {
			return true
		}

		// Package management detection
		if f.nativeLists.DetectPackageManagement && matchPackageManagement(event) {
			return true
		}

		// Data exfiltration detection (always enabled when native lists are present)
		if matchDataExfiltration(event) {
			return true
		}

		// SOX compliance rules (enabled when sox_monitoring is true)
		if f.nativeLists.SOXMonitoring {
			if matchSOXPrivilegedAccess(event) {
				return true
			}
			if matchSOXCriticalFileAccess(event) {
				return true
			}
			if matchSOXAuditLogTampering(event) {
				return true
			}
			if matchSOXCredentialTampering(event) {
				return true
			}
			if matchSOXAuditLogVFS(event) {
				return true
			}
		}

		// PCI-DSS compliance rules (enabled when pci_monitoring is true)
		if f.nativeLists.PCIMonitoring {
			if matchPCIRemoteAccess(event) {
				return true
			}
			if matchPCICriticalPortAccess(event) {
				return true
			}
			if matchPCIShellInContainer(event) {
				return true
			}
			if matchPCICardholderDataAccess(event) {
				return true
			}
			if matchInsecureProtocol(event) {
				return true
			}
			if matchPCIDataExfiltration(event) {
				return true
			}
			if matchPCITerminalInjection(event) {
				return true
			}
			if matchPCIContainerEscape(event) {
				return true
			}
		}
	}

	// Legacy compliance-only rules (enabled when compliance_mode is true)
	// These are kept for backwards compatibility
	if f.config.ComplianceMode {
		if matchSensitiveFileAccess(event) {
			return true
		}
		if matchNewListeningPort(event) {
			return true
		}
		if matchPackageManagement(event) {
			return true
		}
	}

	return false
}

// buildEventContext converts a SecurityEvent to the rules.EventContext format
func (f *AlertFilter) buildEventContext(event *SecurityEvent) *rules.EventContext {
	ctx := &rules.EventContext{
		EventType:   event.Category,
		PID:         event.Process.PID,
		PPID:        event.Process.PPID,
		UID:         event.Process.UID,
		Comm:        event.Process.Name,
		Exe:         event.Process.ExePath,
		Cmdline:     event.Process.Cmdline,
		ContainerID: event.Container.ID,
		Rule:        event.Rule,
		Output:      event.Output,
		Syscall:     event.Syscall.Name,
	}

	// Extract GID from raw fields if available
	if gid, ok := event.RawFields["gid"].(uint32); ok {
		ctx.GID = int(gid)
	} else if gid, ok := event.RawFields["gid"].(int); ok {
		ctx.GID = gid
	}

	// Extract CgroupID from raw fields if available
	if cgroupID, ok := event.RawFields["cgroup_id"].(uint64); ok {
		ctx.CgroupID = cgroupID
	}

	// Container privileged flag
	ctx.ContainerPrivileged = event.Container.Privileged

	// Extract parent info if available
	if event.Process.ParentName != "" {
		ctx.ParentComm = event.Process.ParentName
	}
	if event.Process.ParentExe != "" {
		ctx.ParentExe = event.Process.ParentExe
	}

	// Extract raw fields for event-specific data
	if newUID, ok := event.RawFields["new_uid"].(uint32); ok {
		ctx.NewUID = int(newUID)
	} else if newUID, ok := event.RawFields["new_uid"].(int); ok {
		ctx.NewUID = newUID
	}
	if oldUID, ok := event.RawFields["old_uid"].(uint32); ok {
		ctx.OldUID = int(oldUID)
	} else if oldUID, ok := event.RawFields["old_uid"].(int); ok {
		ctx.OldUID = oldUID
	}
	if newGID, ok := event.RawFields["new_gid"].(uint32); ok {
		ctx.NewGID = int(newGID)
	} else if newGID, ok := event.RawFields["new_gid"].(int); ok {
		ctx.NewGID = newGID
	}
	if oldGID, ok := event.RawFields["old_gid"].(uint32); ok {
		ctx.OldGID = int(oldGID)
	} else if oldGID, ok := event.RawFields["old_gid"].(int); ok {
		ctx.OldGID = oldGID
	}
	if filename, ok := event.RawFields["filename"].(string); ok {
		ctx.Filename = filename
	}
	if operation, ok := event.RawFields["operation"].(string); ok {
		ctx.Operation = operation
	}
	if direction, ok := event.RawFields["direction"].(string); ok {
		ctx.Direction = direction
	}
	if dstPort, ok := event.RawFields["dst_port"].(int); ok {
		ctx.DstPort = dstPort
	} else if dstPort, ok := event.RawFields["dst_port"].(uint16); ok {
		ctx.DstPort = int(dstPort)
	}

	// Extended fields for data-driven rules
	if sig, ok := event.RawFields["sig"].(int32); ok {
		ctx.Signal = int(sig)
	}
	if targetPID, ok := event.RawFields["target_pid"].(int32); ok {
		ctx.TargetPID = int(targetPID)
	}
	if exitCode, ok := event.RawFields["exit_code"].(int32); ok {
		ctx.ExitCode = int(exitCode)
	}
	if newEUID, ok := event.RawFields["new_euid"].(uint32); ok {
		ctx.NewEUID = int(newEUID)
	}
	if newEGID, ok := event.RawFields["new_egid"].(uint32); ok {
		ctx.NewEGID = int(newEGID)
	}
	if dataLen, ok := event.RawFields["len"].(uint64); ok {
		ctx.DataLen = int(dataLen)
	}
	if path, ok := event.RawFields["path"].(string); ok {
		ctx.Path = path
	}
	if srcPort, ok := event.RawFields["sport"].(uint16); ok {
		ctx.SrcPort = int(srcPort)
	} else if srcPort, ok := event.RawFields["sport"].(int); ok {
		ctx.SrcPort = srcPort
	}

	// Event source
	ctx.Source = event.Source

	// Time-based fields for time-of-day rules
	now := time.Now()
	ctx.DayOfWeek = int(now.Weekday()) // 0=Sunday
	ctx.HourOfDay = now.Hour()
	ctx.IsWeekend = now.Weekday() == time.Saturday || now.Weekday() == time.Sunday

	// Map event types to strings for condition matching
	if event.Category == "" && event.Syscall.Name != "" {
		ctx.EventType = strings.ToLower(event.Syscall.Name)
	}

	return ctx
}

// Stats returns alert filtering statistics
func (f *AlertFilter) Stats() AlertFilterStats {
	total := atomic.LoadUint64(&f.totalEvents)
	alerted := atomic.LoadUint64(&f.alertedEvents)
	dropped := atomic.LoadUint64(&f.droppedEvents)

	var alertRate float64
	if total > 0 {
		alertRate = float64(alerted) / float64(total) * 100
	}

	return AlertFilterStats{
		TotalEvents:   total,
		AlertedEvents: alerted,
		DroppedEvents: dropped,
		AlertRate:     alertRate,
	}
}

// ResetStats resets the alert filtering statistics
func (f *AlertFilter) ResetStats() {
	atomic.StoreUint64(&f.totalEvents, 0)
	atomic.StoreUint64(&f.alertedEvents, 0)
	atomic.StoreUint64(&f.droppedEvents, 0)
}

// UpdateConfig updates the filter configuration
func (f *AlertFilter) UpdateConfig(config *AlertFilterConfig) {
	f.config = config
}

// IsEnabled returns whether alert filtering is enabled
func (f *AlertFilter) IsEnabled() bool {
	return f.config.Enabled
}

// IsComplianceMode returns whether compliance mode is enabled
func (f *AlertFilter) IsComplianceMode() bool {
	return f.config.ComplianceMode
}

// IsSOXMonitoring returns whether SOX monitoring is enabled
func (f *AlertFilter) IsSOXMonitoring() bool {
	return f.nativeLists != nil && f.nativeLists.SOXMonitoring
}

// IsPCIMonitoring returns whether PCI-DSS monitoring is enabled
func (f *AlertFilter) IsPCIMonitoring() bool {
	return f.nativeLists != nil && f.nativeLists.PCIMonitoring
}

// GetNativeLists returns the native list configuration
func (f *AlertFilter) GetNativeLists() *NativeListConfig {
	return f.nativeLists
}

package ebpf

import (
	"testing"
)

func TestAlertFilter_Signal0Dropped(t *testing.T) {
	config := &AlertFilterConfig{
		Enabled:        true,
		ComplianceMode: false,
	}
	filter := NewAlertFilter(config)

	// Signal 0 event (process existence check) - should be DROPPED
	signal0Event := SecurityEvent{
		Category: "process",
		Rule:     "Process Signal",
		Priority: PriorityInformational,
		Process: ProcessInfo{
			Name: "anydesk",
			PID:  1234,
		},
		RawFields: map[string]interface{}{
			"sig":        int32(0), // Signal 0
			"target_pid": int32(5678),
		},
	}

	if filter.ShouldAlert(&signal0Event) {
		t.Error("Signal 0 event should be dropped, but was allowed")
	}
}

func TestAlertFilter_SIGKILLAllowed(t *testing.T) {
	config := &AlertFilterConfig{
		Enabled:        true,
		ComplianceMode: false,
	}
	filter := NewAlertFilter(config)

	// SIGKILL event - should be ALLOWED
	sigkillEvent := SecurityEvent{
		Category: "process",
		Rule:     "Process Signal",
		Priority: PriorityInformational,
		Process: ProcessInfo{
			Name: "bash",
			PID:  1234,
		},
		RawFields: map[string]interface{}{
			"sig":        int32(9), // SIGKILL
			"target_pid": int32(5678),
		},
	}

	if !filter.ShouldAlert(&sigkillEvent) {
		t.Error("SIGKILL event should be allowed, but was dropped")
	}
}

func TestAlertFilter_SSHActivityAllowed(t *testing.T) {
	config := &AlertFilterConfig{
		Enabled:        true,
		ComplianceMode: false,
	}
	filter := NewAlertFilter(config)

	// SSH process execution - should be ALLOWED
	sshEvent := SecurityEvent{
		Category: "process",
		Rule:     "Process Execution",
		Priority: PriorityInformational,
		Process: ProcessInfo{
			Name:    "ssh",
			PID:     1234,
			ExePath: "/usr/bin/ssh",
		},
	}

	if !filter.ShouldAlert(&sshEvent) {
		t.Error("SSH execution event should be allowed, but was dropped")
	}
}

func TestAlertFilter_NetworkPort22Allowed(t *testing.T) {
	config := &AlertFilterConfig{
		Enabled:        true,
		ComplianceMode: false,
	}
	filter := NewAlertFilter(config)

	// Connection to port 22 - should be ALLOWED
	sshConnectEvent := SecurityEvent{
		Category: "network",
		Rule:     "Network Connect",
		Priority: PriorityInformational,
		Process: ProcessInfo{
			Name: "curl",
			PID:  1234,
		},
		RawFields: map[string]interface{}{
			"dport": uint16(22),
		},
	}

	if !filter.ShouldAlert(&sshConnectEvent) {
		t.Error("Port 22 connection event should be allowed, but was dropped")
	}
}

func TestAlertFilter_RandomNetworkDropped(t *testing.T) {
	config := &AlertFilterConfig{
		Enabled:        true,
		ComplianceMode: false, // Not compliance mode
	}
	// Create filter with default native lists but disable miner detection for this test
	// since we want to test truly random port behavior
	nativeLists := DefaultNativeListConfig()
	nativeLists.DetectMinerActivity = false
	filter := NewAlertFilterWithLists(config, &nativeLists)

	// Random network connection to high port - should be DROPPED (in non-compliance mode)
	// Note: Using port 54321 which is not in any security-relevant port lists
	randomConnectEvent := SecurityEvent{
		Category: "network",
		Rule:     "Network Connect",
		Priority: PriorityInformational,
		Process: ProcessInfo{
			Name: "someapp",
			PID:  1234,
		},
		RawFields: map[string]interface{}{
			"dport": uint16(54321), // Truly random high port (not in MinerPorts or PCICriticalPorts)
		},
	}

	if filter.ShouldAlert(&randomConnectEvent) {
		t.Error("Random port connection should be dropped in non-compliance mode, but was allowed")
	}
}

func TestAlertFilter_KernelModuleAlwaysAllowed(t *testing.T) {
	config := &AlertFilterConfig{
		Enabled:        true,
		ComplianceMode: false,
	}
	filter := NewAlertFilter(config)

	// Kernel module load - should ALWAYS be allowed
	moduleEvent := SecurityEvent{
		Category: "kernel",
		Rule:     "Kernel Module Load",
		Priority: PriorityInformational, // Even at low priority
		Process: ProcessInfo{
			Name: "modprobe",
			PID:  1234,
		},
	}

	if !filter.ShouldAlert(&moduleEvent) {
		t.Error("Kernel module event should always be allowed, but was dropped")
	}
}

func TestAlertFilter_PrivilegeEscalationToRoot(t *testing.T) {
	config := &AlertFilterConfig{
		Enabled:        true,
		ComplianceMode: false,
	}
	filter := NewAlertFilter(config)

	// Privilege escalation to root - should be ALLOWED
	privEscEvent := SecurityEvent{
		Category: "privilege",
		Rule:     "Privilege Escalation: setuid",
		Priority: PriorityInformational,
		Process: ProcessInfo{
			Name: "sudo",
			PID:  1234,
		},
		RawFields: map[string]interface{}{
			"new_uid":  uint32(0), // Root
			"new_euid": uint32(0),
		},
	}

	if !filter.ShouldAlert(&privEscEvent) {
		t.Error("Privilege escalation to root should be allowed, but was dropped")
	}
}

func TestAlertFilter_PrivilegeChangeNonRoot(t *testing.T) {
	config := &AlertFilterConfig{
		Enabled:        true,
		ComplianceMode: false,
	}
	filter := NewAlertFilter(config)

	// Privilege change to non-root - should be DROPPED (not a security concern)
	privChangeEvent := SecurityEvent{
		Category: "privilege",
		Rule:     "Privilege Escalation: setuid",
		Priority: PriorityInformational,
		Process: ProcessInfo{
			Name: "someapp",
			PID:  1234,
		},
		RawFields: map[string]interface{}{
			"new_uid":  uint32(1000), // Non-root
			"new_euid": uint32(1000),
		},
	}

	if filter.ShouldAlert(&privChangeEvent) {
		t.Error("Privilege change to non-root should be dropped, but was allowed")
	}
}

func TestAlertFilter_SensitiveFileInComplianceMode(t *testing.T) {
	config := &AlertFilterConfig{
		Enabled:        true,
		ComplianceMode: true, // Compliance mode ON
	}
	filter := NewAlertFilter(config)

	// Access to /etc/passwd - should be ALLOWED in compliance mode
	fileEvent := SecurityEvent{
		Category: "file",
		Rule:     "File Open",
		Priority: PriorityInformational,
		Process: ProcessInfo{
			Name: "cat",
			PID:  1234,
		},
		RawFields: map[string]interface{}{
			"filename": "/etc/passwd",
		},
	}

	if !filter.ShouldAlert(&fileEvent) {
		t.Error("/etc/passwd access should be allowed in compliance mode, but was dropped")
	}
}

func TestAlertFilter_SensitiveFileNotInNormalMode(t *testing.T) {
	config := &AlertFilterConfig{
		Enabled:        true,
		ComplianceMode: false, // Compliance mode OFF
	}
	filter := NewAlertFilter(config)

	// Access to /etc/passwd - should be DROPPED in normal mode
	fileEvent := SecurityEvent{
		Category: "file",
		Rule:     "File Open",
		Priority: PriorityInformational,
		Process: ProcessInfo{
			Name: "cat",
			PID:  1234,
		},
		RawFields: map[string]interface{}{
			"filename": "/etc/passwd",
		},
	}

	if filter.ShouldAlert(&fileEvent) {
		t.Error("/etc/passwd access should be dropped in normal mode, but was allowed")
	}
}

func TestAlertFilter_HighPriorityAlwaysAllowed(t *testing.T) {
	config := &AlertFilterConfig{
		Enabled:        true,
		ComplianceMode: false,
	}
	filter := NewAlertFilter(config)

	// High priority event - should ALWAYS be allowed
	highPriorityEvent := SecurityEvent{
		Category: "process",
		Rule:     "Some Random Rule",
		Priority: PriorityWarning, // Warning or higher
		Process: ProcessInfo{
			Name: "someapp",
			PID:  1234,
		},
	}

	if !filter.ShouldAlert(&highPriorityEvent) {
		t.Error("High priority event should always be allowed, but was dropped")
	}
}

func TestAlertFilter_DisabledPassesAll(t *testing.T) {
	config := &AlertFilterConfig{
		Enabled:        false, // Disabled
		ComplianceMode: false,
	}
	filter := NewAlertFilter(config)

	// Random low-priority event - should be ALLOWED when filter is disabled
	randomEvent := SecurityEvent{
		Category: "process",
		Rule:     "Process Clone",
		Priority: PriorityInformational,
		Process: ProcessInfo{
			Name: "bash",
			PID:  1234,
		},
	}

	if !filter.ShouldAlert(&randomEvent) {
		t.Error("Event should be allowed when filter is disabled, but was dropped")
	}
}

func TestAlertFilter_PackageManagerInComplianceMode(t *testing.T) {
	config := &AlertFilterConfig{
		Enabled:        true,
		ComplianceMode: true,
	}
	filter := NewAlertFilter(config)

	// apt-get execution - should be ALLOWED in compliance mode
	aptEvent := SecurityEvent{
		Category: "process",
		Rule:     "Process Execution",
		Priority: PriorityInformational,
		Process: ProcessInfo{
			Name:    "apt-get",
			PID:     1234,
			ExePath: "/usr/bin/apt-get",
		},
	}

	if !filter.ShouldAlert(&aptEvent) {
		t.Error("apt-get execution should be allowed in compliance mode, but was dropped")
	}
}

func TestAlertFilter_PtraceAllowed(t *testing.T) {
	config := &AlertFilterConfig{
		Enabled:        true,
		ComplianceMode: false,
	}
	filter := NewAlertFilter(config)

	// Ptrace event - should ALWAYS be allowed (suspicious)
	ptraceEvent := SecurityEvent{
		Category: "process",
		Rule:     "Process Ptrace",
		Priority: PriorityInformational,
		Process: ProcessInfo{
			Name: "gdb",
			PID:  1234,
		},
		RawFields: map[string]interface{}{
			"ptrace_request": int32(16), // PTRACE_ATTACH
			"target_pid":     int32(5678),
		},
	}

	if !filter.ShouldAlert(&ptraceEvent) {
		t.Error("Ptrace event should always be allowed, but was dropped")
	}
}

// ============================================================================
// Tests for new event type matchers
// ============================================================================

func TestAlertFilter_CredentialChangeAllowed(t *testing.T) {
	config := &AlertFilterConfig{Enabled: true}
	filter := NewAlertFilter(config)

	event := SecurityEvent{
		Category: "privilege",
		Rule:     "Credential Change",
		Priority: PriorityNotice,
		Source:   "kprobe",
		Process:  ProcessInfo{Name: "su", PID: 1234},
		RawFields: map[string]interface{}{
			"new_uid":  uint32(1000),
			"new_euid": uint32(1000),
		},
	}

	if !filter.ShouldAlert(&event) {
		t.Error("Credential Change event should be allowed, but was dropped")
	}
}

func TestAlertFilter_CredentialEscalationAllowed(t *testing.T) {
	config := &AlertFilterConfig{Enabled: true}
	filter := NewAlertFilter(config)

	event := SecurityEvent{
		Category: "privilege",
		Rule:     "Credential Change — Privilege Escalation",
		Priority: PriorityWarning,
		Source:   "kprobe",
		Process:  ProcessInfo{Name: "exploit", PID: 1234},
		RawFields: map[string]interface{}{
			"new_uid":  uint32(0),
			"new_euid": uint32(0),
		},
	}

	if !filter.ShouldAlert(&event) {
		t.Error("Credential escalation event should be allowed, but was dropped")
	}
}

func TestAlertFilter_ContainerEscapeChrootAllowed(t *testing.T) {
	config := &AlertFilterConfig{Enabled: true}
	filter := NewAlertFilter(config)

	event := SecurityEvent{
		Category: "filesystem",
		Rule:     "Filesystem Root Change (chroot)",
		Priority: PriorityNotice, // test at low priority to verify matcher works
		Process:  ProcessInfo{Name: "malicious", PID: 1234},
		RawFields: map[string]interface{}{
			"path": "/host",
		},
	}

	if !filter.ShouldAlert(&event) {
		t.Error("chroot event should be allowed, but was dropped")
	}
}

func TestAlertFilter_ContainerEscapePivotRootAllowed(t *testing.T) {
	config := &AlertFilterConfig{Enabled: true}
	filter := NewAlertFilter(config)

	event := SecurityEvent{
		Category: "filesystem",
		Rule:     "Filesystem Root Change (pivot_root)",
		Priority: PriorityNotice,
		Process:  ProcessInfo{Name: "malicious", PID: 1234},
		RawFields: map[string]interface{}{
			"path":  "/new_root",
			"path2": "/old_root",
		},
	}

	if !filter.ShouldAlert(&event) {
		t.Error("pivot_root event should be allowed, but was dropped")
	}
}

func TestAlertFilter_ChdirToSensitivePathAllowed(t *testing.T) {
	config := &AlertFilterConfig{Enabled: true}
	filter := NewAlertFilter(config)

	event := SecurityEvent{
		Category: "filesystem",
		Rule:     "Directory Change (chdir)",
		Priority: PriorityNotice,
		Process:  ProcessInfo{Name: "bash", PID: 1234},
		RawFields: map[string]interface{}{
			"path": "/proc/1/root",
		},
	}

	if !filter.ShouldAlert(&event) {
		t.Error("chdir to /proc/ should be allowed, but was dropped")
	}
}

func TestAlertFilter_ChdirToNormalPathDropped(t *testing.T) {
	config := &AlertFilterConfig{Enabled: true}
	filter := NewAlertFilter(config)

	event := SecurityEvent{
		Category: "filesystem",
		Rule:     "Directory Change (chdir)",
		Priority: PriorityNotice,
		Process:  ProcessInfo{Name: "bash", PID: 1234},
		RawFields: map[string]interface{}{
			"path": "/home/user/projects",
		},
	}

	if filter.ShouldAlert(&event) {
		t.Error("chdir to normal path should be dropped, but was allowed")
	}
}

func TestAlertFilter_VFSDeleteSensitiveFileAllowed(t *testing.T) {
	config := &AlertFilterConfig{Enabled: true}
	filter := NewAlertFilter(config)

	event := SecurityEvent{
		Category: "file",
		Rule:     "VFS File Delete",
		Priority: PriorityNotice,
		Source:   "kprobe",
		Process:  ProcessInfo{Name: "rm", PID: 1234},
		RawFields: map[string]interface{}{
			"path": "/etc/shadow",
		},
	}

	if !filter.ShouldAlert(&event) {
		t.Error("VFS delete on /etc/shadow should be allowed, but was dropped")
	}
}

func TestAlertFilter_VFSDeleteNormalFileDropped(t *testing.T) {
	config := &AlertFilterConfig{Enabled: true}
	filter := NewAlertFilter(config)

	event := SecurityEvent{
		Category: "file",
		Rule:     "VFS File Delete",
		Priority: PriorityNotice,
		Source:   "kprobe",
		Process:  ProcessInfo{Name: "rm", PID: 1234},
		RawFields: map[string]interface{}{
			"path": "/tmp/scratch.txt",
		},
	}

	if filter.ShouldAlert(&event) {
		t.Error("VFS delete on /tmp file should be dropped, but was allowed")
	}
}

func TestAlertFilter_VFSSysctlWriteAllowed(t *testing.T) {
	config := &AlertFilterConfig{Enabled: true}
	filter := NewAlertFilter(config)

	event := SecurityEvent{
		Category: "file",
		Rule:     "VFS Attribute Change",
		Priority: PriorityNotice,
		Source:   "kprobe",
		Process:  ProcessInfo{Name: "sysctl", PID: 1234},
		RawFields: map[string]interface{}{
			"path": "/proc/sys/net/ipv4/ip_forward",
		},
	}

	if !filter.ShouldAlert(&event) {
		t.Error("VFS attribute change on /proc/sys/ should be allowed, but was dropped")
	}
}

func TestAlertFilter_IoctlAllowed(t *testing.T) {
	config := &AlertFilterConfig{Enabled: true}
	filter := NewAlertFilter(config)

	event := SecurityEvent{
		Category: "ioctl",
		Rule:     "Security-Relevant Ioctl",
		Priority: PriorityNotice,
		Process:  ProcessInfo{Name: "exploit", PID: 1234},
		RawFields: map[string]interface{}{
			"cmd": uint32(0x5412), // TIOCSTI
		},
	}

	if !filter.ShouldAlert(&event) {
		t.Error("ioctl event should be allowed, but was dropped")
	}
}

func TestAlertFilter_ProcessCrashAllowed(t *testing.T) {
	config := &AlertFilterConfig{Enabled: true}
	filter := NewAlertFilter(config)

	event := SecurityEvent{
		Category: "process",
		Rule:     "Process Exit — Signal",
		Priority: PriorityNotice,
		Source:   "kprobe",
		Process:  ProcessInfo{Name: "victim", PID: 1234},
		RawFields: map[string]interface{}{
			"exit_code": int32(11), // SIGSEGV
		},
	}

	if !filter.ShouldAlert(&event) {
		t.Error("Process crash (SIGSEGV) should be allowed, but was dropped")
	}
}

func TestAlertFilter_ProcessNormalExitDropped(t *testing.T) {
	config := &AlertFilterConfig{Enabled: true}
	filter := NewAlertFilter(config)

	event := SecurityEvent{
		Category: "process",
		Rule:     "Process Exit",
		Priority: PriorityNotice,
		Source:   "kprobe",
		Process:  ProcessInfo{Name: "ls", PID: 1234},
		RawFields: map[string]interface{}{
			"exit_code": int32(0),
		},
	}

	if filter.ShouldAlert(&event) {
		t.Error("Normal process exit should be dropped, but was allowed")
	}
}

func TestAlertFilter_DataExfilInContainerAllowed(t *testing.T) {
	config := &AlertFilterConfig{Enabled: true}
	nativeLists := DefaultNativeListConfig()
	filter := NewAlertFilterWithLists(config, &nativeLists)

	event := SecurityEvent{
		Category:  "file",
		Rule:      "Data Transfer via Sendfile",
		Priority:  PriorityNotice,
		Process:   ProcessInfo{Name: "malware", PID: 1234},
		Container: ContainerInfo{ID: "abc123"},
		RawFields: map[string]interface{}{
			"len": uint64(1024),
		},
	}

	if !filter.ShouldAlert(&event) {
		t.Error("Data transfer from container should be allowed, but was dropped")
	}
}

func TestAlertFilter_DataExfilSmallNonContainerDropped(t *testing.T) {
	config := &AlertFilterConfig{Enabled: true}
	nativeLists := DefaultNativeListConfig()
	filter := NewAlertFilterWithLists(config, &nativeLists)

	event := SecurityEvent{
		Category: "file",
		Rule:     "Data Transfer via Splice",
		Priority: PriorityNotice,
		Process:  ProcessInfo{Name: "nginx", PID: 1234},
		RawFields: map[string]interface{}{
			"len": uint64(4096), // small transfer, not in container
		},
	}

	if filter.ShouldAlert(&event) {
		t.Error("Small data transfer outside container should be dropped, but was allowed")
	}
}

func TestAlertFilter_SOXCredentialTampering(t *testing.T) {
	config := &AlertFilterConfig{Enabled: true}
	nativeLists := DefaultNativeListConfig()
	nativeLists.SOXMonitoring = true
	filter := NewAlertFilterWithLists(config, &nativeLists)

	event := SecurityEvent{
		Category: "privilege",
		Rule:     "Credential Change",
		Priority: PriorityNotice,
		Source:   "kprobe",
		Process:  ProcessInfo{Name: "su", PID: 1234},
	}

	if !filter.ShouldAlert(&event) {
		t.Error("Credential change should be allowed with SOX monitoring, but was dropped")
	}
}

func TestAlertFilter_SOXAuditLogVFS(t *testing.T) {
	config := &AlertFilterConfig{Enabled: true}
	nativeLists := DefaultNativeListConfig()
	nativeLists.SOXMonitoring = true
	filter := NewAlertFilterWithLists(config, &nativeLists)

	event := SecurityEvent{
		Category: "file",
		Rule:     "VFS File Delete",
		Priority: PriorityNotice,
		Source:   "kprobe",
		Process:  ProcessInfo{Name: "attacker", PID: 1234},
		RawFields: map[string]interface{}{
			"path": "/var/log/audit/audit.log",
		},
	}

	if !filter.ShouldAlert(&event) {
		t.Error("VFS delete on audit log should be allowed with SOX monitoring, but was dropped")
	}
}

func TestAlertFilter_PCIDataExfiltration(t *testing.T) {
	config := &AlertFilterConfig{Enabled: true}
	nativeLists := DefaultNativeListConfig()
	nativeLists.PCIMonitoring = true
	filter := NewAlertFilterWithLists(config, &nativeLists)

	event := SecurityEvent{
		Category:  "file",
		Rule:      "Data Transfer via Sendfile",
		Priority:  PriorityNotice,
		Process:   ProcessInfo{Name: "exfil", PID: 1234},
		Container: ContainerInfo{ID: "container123"},
		RawFields: map[string]interface{}{
			"len": uint64(2048),
		},
	}

	if !filter.ShouldAlert(&event) {
		t.Error("Data transfer in container should be allowed with PCI monitoring, but was dropped")
	}
}

func TestAlertFilter_PCITerminalInjection(t *testing.T) {
	config := &AlertFilterConfig{Enabled: true}
	nativeLists := DefaultNativeListConfig()
	nativeLists.PCIMonitoring = true
	filter := NewAlertFilterWithLists(config, &nativeLists)

	event := SecurityEvent{
		Category: "ioctl",
		Rule:     "Security-Relevant Ioctl",
		Priority: PriorityNotice,
		Process:  ProcessInfo{Name: "exploit", PID: 1234},
		RawFields: map[string]interface{}{
			"cmd": uint32(0x5412),
		},
	}

	if !filter.ShouldAlert(&event) {
		t.Error("ioctl should be allowed with PCI monitoring, but was dropped")
	}
}

func TestAlertFilter_PCIContainerEscape(t *testing.T) {
	config := &AlertFilterConfig{Enabled: true}
	nativeLists := DefaultNativeListConfig()
	nativeLists.PCIMonitoring = true
	filter := NewAlertFilterWithLists(config, &nativeLists)

	event := SecurityEvent{
		Category: "filesystem",
		Rule:     "Filesystem Root Change (chroot)",
		Priority: PriorityNotice,
		Process:  ProcessInfo{Name: "escape", PID: 1234},
		RawFields: map[string]interface{}{
			"path": "/host",
		},
	}

	if !filter.ShouldAlert(&event) {
		t.Error("chroot should be allowed with PCI monitoring, but was dropped")
	}
}

func TestAlertFilter_Stats(t *testing.T) {
	config := &AlertFilterConfig{
		Enabled:        true,
		ComplianceMode: false,
	}
	filter := NewAlertFilter(config)

	// Generate some events
	allowedEvent := SecurityEvent{
		Category: "kernel",
		Rule:     "Kernel Module Load",
		Priority: PriorityInformational,
	}

	droppedEvent := SecurityEvent{
		Category: "process",
		Rule:     "Process Signal",
		Priority: PriorityInformational,
		RawFields: map[string]interface{}{
			"sig": int32(0), // Signal 0 - dropped
		},
	}

	// Process events
	filter.ShouldAlert(&allowedEvent)
	filter.ShouldAlert(&droppedEvent)

	stats := filter.Stats()

	if stats.TotalEvents != 2 {
		t.Errorf("Expected TotalEvents=2, got %d", stats.TotalEvents)
	}
	if stats.AlertedEvents != 1 {
		t.Errorf("Expected AlertedEvents=1, got %d", stats.AlertedEvents)
	}
	if stats.DroppedEvents != 1 {
		t.Errorf("Expected DroppedEvents=1, got %d", stats.DroppedEvents)
	}
}

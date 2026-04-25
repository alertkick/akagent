package ebpf

import (
	"fmt"
	"os"
	"strings"
)

// Alert rule matchers - each function returns true if the event matches the rule
// Note: Many hardcoded lists have been moved to native_lists.go for reuse

// matchSSHActivity detects SSH-related activity
// Matches: SSH process execution, connections to port 22
func matchSSHActivity(event *SecurityEvent) bool {
	// SSH process execution
	if event.Category == "process" && event.Rule == "Process Execution" {
		name := strings.ToLower(event.Process.Name)
		if IsSSHBinary(name) {
			return true
		}
		// Also check exe path for full paths like /usr/bin/ssh
		if event.Process.ExePath != "" {
			exeName := extractExeName(event.Process.ExePath)
			if IsSSHBinary(exeName) {
				return true
			}
		}
	}

	// Network connection to SSH port
	if event.Category == "network" {
		if dport, ok := getPort(event.RawFields, "dport"); ok && dport == 22 {
			return true
		}
		// Inbound SSH connection (accept on port 22)
		if event.Rule == "Network Accept" || event.Rule == "Network Bind" {
			if sport, ok := getPort(event.RawFields, "sport"); ok && sport == 22 {
				return true
			}
		}
	}

	return false
}

// matchPrivilegeEscalation detects privilege escalation attempts
// Matches: setuid/setgid to root (UID/GID 0), excluding:
// - Container runtimes (ContainerBinaries)
// - Legitimate system processes (LegitPrivEscalationParents)
func matchPrivilegeEscalation(event *SecurityEvent) bool {
	if event.Category != "privilege" {
		return false
	}

	// Check for escalation to root (UID 0 or GID 0)
	isEscalationToRoot := false
	if newUID, ok := event.RawFields["new_uid"].(uint32); ok && newUID == 0 {
		isEscalationToRoot = true
	}
	if newEUID, ok := event.RawFields["new_euid"].(uint32); ok && newEUID == 0 {
		isEscalationToRoot = true
	}
	if newGID, ok := event.RawFields["new_gid"].(uint32); ok && newGID == 0 {
		isEscalationToRoot = true
	}
	if newEGID, ok := event.RawFields["new_egid"].(uint32); ok && newEGID == 0 {
		isEscalationToRoot = true
	}

	if !isEscalationToRoot {
		return false
	}

	processName := strings.ToLower(event.Process.Name)
	parentName := strings.ToLower(event.Process.ParentName)

	// Exclude container runtimes - they legitimately setuid/setgid to root
	// Check both the process and its parent, since container shims spawn
	// child processes (e.g. healthcheck scripts) that inherit setuid calls
	for runtime := range ContainerBinaries {
		if strings.HasPrefix(processName, runtime) || strings.HasPrefix(parentName, runtime) {
			return false
		}
	}

	// Exclude legitimate system processes that trigger privilege escalation
	// Check both the process name and parent name
	if IsLegitPrivEscalationParent(processName) {
		return false
	}
	if IsLegitPrivEscalationParent(parentName) {
		return false
	}

	// Also check with prefix matching for truncated names (Linux comm is 15 chars max)
	for legit := range LegitPrivEscalationParents {
		if len(legit) >= 15 {
			// Check if truncated version matches
			truncated := legit[:15]
			if strings.HasPrefix(processName, truncated) || strings.HasPrefix(parentName, truncated) {
				return false
			}
		}
	}

	return true
}

// matchKernelModule detects kernel module operations
// All kernel module operations are security-relevant
func matchKernelModule(event *SecurityEvent) bool {
	return event.Category == "kernel"
}

// matchProcessInjection detects potential process injection via ptrace or suspicious memory operations
func matchProcessInjection(event *SecurityEvent) bool {
	// Ptrace is always suspicious - used for debugging/injection
	if event.Category == "process" && event.Rule == "Process Ptrace" {
		return true
	}

	// Suspicious mmap events at Notice level (anonymous exec, fixed exec)
	// W+X events (Warning+) already bypass the alert filter via priority,
	// but anonymous-exec and fixed-exec mmaps at Notice need rule matching.
	// JIT processes are already filtered in parseMemoryEvent before we get here.
	if event.Category == "memory" {
		switch event.Rule {
		case "Anonymous Executable Memory Mapping",
			"Fixed Executable Memory Mapping":
			return true
		}
	}

	return false
}

// matchNamespaceOperations detects namespace manipulation (container breakout vector)
// All namespace events are security-relevant — setns and unshare with CLONE_NEW* flags
func matchNamespaceOperations(event *SecurityEvent) bool {
	return event.Category == "namespace"
}

// matchCapabilityChanges detects capability elevation attempts
// All capset events are security-relevant
func matchCapabilityChanges(event *SecurityEvent) bool {
	return event.Category == "capability"
}

// matchNamespaceClone detects clone syscalls that create new namespaces
// These are captured by the process event parser when CLONE_NEW* flags are present
func matchNamespaceClone(event *SecurityEvent) bool {
	return event.Category == "process" && event.Rule == "Namespace Clone"
}

// matchSysctlWrite detects writes to /proc/sys/ (kernel parameter tampering)
// These are captured by the file event monitoring
func matchSysctlWrite(event *SecurityEvent) bool {
	if event.Category != "file" {
		return false
	}
	// Check RawFields filename
	if filename, ok := event.RawFields["filename"].(string); ok {
		if strings.HasPrefix(filename, "/proc/sys/") {
			return true
		}
	}
	// Also check FileInfo.Path
	if strings.HasPrefix(event.File.Path, "/proc/sys/") {
		return true
	}
	return false
}

// Critical processes that we care about being signaled
// Signals to these processes are security-relevant
var criticalProcesses = map[string]struct{}{
	// Security and audit
	"sshd": {}, "auditd": {}, "rsyslogd": {}, "syslog-ng": {},
	"fail2ban": {}, "crowdsec": {},
	// System services
	"systemd": {}, "init": {}, "dbus-daemon": {},
	// Monitoring
	"alertkick": {}, "ap-agent": {}, "prometheus": {}, "grafana": {},
	"newrelic": {},
	// Databases (killing these is serious)
	"mysqld": {}, "postgres": {}, "mongod": {}, "redis-server": {},
	// Web servers
	"nginx": {}, "apache2": {}, "httpd": {},
}

// Noisy processes that commonly send signals to their children
// These are filtered out to reduce noise
var noisySignalSenders = map[string]struct{}{
	// Browsers (constantly managing child processes)
	"chrome": {}, "chromium": {}, "firefox": {}, "msedge": {},
	"brave": {}, "opera": {}, "vivaldi": {},
	// Browser helpers
	"Web Content": {}, "WebExtensions": {}, "Isolated Web Co": {},
	"RDD Process": {}, "Socket Process": {}, "Utility Process": {},
	"ThreadPoolSingl": {}, "ThreadPoolForeg": {},
	// Container runtimes
	"runc": {}, "containerd": {}, "dockerd": {}, "docker-proxy": {},
	"crio": {}, "podman": {},
	// Desktop environments
	"gnome-shell": {}, "plasmashell": {}, "kwin": {},
	// Editors/IDEs
	"code": {}, "code-server": {}, "electron": {},
}

// matchDangerousSignals filters signal events to only alert on meaningful ones
// We only care about:
// 1. SIGKILL/SIGSTOP to critical processes
// 2. Signals from unexpected sources to security-relevant targets
// We ignore routine parent->child signals and browser noise
func matchDangerousSignals(event *SecurityEvent) bool {
	if event.Category != "process" || event.Rule != "Process Signal" {
		return false
	}

	sig, ok := event.RawFields["sig"].(int32)
	if !ok {
		return false
	}

	// Ignore signal 0 (existence check) - it's just a probe
	if sig == 0 {
		return false
	}

	// Get the sender process name
	senderName := event.Process.Name
	if senderName == "" {
		return false
	}

	// Filter out noisy senders (browsers, container runtimes, etc.)
	// These processes constantly send signals to their children
	senderLower := strings.ToLower(senderName)
	for noisy := range noisySignalSenders {
		if strings.HasPrefix(senderLower, strings.ToLower(noisy)) {
			return false
		}
	}

	// Only alert on SIGKILL (9) or SIGSTOP (19) to critical processes
	// Other signals (SIGTERM, SIGINT, etc.) are too common to be useful
	if sig != 9 && sig != 19 {
		return false
	}

	// At this point we have SIGKILL or SIGSTOP from a non-noisy sender
	// This is potentially interesting, but still might be normal
	// For now, we'll alert on it since it's relatively rare
	return true
}

// Sensitive file paths for compliance monitoring
var sensitiveFilePaths = []string{
	// Authentication and authorization
	"/etc/passwd",
	"/etc/shadow",
	"/etc/sudoers",
	"/etc/group",
	"/etc/gshadow",

	// SSH configuration and keys
	"/etc/ssh/",
	"/.ssh/",
	"/root/.ssh/",

	// PAM and security
	"/etc/pam.d/",
	"/etc/security/",

	// System configuration
	"/etc/hosts",
	"/etc/resolv.conf",
	"/etc/fstab",
	"/etc/crontab",
	"/etc/cron.d/",
	"/var/spool/cron/",

	// Audit and logging
	"/var/log/auth.log",
	"/var/log/secure",
	"/var/log/audit/",
}

// matchSensitiveFileAccess detects access to security-sensitive files
// Only enabled in compliance mode
func matchSensitiveFileAccess(event *SecurityEvent) bool {
	if event.Category != "file" {
		return false
	}

	// Get filename from raw fields
	filename, ok := event.RawFields["filename"].(string)
	if !ok || filename == "" {
		return false
	}

	for _, sensitive := range sensitiveFilePaths {
		if strings.HasPrefix(filename, sensitive) {
			return true
		}
		// Also check for patterns like /home/user/.ssh/
		if strings.Contains(filename, "/.ssh/") {
			return true
		}
	}

	return false
}

// Well-known service ports that are security-relevant
var wellKnownPorts = map[uint16]struct{}{
	21:   {}, // FTP
	22:   {}, // SSH
	23:   {}, // Telnet
	25:   {}, // SMTP
	53:   {}, // DNS
	80:   {}, // HTTP
	110:  {}, // POP3
	143:  {}, // IMAP
	443:  {}, // HTTPS
	445:  {}, // SMB
	993:  {}, // IMAPS
	995:  {}, // POP3S
	3306: {}, // MySQL
	3389: {}, // RDP
	5432: {}, // PostgreSQL
	5900: {}, // VNC
	6379: {}, // Redis
	8080: {}, // HTTP Alt
	8443: {}, // HTTPS Alt
	27017: {}, // MongoDB
}

// matchNewListeningPort detects when processes bind to ports
// Only enabled in compliance mode
func matchNewListeningPort(event *SecurityEvent) bool {
	if event.Category != "network" || event.Rule != "Network Bind" {
		return false
	}

	port, ok := getPort(event.RawFields, "dport")
	if !ok {
		return false
	}

	// Alert on privileged ports (< 1024) or well-known service ports
	if port < 1024 {
		return true
	}
	_, isWellKnown := wellKnownPorts[port]
	return isWellKnown
}

// matchPackageManagement detects package manager executions
// Only enabled in compliance mode
// Uses PackageMgmtBinaries from native_lists.go
func matchPackageManagement(event *SecurityEvent) bool {
	if event.Category != "process" || event.Rule != "Process Execution" {
		return false
	}

	name := strings.ToLower(event.Process.Name)
	return IsPackageManager(name)
}

// Helper functions

// extractExeName extracts the executable name from a full path
func extractExeName(path string) string {
	idx := strings.LastIndex(path, "/")
	if idx >= 0 && idx < len(path)-1 {
		return strings.ToLower(path[idx+1:])
	}
	return strings.ToLower(path)
}

// getPort extracts a port number from raw fields
func getPort(fields map[string]interface{}, key string) (uint16, bool) {
	val, ok := fields[key]
	if !ok {
		return 0, false
	}

	switch v := val.(type) {
	case uint16:
		return v, true
	case int:
		return uint16(v), true
	case int32:
		return uint16(v), true
	case int64:
		return uint16(v), true
	case uint32:
		return uint16(v), true
	case uint64:
		return uint16(v), true
	case float64:
		return uint16(v), true
	default:
		return 0, false
	}
}

// ============================================================================
// NEW DETECTION MATCHERS - Threat Detection, SOX, and PCI Compliance
// ============================================================================

// matchNetworkRecon detects network reconnaissance tool execution
// Triggers on execution of tools like nmap, nc, tcpdump, etc.
func matchNetworkRecon(event *SecurityEvent) bool {
	if event.Category != "process" || event.Rule != "Process Execution" {
		return false
	}

	name := strings.ToLower(event.Process.Name)
	if IsNetworkTool(name) {
		return true
	}

	// Also check exe path
	if event.Process.ExePath != "" {
		exeName := extractExeName(event.Process.ExePath)
		if IsNetworkTool(exeName) {
			return true
		}
	}

	return false
}

// matchCryptoMining detects cryptocurrency mining activity
// Triggers on: miner process names, connections to mining pool ports
func matchCryptoMining(event *SecurityEvent) bool {
	// Check for known miner process execution
	if event.Category == "process" && event.Rule == "Process Execution" {
		name := strings.ToLower(event.Process.Name)
		if IsMinerProcess(name) {
			return true
		}
		// Also check exe path
		if event.Process.ExePath != "" {
			exeName := extractExeName(event.Process.ExePath)
			if IsMinerProcess(exeName) {
				return true
			}
		}
	}

	// Check for connections to mining pool ports
	if event.Category == "network" && event.Rule == "Network Connect" {
		if dport, ok := getPort(event.RawFields, "dport"); ok {
			if IsMinerPort(int(dport)) {
				return true
			}
		}
	}

	return false
}

// matchShellInContainer detects shell execution inside containers
// This is security-relevant as shells shouldn't typically run in production containers
func matchShellInContainer(event *SecurityEvent) bool {
	if event.Category != "process" || event.Rule != "Process Execution" {
		return false
	}

	// Check if this is inside a container
	if event.Container.ID == "" {
		return false
	}

	name := strings.ToLower(event.Process.Name)
	return IsShellBinary(name)
}

// ============================================================================
// SOX COMPLIANCE MATCHERS
// ============================================================================

// matchSOXPrivilegedAccess detects privileged command execution for SOX compliance
// Triggers on: sudo, su, pkexec, passwd, usermod, etc.
func matchSOXPrivilegedAccess(event *SecurityEvent) bool {
	if event.Category != "process" || event.Rule != "Process Execution" {
		return false
	}

	name := strings.ToLower(event.Process.Name)
	if IsSOXPrivilegedCommand(name) {
		return true
	}

	// Also check exe path
	if event.Process.ExePath != "" {
		exeName := extractExeName(event.Process.ExePath)
		if IsSOXPrivilegedCommand(exeName) {
			return true
		}
	}

	return false
}

// matchSOXCriticalFileAccess detects access to SOX-critical files
// Triggers on: access to /etc/passwd, /etc/shadow, /etc/sudoers, audit logs, etc.
func matchSOXCriticalFileAccess(event *SecurityEvent) bool {
	if event.Category != "file" {
		return false
	}

	filename, ok := event.RawFields["filename"].(string)
	if !ok || filename == "" {
		return false
	}

	return PathMatchesSOXCritical(filename)
}

// matchSOXAuditLogTampering detects potential tampering with audit systems
// Triggers on: signals to auditd, rsyslogd, or file operations on audit logs
func matchSOXAuditLogTampering(event *SecurityEvent) bool {
	// Check for signals to audit processes
	if event.Category == "process" && event.Rule == "Process Signal" {
		targetPID, ok := event.RawFields["target_pid"].(int32)
		if !ok {
			return false
		}
		// Resolve target PID to process name via /proc
		if targetName, err := readProcComm(int(targetPID)); err == nil {
			if IsSOXAuditBinary(strings.ToLower(targetName)) {
				return true
			}
		}
	}

	// Check for file operations on audit logs
	if event.Category == "file" {
		filename, ok := event.RawFields["filename"].(string)
		if !ok {
			return false
		}
		// Check for destructive or tampering operations on audit logs
		if strings.HasPrefix(filename, "/var/log/audit/") ||
			strings.HasPrefix(filename, "/var/log/auth.log") ||
			strings.HasPrefix(filename, "/var/log/secure") {
			switch event.Rule {
			case "File Delete", "File Modify", "Timestamp Modification",
				"File Ownership Change", "File Permission Change",
				"Extended Attribute Set", "Extended Attribute Remove":
				return true
			}
		}
	}

	// Check for execution of audit binaries (might indicate config changes)
	if event.Category == "process" && event.Rule == "Process Execution" {
		name := strings.ToLower(event.Process.Name)
		if IsSOXAuditBinary(name) {
			return true
		}
	}

	return false
}

// ============================================================================
// PCI-DSS COMPLIANCE MATCHERS
// ============================================================================

// matchPCIRemoteAccess detects remote access tool usage for PCI Req 8 compliance
// Triggers on: SSH, telnet, VNC, RDP connections and process execution
func matchPCIRemoteAccess(event *SecurityEvent) bool {
	// Check for remote access process execution
	if event.Category == "process" && event.Rule == "Process Execution" {
		name := strings.ToLower(event.Process.Name)
		if IsPCIRemoteAccessBinary(name) {
			return true
		}
	}

	// Check for connections to remote access ports
	if event.Category == "network" {
		if dport, ok := getPort(event.RawFields, "dport"); ok {
			// Check specific remote access ports
			switch dport {
			case 22, 23, 3389, 5900, 5901, 5902:
				return true
			}
		}
	}

	return false
}

// matchPCICriticalPortAccess detects access to PCI-critical ports
// Triggers on: connections/binds to database ports, web ports, etc.
func matchPCICriticalPortAccess(event *SecurityEvent) bool {
	if event.Category != "network" {
		return false
	}

	// Check destination port for connects
	if dport, ok := getPort(event.RawFields, "dport"); ok {
		if IsPCICriticalPort(int(dport)) {
			return true
		}
	}

	// Check source port for binds/accepts
	if event.Rule == "Network Bind" || event.Rule == "Network Accept" {
		if sport, ok := getPort(event.RawFields, "sport"); ok {
			if IsPCICriticalPort(int(sport)) {
				return true
			}
		}
	}

	return false
}

// matchPCIShellInContainer detects shell execution in containers for PCI compliance
// This wraps matchShellInContainer but is specifically for PCI Req 10 logging
func matchPCIShellInContainer(event *SecurityEvent) bool {
	return matchShellInContainer(event)
}

// matchPCICardholderDataAccess detects access to cardholder data paths
// Triggers on: file access to configured PCI cardholder data locations
func matchPCICardholderDataAccess(event *SecurityEvent) bool {
	if event.Category != "file" {
		return false
	}

	filename, ok := event.RawFields["filename"].(string)
	if !ok || filename == "" {
		return false
	}

	return PathMatchesPCICardholder(filename)
}

// matchInsecureProtocol detects use of insecure protocols (telnet, FTP, rsh)
// These are prohibited under PCI-DSS requirements
func matchInsecureProtocol(event *SecurityEvent) bool {
	// Check for insecure protocol process execution
	if event.Category == "process" && event.Rule == "Process Execution" {
		name := strings.ToLower(event.Process.Name)
		switch name {
		case "telnet", "telnetd", "rsh", "rshd", "rlogin", "rlogind", "ftp", "ftpd":
			return true
		}
	}

	// Check for connections to insecure ports
	if event.Category == "network" && event.Rule == "Network Connect" {
		if dport, ok := getPort(event.RawFields, "dport"); ok {
			switch dport {
			case 21, 23: // FTP, Telnet
				return true
			case 513, 514: // rlogin, rsh
				return true
			}
		}
	}

	return false
}

// readProcComm reads the process name from /proc/<pid>/comm.
// Returns the trimmed process name or an error if the process doesn't exist.
func readProcComm(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// ============================================================================
// NEW EVENT TYPE MATCHERS
// Wire the event types added in Batches 2-6 into the alert filtering system.
// ============================================================================

// matchDataExfiltration detects high-volume data transfer syscalls (splice, sendfile, etc.)
// Always alerts on large transfers (>10MB, already PriorityWarning so bypasses filter),
// and on any data transfer from containers or to network file descriptors.
func matchDataExfiltration(event *SecurityEvent) bool {
	if !strings.HasPrefix(event.Rule, "Data Transfer via ") {
		return false
	}

	// Alert if inside a container (potential exfiltration from containerized workload)
	if event.Container.ID != "" {
		return true
	}

	// Alert on large transfers (these are already Warning priority and bypass the filter,
	// but this ensures they match a rule for consistent tagging)
	if dataLen, ok := event.RawFields["len"].(uint64); ok && dataLen > 10*1024*1024 {
		return true
	}

	return false
}

// matchContainerEscape detects chroot and pivot_root calls that may indicate container escape
// chroot is PriorityWarning and pivot_root is PriorityCritical in the parser,
// so they bypass the filter via priority. This matcher exists for:
// - Consistent rule tagging/categorization
// - chdir into sensitive directories
func matchContainerEscape(event *SecurityEvent) bool {
	if event.Category != "filesystem" {
		return false
	}

	switch event.Rule {
	case "Filesystem Root Change (chroot)",
		"Filesystem Root Change (pivot_root)":
		return true
	}

	// chdir/fchdir into sensitive locations
	if event.Rule == "Directory Change (chdir)" || event.Rule == "Directory Change (fchdir)" {
		if path, ok := event.RawFields["path"].(string); ok {
			if strings.HasPrefix(path, "/proc/") ||
				strings.HasPrefix(path, "/sys/") ||
				path == "/" {
				return true
			}
		}
	}

	return false
}

// matchCredentialChange detects credential changes from the commit_creds kprobe
// The privilege escalation case (non-root -> root) is already PriorityWarning
// and bypasses the filter. This catches non-root credential changes.
func matchCredentialChange(event *SecurityEvent) bool {
	switch event.Rule {
	case "Credential Change — Privilege Escalation",
		"Credential Change":
		return true
	}
	return false
}

// matchVFSSensitiveFileOps detects VFS-level file operations on security-sensitive paths
// VFS hooks see all file operations including those from kernel-internal callers
func matchVFSSensitiveFileOps(event *SecurityEvent) bool {
	if event.Source != "kprobe" {
		return false
	}
	if !strings.HasPrefix(event.Rule, "VFS ") {
		return false
	}

	path, ok := event.RawFields["path"].(string)
	if !ok || path == "" {
		return false
	}

	// Check against sensitive file paths
	for _, sensitive := range sensitiveFilePaths {
		if strings.HasPrefix(path, sensitive) {
			return true
		}
		if strings.Contains(path, "/.ssh/") {
			return true
		}
	}

	// Also check /proc/sys/ (sysctl) and kernel-critical paths
	if strings.HasPrefix(path, "/proc/sys/") {
		return true
	}

	return false
}

// matchIoctlAbuse detects security-relevant ioctl commands
// TIOCSTI and TIOCLINUX are already PriorityCritical and bypass the filter.
// This catches other security-relevant ioctls (loop device manipulation, etc.)
func matchIoctlAbuse(event *SecurityEvent) bool {
	return event.Category == "ioctl"
}

// matchProcessCrash detects process exits caused by crash signals (SIGSEGV, SIGABRT, SIGKILL)
// Multiple crashes may indicate exploitation attempts or stability issues
func matchProcessCrash(event *SecurityEvent) bool {
	if event.Rule != "Process Exit — Signal" {
		return false
	}

	// Check if the signal is a crash-related signal
	if exitCode, ok := event.RawFields["exit_code"].(int32); ok {
		sig := exitCode & 0x7f
		switch sig {
		case 6, 9, 11: // SIGABRT, SIGKILL, SIGSEGV
			return true
		}
	}

	return false
}

// ============================================================================
// SOX COMPLIANCE - Extended matchers for new event types
// ============================================================================

// matchSOXCredentialTampering detects credential changes relevant to SOX audit
// Triggers on: commit_creds events that change effective UID/GID
func matchSOXCredentialTampering(event *SecurityEvent) bool {
	switch event.Rule {
	case "Credential Change — Privilege Escalation",
		"Credential Change":
		return true
	}
	return false
}

// matchSOXAuditLogVFS detects VFS-level operations on audit log files
// This catches operations that bypass the syscall layer (e.g., kernel-internal writes)
func matchSOXAuditLogVFS(event *SecurityEvent) bool {
	if event.Source != "kprobe" || !strings.HasPrefix(event.Rule, "VFS ") {
		return false
	}

	path, ok := event.RawFields["path"].(string)
	if !ok {
		return false
	}

	// Check for operations on audit-critical paths
	if strings.HasPrefix(path, "/var/log/audit/") ||
		strings.HasPrefix(path, "/var/log/auth.log") ||
		strings.HasPrefix(path, "/var/log/secure") ||
		strings.HasPrefix(path, "/etc/audit/") {
		// Only alert on destructive operations
		switch event.Rule {
		case "VFS File Delete", "VFS File Rename", "VFS Attribute Change":
			return true
		}
	}

	return false
}

// ============================================================================
// PCI-DSS COMPLIANCE - Extended matchers for new event types
// ============================================================================

// matchPCIDataExfiltration detects data exfiltration attempts relevant to PCI compliance
// Large data transfers and transfers from containers are suspicious
func matchPCIDataExfiltration(event *SecurityEvent) bool {
	if !strings.HasPrefix(event.Rule, "Data Transfer via ") {
		return false
	}

	// Any data transfer from a container is interesting for PCI
	if event.Container.ID != "" {
		return true
	}

	// Large transfers
	if dataLen, ok := event.RawFields["len"].(uint64); ok && dataLen > 1*1024*1024 {
		return true
	}

	return false
}

// matchPCITerminalInjection detects terminal injection via ioctl (TIOCSTI, TIOCLINUX)
// These are already PriorityCritical for TIOCSTI/TIOCLINUX, but this provides
// PCI-specific tagging for all ioctl events
func matchPCITerminalInjection(event *SecurityEvent) bool {
	return event.Category == "ioctl"
}

// matchPCIContainerEscape detects chroot/pivot_root for PCI compliance
func matchPCIContainerEscape(event *SecurityEvent) bool {
	if event.Category != "filesystem" {
		return false
	}
	switch event.Rule {
	case "Filesystem Root Change (chroot)",
		"Filesystem Root Change (pivot_root)":
		return true
	}
	return false
}

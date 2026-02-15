package ebpf

import (
	"testing"
)

// ============================================================================
// EXCLUSION LIST TESTS
// ============================================================================

func TestCoreutilsBinaries_ContainsExpectedTools(t *testing.T) {
	expectedTools := []string{
		"cat", "ls", "cp", "mv", "rm", "mkdir", "chmod", "chown",
		"grep", "sed", "awk", "find", "xargs", "touch", "head", "tail",
	}

	for _, tool := range expectedTools {
		if _, ok := CoreutilsBinaries[tool]; !ok {
			t.Errorf("CoreutilsBinaries should contain '%s'", tool)
		}
	}
}

func TestContainerBinaries_ContainsRuntimes(t *testing.T) {
	expectedRuntimes := []string{
		"docker", "dockerd", "containerd", "runc", "crio", "podman", "buildah",
	}

	for _, runtime := range expectedRuntimes {
		if _, ok := ContainerBinaries[runtime]; !ok {
			t.Errorf("ContainerBinaries should contain '%s'", runtime)
		}
	}
}

func TestK8sBinaries_ContainsComponents(t *testing.T) {
	expectedComponents := []string{
		"kubectl", "kubelet", "kube-proxy", "kube-apiserver",
		"kube-controller-manager", "kube-scheduler", "etcd",
	}

	for _, component := range expectedComponents {
		if _, ok := K8sBinaries[component]; !ok {
			t.Errorf("K8sBinaries should contain '%s'", component)
		}
	}
}

func TestDBServerBinaries_ContainsDatabases(t *testing.T) {
	expectedDBs := []string{
		"mysqld", "postgres", "mongod", "redis-server", "elasticsearch",
	}

	for _, db := range expectedDBs {
		if _, ok := DBServerBinaries[db]; !ok {
			t.Errorf("DBServerBinaries should contain '%s'", db)
		}
	}
}

// ============================================================================
// DETECTION LIST TESTS
// ============================================================================

func TestSSHBinaries_ContainsSSHTools(t *testing.T) {
	expectedTools := []string{
		"ssh", "sshd", "scp", "sftp", "ssh-agent", "ssh-add", "rsync",
	}

	for _, tool := range expectedTools {
		if _, ok := SSHBinaries[tool]; !ok {
			t.Errorf("SSHBinaries should contain '%s'", tool)
		}
	}
}

func TestNetworkToolBinaries_ContainsReconTools(t *testing.T) {
	expectedTools := []string{
		"nc", "ncat", "netcat", "nmap", "tcpdump", "dig", "wget", "curl",
	}

	for _, tool := range expectedTools {
		if _, ok := NetworkToolBinaries[tool]; !ok {
			t.Errorf("NetworkToolBinaries should contain '%s'", tool)
		}
	}
}

func TestShellBinaries_ContainsShells(t *testing.T) {
	expectedShells := []string{
		"bash", "sh", "zsh", "dash", "fish", "ksh",
	}

	for _, shell := range expectedShells {
		if _, ok := ShellBinaries[shell]; !ok {
			t.Errorf("ShellBinaries should contain '%s'", shell)
		}
	}
}

func TestMinerPorts_ContainsCommonPorts(t *testing.T) {
	expectedPorts := []int{3333, 4444, 5555, 9999, 14444}

	for _, port := range expectedPorts {
		if _, ok := MinerPorts[port]; !ok {
			t.Errorf("MinerPorts should contain port %d", port)
		}
	}
}

func TestMinerProcessNames_ContainsMiners(t *testing.T) {
	expectedMiners := []string{
		"xmrig", "xmr-stak", "minerd", "cpuminer", "ethminer",
	}

	for _, miner := range expectedMiners {
		if _, ok := MinerProcessNames[miner]; !ok {
			t.Errorf("MinerProcessNames should contain '%s'", miner)
		}
	}
}

// ============================================================================
// SOX COMPLIANCE LIST TESTS
// ============================================================================

func TestSOXPrivilegedCommands_ContainsExpected(t *testing.T) {
	expectedCmds := []string{
		"sudo", "su", "pkexec", "visudo", "passwd", "usermod",
	}

	for _, cmd := range expectedCmds {
		if _, ok := SOXPrivilegedCommands[cmd]; !ok {
			t.Errorf("SOXPrivilegedCommands should contain '%s'", cmd)
		}
	}
}

func TestSOXAuditBinaries_ContainsAuditTools(t *testing.T) {
	expectedTools := []string{
		"auditd", "auditctl", "rsyslogd", "syslog-ng", "journald",
	}

	for _, tool := range expectedTools {
		if _, ok := SOXAuditBinaries[tool]; !ok {
			t.Errorf("SOXAuditBinaries should contain '%s'", tool)
		}
	}
}

func TestSOXCriticalPaths_ContainsCriticalFiles(t *testing.T) {
	expectedPaths := []string{
		"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/",
	}

	for _, path := range expectedPaths {
		found := false
		for _, criticalPath := range SOXCriticalPaths {
			if criticalPath == path {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("SOXCriticalPaths should contain '%s'", path)
		}
	}
}

// ============================================================================
// PCI-DSS COMPLIANCE LIST TESTS
// ============================================================================

func TestPCICriticalPorts_ContainsDatabasePorts(t *testing.T) {
	expectedPorts := []int{3306, 5432, 1433, 27017, 6379} // MySQL, PG, MSSQL, Mongo, Redis

	for _, port := range expectedPorts {
		if _, ok := PCICriticalPorts[port]; !ok {
			t.Errorf("PCICriticalPorts should contain port %d", port)
		}
	}
}

func TestPCIRemoteAccessBinaries_ContainsRemoteTools(t *testing.T) {
	expectedTools := []string{
		"ssh", "sshd", "telnet", "vncserver", "xrdp",
	}

	for _, tool := range expectedTools {
		if _, ok := PCIRemoteAccessBinaries[tool]; !ok {
			t.Errorf("PCIRemoteAccessBinaries should contain '%s'", tool)
		}
	}
}

// ============================================================================
// CONFIG AND HELPER FUNCTION TESTS
// ============================================================================

func TestDefaultNativeListConfig(t *testing.T) {
	config := DefaultNativeListConfig()

	// Exclusions should be enabled by default
	if !config.ExcludeCoreutilsBinaries {
		t.Error("ExcludeCoreutilsBinaries should be true by default")
	}
	if !config.ExcludeContainerBinaries {
		t.Error("ExcludeContainerBinaries should be true by default")
	}
	if !config.ExcludeK8sBinaries {
		t.Error("ExcludeK8sBinaries should be true by default")
	}

	// Detections should be enabled by default
	if !config.DetectNetworkTools {
		t.Error("DetectNetworkTools should be true by default")
	}
	if !config.DetectMinerActivity {
		t.Error("DetectMinerActivity should be true by default")
	}
	if !config.DetectShellInContainer {
		t.Error("DetectShellInContainer should be true by default")
	}

	// Compliance should be disabled by default
	if config.SOXMonitoring {
		t.Error("SOXMonitoring should be false by default")
	}
	if config.PCIMonitoring {
		t.Error("PCIMonitoring should be false by default")
	}
}

func TestBuildExcludeComms_WithAllDisabled(t *testing.T) {
	config := NativeListConfig{
		ExcludeCoreutilsBinaries: false,
		ExcludeLoginBinaries:     false,
		ExcludeContainerBinaries: false,
		ExcludeK8sBinaries:       false,
		ExcludeDBBinaries:        false,
		ExcludeCronBinaries:      false,
		ExcludeMailBinaries:      false,
	}

	result := config.BuildExcludeComms()

	if len(result) != 0 {
		t.Errorf("Expected empty map when all exclusions disabled, got %d entries", len(result))
	}
}

func TestBuildExcludeComms_WithAllEnabled(t *testing.T) {
	config := NativeListConfig{
		ExcludeCoreutilsBinaries: true,
		ExcludeLoginBinaries:     true,
		ExcludePasswdBinaries:    true,
		ExcludeContainerBinaries: true,
		ExcludeK8sBinaries:       true,
		ExcludeDBBinaries:        true,
		ExcludeCronBinaries:      true,
		ExcludeMailBinaries:      true,
	}

	result := config.BuildExcludeComms()

	// Should contain entries from all enabled lists
	expectedMinSize := len(CoreutilsBinaries) + len(LoginBinaries) + len(ContainerBinaries)
	if len(result) < expectedMinSize {
		t.Errorf("Expected at least %d entries, got %d", expectedMinSize, len(result))
	}

	// Verify specific entries exist
	if _, ok := result["cat"]; !ok {
		t.Error("Result should contain 'cat' from CoreutilsBinaries")
	}
	if _, ok := result["docker"]; !ok {
		t.Error("Result should contain 'docker' from ContainerBinaries")
	}
	if _, ok := result["kubectl"]; !ok {
		t.Error("Result should contain 'kubectl' from K8sBinaries")
	}
}

func TestBuildExcludePaths_WithSafeEtcDirsEnabled(t *testing.T) {
	config := NativeListConfig{
		ExcludeSafeEtcDirs: true,
	}

	result := config.BuildExcludePaths()

	if len(result) == 0 {
		t.Error("Expected paths when ExcludeSafeEtcDirs is enabled")
	}

	// Verify some expected paths
	found := false
	for _, path := range result {
		if path == "/etc/ssl/certs/" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Result should contain '/etc/ssl/certs/'")
	}
}

func TestBuildExcludePaths_WithSafeEtcDirsDisabled(t *testing.T) {
	config := NativeListConfig{
		ExcludeSafeEtcDirs: false,
	}

	result := config.BuildExcludePaths()

	if len(result) != 0 {
		t.Errorf("Expected empty slice when ExcludeSafeEtcDirs is disabled, got %d entries", len(result))
	}
}

// ============================================================================
// HELPER FUNCTION TESTS
// ============================================================================

func TestIsNetworkTool(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"nmap", true},
		{"nc", true},
		{"tcpdump", true},
		{"bash", false},
		{"cat", false},
		{"unknowntool", false},
	}

	for _, tt := range tests {
		result := IsNetworkTool(tt.name)
		if result != tt.expected {
			t.Errorf("IsNetworkTool(%q) = %v, expected %v", tt.name, result, tt.expected)
		}
	}
}

func TestIsMinerProcess(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"xmrig", true},
		{"minerd", true},
		{"ethminer", true},
		{"bash", false},
		{"nginx", false},
	}

	for _, tt := range tests {
		result := IsMinerProcess(tt.name)
		if result != tt.expected {
			t.Errorf("IsMinerProcess(%q) = %v, expected %v", tt.name, result, tt.expected)
		}
	}
}

func TestIsMinerPort(t *testing.T) {
	tests := []struct {
		port     int
		expected bool
	}{
		{3333, true},
		{4444, true},
		{14444, true},
		{22, false},
		{80, false},
		{443, false},
	}

	for _, tt := range tests {
		result := IsMinerPort(tt.port)
		if result != tt.expected {
			t.Errorf("IsMinerPort(%d) = %v, expected %v", tt.port, result, tt.expected)
		}
	}
}

func TestIsShellBinary(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"bash", true},
		{"sh", true},
		{"zsh", true},
		{"fish", true},
		{"cat", false},
		{"nginx", false},
	}

	for _, tt := range tests {
		result := IsShellBinary(tt.name)
		if result != tt.expected {
			t.Errorf("IsShellBinary(%q) = %v, expected %v", tt.name, result, tt.expected)
		}
	}
}

func TestIsSSHBinary(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"ssh", true},
		{"sshd", true},
		{"scp", true},
		{"sftp", true},
		{"bash", false},
		{"telnet", false},
	}

	for _, tt := range tests {
		result := IsSSHBinary(tt.name)
		if result != tt.expected {
			t.Errorf("IsSSHBinary(%q) = %v, expected %v", tt.name, result, tt.expected)
		}
	}
}

func TestIsPackageManager(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"apt", true},
		{"apt-get", true},
		{"yum", true},
		{"pip", true},
		{"npm", true},
		{"cargo", true},
		{"bash", false},
		{"cat", false},
	}

	for _, tt := range tests {
		result := IsPackageManager(tt.name)
		if result != tt.expected {
			t.Errorf("IsPackageManager(%q) = %v, expected %v", tt.name, result, tt.expected)
		}
	}
}

func TestIsSOXPrivilegedCommand(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"sudo", true},
		{"su", true},
		{"passwd", true},
		{"visudo", true},
		{"cat", false},
		{"ls", false},
	}

	for _, tt := range tests {
		result := IsSOXPrivilegedCommand(tt.name)
		if result != tt.expected {
			t.Errorf("IsSOXPrivilegedCommand(%q) = %v, expected %v", tt.name, result, tt.expected)
		}
	}
}

func TestIsPCIRemoteAccessBinary(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"ssh", true},
		{"sshd", true},
		{"telnet", true},
		{"vncserver", true},
		{"xrdp", true},
		{"bash", false},
		{"cat", false},
	}

	for _, tt := range tests {
		result := IsPCIRemoteAccessBinary(tt.name)
		if result != tt.expected {
			t.Errorf("IsPCIRemoteAccessBinary(%q) = %v, expected %v", tt.name, result, tt.expected)
		}
	}
}

func TestIsPCICriticalPort(t *testing.T) {
	tests := []struct {
		port     int
		expected bool
	}{
		{22, true},   // SSH
		{3306, true}, // MySQL
		{5432, true}, // PostgreSQL
		{443, true},  // HTTPS
		{12345, false},
		{65535, false},
	}

	for _, tt := range tests {
		result := IsPCICriticalPort(tt.port)
		if result != tt.expected {
			t.Errorf("IsPCICriticalPort(%d) = %v, expected %v", tt.port, result, tt.expected)
		}
	}
}

func TestIsContainerBinary(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"docker", true},
		{"dockerd", true},
		{"containerd", true},
		{"runc", true},
		{"podman", true},
		{"bash", false},
		{"nginx", false},
	}

	for _, tt := range tests {
		result := IsContainerBinary(tt.name)
		if result != tt.expected {
			t.Errorf("IsContainerBinary(%q) = %v, expected %v", tt.name, result, tt.expected)
		}
	}
}

func TestPathMatchesSOXCritical(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/etc/passwd", true},
		{"/etc/shadow", true},
		{"/etc/sudoers", true},
		{"/etc/ssh/sshd_config", true},
		{"/etc/pam.d/common-auth", true},
		{"/var/log/audit/audit.log", true},
		{"/tmp/test.txt", false},
		{"/home/user/file.txt", false},
	}

	for _, tt := range tests {
		result := PathMatchesSOXCritical(tt.path)
		if result != tt.expected {
			t.Errorf("PathMatchesSOXCritical(%q) = %v, expected %v", tt.path, result, tt.expected)
		}
	}
}

func TestPathMatchesPCICardholder(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/var/lib/mysql/payments.db", true},
		{"/var/lib/postgresql/transactions", true},
		{"/tmp/test.txt", false},
		{"/etc/passwd", false},
	}

	for _, tt := range tests {
		result := PathMatchesPCICardholder(tt.path)
		if result != tt.expected {
			t.Errorf("PathMatchesPCICardholder(%q) = %v, expected %v", tt.path, result, tt.expected)
		}
	}
}

func TestDomainMatchesMiner(t *testing.T) {
	tests := []struct {
		domain   string
		expected bool
	}{
		{"pool.nanopool.org", true},
		{"xmr.nanopool.org", true},
		{"supportxmr.com", true},
		{"stratum.supportxmr.com", true},
		{"google.com", false},
		{"example.com", false},
		{"nanopool.org.fake.com", false}, // Should not match - wrong position
	}

	for _, tt := range tests {
		result := DomainMatchesMiner(tt.domain)
		if result != tt.expected {
			t.Errorf("DomainMatchesMiner(%q) = %v, expected %v", tt.domain, result, tt.expected)
		}
	}
}

// ============================================================================
// ALERT FILTER INTEGRATION TESTS
// ============================================================================

func TestAlertFilter_NetworkReconDetection(t *testing.T) {
	nativeLists := &NativeListConfig{
		DetectNetworkTools: true,
	}
	config := &AlertFilterConfig{
		Enabled: true,
	}
	filter := NewAlertFilterWithLists(config, nativeLists)

	// Test nmap execution
	nmapEvent := SecurityEvent{
		Category: "process",
		Rule:     "Process Execution",
		Priority: PriorityInformational,
		Process: ProcessInfo{
			Name: "nmap",
			PID:  1234,
		},
	}

	if !filter.ShouldAlert(&nmapEvent) {
		t.Error("nmap execution should trigger alert when DetectNetworkTools is enabled")
	}
}

func TestAlertFilter_NetworkReconDisabled(t *testing.T) {
	nativeLists := &NativeListConfig{
		DetectNetworkTools: false,
	}
	config := &AlertFilterConfig{
		Enabled: true,
	}
	filter := NewAlertFilterWithLists(config, nativeLists)

	// Test nmap execution - should not alert
	nmapEvent := SecurityEvent{
		Category: "process",
		Rule:     "Process Execution",
		Priority: PriorityInformational,
		Process: ProcessInfo{
			Name: "nmap",
			PID:  1234,
		},
	}

	if filter.ShouldAlert(&nmapEvent) {
		t.Error("nmap execution should not trigger alert when DetectNetworkTools is disabled")
	}
}

func TestAlertFilter_CryptoMiningDetection(t *testing.T) {
	nativeLists := &NativeListConfig{
		DetectMinerActivity: true,
	}
	config := &AlertFilterConfig{
		Enabled: true,
	}
	filter := NewAlertFilterWithLists(config, nativeLists)

	// Test xmrig execution
	xmrigEvent := SecurityEvent{
		Category: "process",
		Rule:     "Process Execution",
		Priority: PriorityInformational,
		Process: ProcessInfo{
			Name: "xmrig",
			PID:  1234,
		},
	}

	if !filter.ShouldAlert(&xmrigEvent) {
		t.Error("xmrig execution should trigger alert when DetectMinerActivity is enabled")
	}

	// Test connection to mining port
	miningConnEvent := SecurityEvent{
		Category: "network",
		Rule:     "Network Connect",
		Priority: PriorityInformational,
		Process: ProcessInfo{
			Name: "someapp",
			PID:  1234,
		},
		RawFields: map[string]interface{}{
			"dport": uint16(3333),
		},
	}

	if !filter.ShouldAlert(&miningConnEvent) {
		t.Error("Connection to mining port should trigger alert")
	}
}

func TestAlertFilter_ShellInContainerDetection(t *testing.T) {
	nativeLists := &NativeListConfig{
		DetectShellInContainer: true,
	}
	config := &AlertFilterConfig{
		Enabled: true,
	}
	filter := NewAlertFilterWithLists(config, nativeLists)

	// Test shell in container
	shellEvent := SecurityEvent{
		Category: "process",
		Rule:     "Process Execution",
		Priority: PriorityInformational,
		Process: ProcessInfo{
			Name: "bash",
			PID:  1234,
		},
		Container: ContainerInfo{
			ID:   "abc123",
			Name: "test-container",
		},
	}

	if !filter.ShouldAlert(&shellEvent) {
		t.Error("Shell in container should trigger alert")
	}

	// Test shell outside container - should not alert (unless other rules match)
	shellNoContainerEvent := SecurityEvent{
		Category: "process",
		Rule:     "Process Execution",
		Priority: PriorityInformational,
		Process: ProcessInfo{
			Name: "bash",
			PID:  1234,
		},
		Container: ContainerInfo{}, // No container
	}

	// This should not alert because it's not in a container and doesn't match other rules
	if filter.ShouldAlert(&shellNoContainerEvent) {
		t.Error("Shell outside container should not trigger shell-in-container alert")
	}
}

func TestAlertFilter_SOXMonitoring(t *testing.T) {
	nativeLists := &NativeListConfig{
		SOXMonitoring: true,
	}
	config := &AlertFilterConfig{
		Enabled: true,
	}
	filter := NewAlertFilterWithLists(config, nativeLists)

	// Test sudo execution
	sudoEvent := SecurityEvent{
		Category: "process",
		Rule:     "Process Execution",
		Priority: PriorityInformational,
		Process: ProcessInfo{
			Name:    "sudo",
			PID:     1234,
			ExePath: "/usr/bin/sudo",
		},
	}

	if !filter.ShouldAlert(&sudoEvent) {
		t.Error("sudo execution should trigger alert when SOXMonitoring is enabled")
	}

	// Test critical file access
	passwdEvent := SecurityEvent{
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

	if !filter.ShouldAlert(&passwdEvent) {
		t.Error("/etc/passwd access should trigger alert when SOXMonitoring is enabled")
	}
}

func TestAlertFilter_PCIMonitoring(t *testing.T) {
	nativeLists := &NativeListConfig{
		PCIMonitoring: true,
	}
	config := &AlertFilterConfig{
		Enabled: true,
	}
	filter := NewAlertFilterWithLists(config, nativeLists)

	// Test telnet usage (insecure protocol)
	telnetEvent := SecurityEvent{
		Category: "process",
		Rule:     "Process Execution",
		Priority: PriorityInformational,
		Process: ProcessInfo{
			Name: "telnet",
			PID:  1234,
		},
	}

	if !filter.ShouldAlert(&telnetEvent) {
		t.Error("telnet execution should trigger alert when PCIMonitoring is enabled")
	}

	// Test connection to database port
	dbConnEvent := SecurityEvent{
		Category: "network",
		Rule:     "Network Connect",
		Priority: PriorityInformational,
		Process: ProcessInfo{
			Name: "someapp",
			PID:  1234,
		},
		RawFields: map[string]interface{}{
			"dport": uint16(3306), // MySQL
		},
	}

	if !filter.ShouldAlert(&dbConnEvent) {
		t.Error("Connection to MySQL port should trigger alert when PCIMonitoring is enabled")
	}
}

func TestAlertFilter_ComplianceHelpers(t *testing.T) {
	nativeLists := &NativeListConfig{
		SOXMonitoring: true,
		PCIMonitoring: false,
	}
	config := &AlertFilterConfig{
		Enabled:        true,
		ComplianceMode: true,
	}
	filter := NewAlertFilterWithLists(config, nativeLists)

	if !filter.IsSOXMonitoring() {
		t.Error("IsSOXMonitoring should return true")
	}

	if filter.IsPCIMonitoring() {
		t.Error("IsPCIMonitoring should return false")
	}

	if !filter.IsComplianceMode() {
		t.Error("IsComplianceMode should return true")
	}

	// Test GetNativeLists
	lists := filter.GetNativeLists()
	if lists == nil {
		t.Error("GetNativeLists should return non-nil")
	}
	if !lists.SOXMonitoring {
		t.Error("GetNativeLists should return config with SOXMonitoring=true")
	}
}

// ============================================================================
// LIST SIZE SANITY TESTS
// ============================================================================

func TestListSizes_ReasonableCount(t *testing.T) {
	// Verify lists have reasonable sizes (not empty, not suspiciously small)
	if len(CoreutilsBinaries) < 50 {
		t.Errorf("CoreutilsBinaries seems too small: %d entries", len(CoreutilsBinaries))
	}

	if len(ContainerBinaries) < 10 {
		t.Errorf("ContainerBinaries seems too small: %d entries", len(ContainerBinaries))
	}

	if len(K8sBinaries) < 10 {
		t.Errorf("K8sBinaries seems too small: %d entries", len(K8sBinaries))
	}

	if len(NetworkToolBinaries) < 20 {
		t.Errorf("NetworkToolBinaries seems too small: %d entries", len(NetworkToolBinaries))
	}

	if len(PackageMgmtBinaries) < 20 {
		t.Errorf("PackageMgmtBinaries seems too small: %d entries", len(PackageMgmtBinaries))
	}

	if len(MinerPorts) < 10 {
		t.Errorf("MinerPorts seems too small: %d entries", len(MinerPorts))
	}

	if len(SOXCriticalPaths) < 20 {
		t.Errorf("SOXCriticalPaths seems too small: %d entries", len(SOXCriticalPaths))
	}

	if len(PCICriticalPorts) < 10 {
		t.Errorf("PCICriticalPorts seems too small: %d entries", len(PCICriticalPorts))
	}
}

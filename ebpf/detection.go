package ebpf

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// AgentPaths defines the common paths for detecting eBPF agents
type AgentPaths struct {
	BinaryPaths   []string
	ServiceNames  []string
	ConfigPaths   []string
	RulesDirs     []string
}

// KnownAgentPaths contains the detection paths for known agents
// Note: AgentTypeNative is not in this map as it's built-in and uses kernel detection
var KnownAgentPaths = map[AgentType]AgentPaths{
	AgentTypeFalco: {
		BinaryPaths: []string{
			"/usr/bin/falco",
			"/usr/local/bin/falco",
		},
		ServiceNames: []string{
			"falco-modern-bpf.service",
			"falco.service",
			"falco-bpf.service",
		},
		ConfigPaths: []string{
			"/etc/falco/falco.yaml",
			"/etc/falco/config.d/",
		},
		RulesDirs: []string{
			"/etc/falco/rules.d/",
			"/etc/falco/rules.alertpriority/",
		},
	},
	AgentTypeTetragon: {
		BinaryPaths: []string{
			"/usr/bin/tetragon",
			"/usr/local/bin/tetragon",
			"/opt/tetragon/usr/bin/tetragon",
		},
		ServiceNames: []string{
			"tetragon.service",
		},
		ConfigPaths: []string{
			"/etc/tetragon/tetragon.yaml",
			"/etc/tetragon/tetragon.conf.d/",
		},
		RulesDirs: []string{
			"/etc/tetragon/tetragon.tp.d/",
		},
	},
	AgentTypePixie: {
		BinaryPaths: []string{
			"/usr/bin/vizier",
			"/usr/local/bin/vizier",
			"/opt/pixie/bin/vizier-pem",
		},
		ServiceNames: []string{
			"pixie-vizier.service",
			"vizier-pem.service",
		},
		ConfigPaths: []string{
			"/etc/pixie/config.yaml",
			"/opt/pixie/config/",
		},
		RulesDirs: []string{
			"/etc/pixie/scripts/",
		},
	},
}

// DetectionResult contains the results of agent detection
type DetectionResult struct {
	AgentType    AgentType
	Installed    bool
	BinaryPath   string
	ServiceName  string
	ConfigPath   string
	RulesDir     string
	Version      string
}

// DetectAgent checks if a specific agent type is installed
func DetectAgent(agentType AgentType) DetectionResult {
	result := DetectionResult{
		AgentType: agentType,
		Installed: false,
	}

	// Native agent is built-in - detection is handled by kernel feature checks
	// Return a special result indicating it's available (actual feature check done at runtime)
	if agentType == AgentTypeNative {
		result.Installed = checkNativeSupport()
		result.BinaryPath = "embedded"
		result.ServiceName = ""
		result.ConfigPath = "/etc/apagent/native.yaml"
		result.RulesDir = "/etc/apagent/rules.d"
		result.Version = "1.0.0"
		return result
	}

	paths, exists := KnownAgentPaths[agentType]
	if !exists {
		return result
	}

	// Check for binary
	for _, binaryPath := range paths.BinaryPaths {
		if fileExists(binaryPath) {
			result.BinaryPath = binaryPath
			result.Installed = true
			break
		}
	}

	if !result.Installed {
		return result
	}

	// Find config path
	for _, configPath := range paths.ConfigPaths {
		if fileExists(configPath) {
			result.ConfigPath = configPath
			break
		}
	}

	// Find rules directory
	for _, rulesDir := range paths.RulesDirs {
		if dirExists(rulesDir) {
			result.RulesDir = rulesDir
			break
		}
	}

	// Find service name (first available)
	for _, serviceName := range paths.ServiceNames {
		if serviceExists(serviceName) {
			result.ServiceName = serviceName
			break
		}
	}
	// If no service found, use the first one as default
	if result.ServiceName == "" && len(paths.ServiceNames) > 0 {
		result.ServiceName = paths.ServiceNames[0]
	}

	// Try to get version
	result.Version = getAgentVersion(agentType, result.BinaryPath)

	return result
}

// DetectAllAgents checks all known agent types and returns detection results
func DetectAllAgents() []DetectionResult {
	results := make([]DetectionResult, 0, len(KnownAgentPaths)+1)

	// Check path-based agents
	for agentType := range KnownAgentPaths {
		result := DetectAgent(agentType)
		results = append(results, result)
	}

	// Also check native agent (which uses kernel detection instead of paths)
	nativeResult := DetectAgent(AgentTypeNative)
	results = append(results, nativeResult)

	return results
}

// DetectInstalledAgents returns detection results only for installed agents
func DetectInstalledAgents() []DetectionResult {
	allResults := DetectAllAgents()
	installed := make([]DetectionResult, 0)
	for _, result := range allResults {
		if result.Installed {
			installed = append(installed, result)
		}
	}
	return installed
}

// fileExists checks if a file exists and is not a directory
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil && !info.IsDir()
}

// dirExists checks if a directory exists
func dirExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil && info.IsDir()
}

// serviceExists checks if a systemd service exists
func serviceExists(serviceName string) bool {
	cmd := exec.Command("systemctl", "cat", serviceName)
	err := cmd.Run()
	return err == nil
}

// getAgentVersion attempts to get the version of an agent
func getAgentVersion(agentType AgentType, binaryPath string) string {
	if binaryPath == "" {
		return ""
	}

	var cmd *exec.Cmd
	switch agentType {
	case AgentTypeFalco:
		cmd = exec.Command(binaryPath, "--version")
	case AgentTypeTetragon:
		cmd = exec.Command(binaryPath, "version")
	case AgentTypePixie:
		cmd = exec.Command(binaryPath, "--version")
	default:
		return ""
	}

	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	// Parse version from output (typically first line)
	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 {
		return parseVersionString(lines[0])
	}
	return ""
}

// parseVersionString extracts version number from a version string
func parseVersionString(s string) string {
	// Common patterns: "Falco 0.35.1", "Tetragon version 1.0.0", etc.
	s = strings.TrimSpace(s)
	parts := strings.Fields(s)

	for _, part := range parts {
		// Look for semver-like patterns
		if len(part) > 0 && (part[0] >= '0' && part[0] <= '9') {
			return part
		}
		// Check for "v" prefix followed by a digit (e.g., "v1.2.3")
		if strings.HasPrefix(part, "v") && len(part) > 1 && (part[1] >= '0' && part[1] <= '9') {
			return part[1:]
		}
	}

	return s
}

// GetAgentBinaryPath returns the first found binary path for an agent type
func GetAgentBinaryPath(agentType AgentType) string {
	paths, exists := KnownAgentPaths[agentType]
	if !exists {
		return ""
	}

	for _, binaryPath := range paths.BinaryPaths {
		if fileExists(binaryPath) {
			return binaryPath
		}
	}
	return ""
}

// GetAgentServiceName returns the first found service name for an agent type
func GetAgentServiceName(agentType AgentType) string {
	paths, exists := KnownAgentPaths[agentType]
	if !exists {
		return ""
	}

	for _, serviceName := range paths.ServiceNames {
		if serviceExists(serviceName) {
			return serviceName
		}
	}
	// Return default if none found
	if len(paths.ServiceNames) > 0 {
		return paths.ServiceNames[0]
	}
	return ""
}

// GetAgentConfigPath returns the first found config path for an agent type
func GetAgentConfigPath(agentType AgentType) string {
	paths, exists := KnownAgentPaths[agentType]
	if !exists {
		return ""
	}

	for _, configPath := range paths.ConfigPaths {
		if fileExists(configPath) || dirExists(configPath) {
			return configPath
		}
	}
	// Return default if none found
	if len(paths.ConfigPaths) > 0 {
		return paths.ConfigPaths[0]
	}
	return ""
}

// GetAgentRulesDir returns the first found rules directory for an agent type
func GetAgentRulesDir(agentType AgentType) string {
	paths, exists := KnownAgentPaths[agentType]
	if !exists {
		return ""
	}

	for _, rulesDir := range paths.RulesDirs {
		if dirExists(rulesDir) {
			return rulesDir
		}
	}
	// Return default if none found
	if len(paths.RulesDirs) > 0 {
		return paths.RulesDirs[0]
	}
	return ""
}

// checkNativeSupport performs a basic check for native eBPF support
// This is a preliminary check; detailed feature checks are done when loading BPF programs
func checkNativeSupport() bool {
	// Check if kernel version is 5.8+ (required for ring buffers)
	// Parse /proc/version or use uname
	output, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return false
	}

	version := strings.TrimSpace(string(output))
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return false
	}

	// Parse major version
	major := 0
	minor := 0
	fmt.Sscanf(parts[0], "%d", &major)
	fmt.Sscanf(parts[1], "%d", &minor)

	// Require kernel 5.8+ for ring buffer support
	if major > 5 || (major == 5 && minor >= 8) {
		return true
	}

	return false
}

// GetNativeKernelVersion returns the running kernel version
func GetNativeKernelVersion() string {
	output, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

package ebpf

import (
	"testing"
)

func TestKnownAgentPaths(t *testing.T) {
	// Verify that known agent paths are defined for all path-based agent types
	// Note: AgentTypeNative is intentionally not in KnownAgentPaths as it uses kernel detection
	supportedTypes := GetSupportedAgentTypes()

	for _, agentType := range supportedTypes {
		// Skip native agent - it doesn't use external binary paths
		if agentType == AgentTypeNative {
			continue
		}

		paths, exists := KnownAgentPaths[agentType]
		if !exists {
			t.Errorf("No paths defined for agent type: %s", agentType)
			continue
		}

		if len(paths.BinaryPaths) == 0 {
			t.Errorf("No binary paths defined for agent type: %s", agentType)
		}

		if len(paths.ServiceNames) == 0 {
			t.Errorf("No service names defined for agent type: %s", agentType)
		}

		if len(paths.ConfigPaths) == 0 {
			t.Errorf("No config paths defined for agent type: %s", agentType)
		}
	}
}

func TestDetectAgentUnknownType(t *testing.T) {
	result := DetectAgent(AgentType("unknown-agent"))

	if result.Installed {
		t.Error("Expected unknown agent to not be installed")
	}

	if result.BinaryPath != "" {
		t.Error("Expected empty binary path for unknown agent")
	}
}

func TestDetectAllAgents(t *testing.T) {
	results := DetectAllAgents()

	// Should have results for all known agent types plus native agent
	expectedCount := len(KnownAgentPaths) + 1 // +1 for native agent
	if len(results) != expectedCount {
		t.Errorf("Expected %d detection results, got %d", expectedCount, len(results))
	}

	// Verify each result has an agent type
	for _, result := range results {
		if result.AgentType == "" {
			t.Error("Detection result has empty agent type")
		}
	}

	// Verify native agent is included in results
	foundNative := false
	for _, result := range results {
		if result.AgentType == AgentTypeNative {
			foundNative = true
			// Native agent should have "embedded" as binary path
			if result.BinaryPath != "embedded" {
				t.Errorf("Expected native agent BinaryPath to be 'embedded', got %s", result.BinaryPath)
			}
			break
		}
	}
	if !foundNative {
		t.Error("Native agent not found in DetectAllAgents results")
	}
}

func TestDetectInstalledAgents(t *testing.T) {
	results := DetectInstalledAgents()

	// All returned results should be installed
	for _, result := range results {
		if !result.Installed {
			t.Errorf("DetectInstalledAgents returned non-installed agent: %s", result.AgentType)
		}
	}
}

func TestParseVersionString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Falco 0.35.1", "0.35.1"},
		{"Tetragon version 1.0.0", "1.0.0"},
		{"v1.2.3", "1.2.3"},
		{"1.0.0", "1.0.0"},
		{"some-binary", "some-binary"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseVersionString(tt.input)
			if result != tt.expected {
				t.Errorf("parseVersionString(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestFileExists(t *testing.T) {
	// Test with a file that should exist on most systems
	if !fileExists("/etc/passwd") {
		// Skip if file doesn't exist (might be running in minimal container)
		t.Skip("/etc/passwd not found, skipping test")
	}

	// Test with a file that shouldn't exist
	if fileExists("/this/file/does/not/exist") {
		t.Error("Expected non-existent file to return false")
	}

	// Test with a directory (should return false)
	if fileExists("/tmp") {
		t.Error("Expected directory to return false for fileExists")
	}
}

func TestDirExists(t *testing.T) {
	// Test with a directory that should exist
	if !dirExists("/tmp") {
		t.Skip("/tmp not found, skipping test")
	}

	// Test with a directory that shouldn't exist
	if dirExists("/this/directory/does/not/exist") {
		t.Error("Expected non-existent directory to return false")
	}

	// Test with a file (should return false)
	if dirExists("/etc/passwd") {
		t.Error("Expected file to return false for dirExists")
	}
}

func TestGetAgentBinaryPath(t *testing.T) {
	// Test with a known agent type
	path := GetAgentBinaryPath(AgentTypeFalco)
	// Path might be empty if Falco isn't installed, that's OK
	// Just verify it doesn't panic

	// Test with unknown agent type
	path = GetAgentBinaryPath(AgentType("unknown"))
	if path != "" {
		t.Errorf("Expected empty path for unknown agent, got %s", path)
	}
}

func TestGetAgentServiceName(t *testing.T) {
	// Test with known agent types - should return non-empty even if not installed
	serviceName := GetAgentServiceName(AgentTypeFalco)
	if serviceName == "" {
		t.Error("Expected non-empty service name for Falco")
	}

	serviceName = GetAgentServiceName(AgentTypeTetragon)
	if serviceName == "" {
		t.Error("Expected non-empty service name for Tetragon")
	}

	// Test with unknown agent type
	serviceName = GetAgentServiceName(AgentType("unknown"))
	if serviceName != "" {
		t.Errorf("Expected empty service name for unknown agent, got %s", serviceName)
	}
}

func TestGetAgentConfigPath(t *testing.T) {
	// Test with known agent types
	configPath := GetAgentConfigPath(AgentTypeFalco)
	if configPath == "" {
		t.Error("Expected non-empty config path for Falco")
	}

	// Test with unknown agent type
	configPath = GetAgentConfigPath(AgentType("unknown"))
	if configPath != "" {
		t.Errorf("Expected empty config path for unknown agent, got %s", configPath)
	}
}

func TestGetAgentRulesDir(t *testing.T) {
	// Test with known agent types
	rulesDir := GetAgentRulesDir(AgentTypeFalco)
	if rulesDir == "" {
		t.Error("Expected non-empty rules dir for Falco")
	}

	// Test with unknown agent type
	rulesDir = GetAgentRulesDir(AgentType("unknown"))
	if rulesDir != "" {
		t.Errorf("Expected empty rules dir for unknown agent, got %s", rulesDir)
	}
}

func TestDetectionResult(t *testing.T) {
	result := DetectionResult{
		AgentType:   AgentTypeFalco,
		Installed:   true,
		BinaryPath:  "/usr/bin/falco",
		ServiceName: "falco-modern-bpf.service",
		ConfigPath:  "/etc/falco/falco.yaml",
		RulesDir:    "/etc/falco/rules.d/",
		Version:     "0.35.1",
	}

	if result.AgentType != AgentTypeFalco {
		t.Errorf("Expected AgentType to be Falco, got %s", result.AgentType)
	}

	if !result.Installed {
		t.Error("Expected Installed to be true")
	}

	if result.BinaryPath != "/usr/bin/falco" {
		t.Errorf("Expected BinaryPath to be '/usr/bin/falco', got %s", result.BinaryPath)
	}
}

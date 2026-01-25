package ebpf

import (
	"testing"
)

func TestAgentTypeString(t *testing.T) {
	tests := []struct {
		agentType AgentType
		expected  string
	}{
		{AgentTypeFalco, "falco"},
		{AgentTypeTetragon, "tetragon"},
		{AgentTypePixie, "pixie"},
	}

	for _, tt := range tests {
		t.Run(string(tt.agentType), func(t *testing.T) {
			if got := tt.agentType.String(); got != tt.expected {
				t.Errorf("AgentType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestServiceStatus(t *testing.T) {
	status := ServiceStatus{
		ActiveState: "active",
		SubState:    "running",
		Running:     true,
	}

	if !status.Running {
		t.Error("Expected Running to be true")
	}

	if status.ActiveState != "active" {
		t.Errorf("Expected ActiveState to be 'active', got %s", status.ActiveState)
	}
}

func TestAgentConfig(t *testing.T) {
	config := AgentConfig{
		Enabled:    true,
		ConfigPath: "/etc/falco/falco.yaml",
		Options: map[string]string{
			"json_output": "true",
		},
	}

	if !config.Enabled {
		t.Error("Expected Enabled to be true")
	}

	if config.ConfigPath != "/etc/falco/falco.yaml" {
		t.Errorf("Expected ConfigPath to be '/etc/falco/falco.yaml', got %s", config.ConfigPath)
	}

	if config.Options["json_output"] != "true" {
		t.Errorf("Expected json_output option to be 'true', got %s", config.Options["json_output"])
	}
}

func TestRuleFile(t *testing.T) {
	rule := RuleFile{
		Filename: "custom_rules.yaml",
		MD5Sum:   "abc123",
		Content:  "base64content",
		Size:     100,
	}

	if rule.Filename != "custom_rules.yaml" {
		t.Errorf("Expected Filename to be 'custom_rules.yaml', got %s", rule.Filename)
	}

	if rule.Size != 100 {
		t.Errorf("Expected Size to be 100, got %d", rule.Size)
	}
}

func TestAgentInfo(t *testing.T) {
	info := AgentInfo{
		Type:          AgentTypeFalco,
		Name:          "Falco",
		Version:       "0.35.1",
		Installed:     true,
		Enabled:       true,
		ServiceStatus: "running",
		BinaryPath:    "/usr/bin/falco",
		ConfigPath:    "/etc/falco/falco.yaml",
		RulesDir:      "/etc/falco/rules.d/",
	}

	if info.Type != AgentTypeFalco {
		t.Errorf("Expected Type to be AgentTypeFalco, got %s", info.Type)
	}

	if !info.Installed {
		t.Error("Expected Installed to be true")
	}

	if !info.Enabled {
		t.Error("Expected Enabled to be true")
	}
}

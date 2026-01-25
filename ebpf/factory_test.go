package ebpf

import (
	"context"
	"testing"
)

// mockAgent implements EBPFAgent for testing
type mockAgent struct {
	agentType   AgentType
	name        string
	installed   bool
	running     bool
	listening   bool
	eventChan   chan SecurityEvent
}

func newMockAgent(agentType AgentType, installed bool) *mockAgent {
	return &mockAgent{
		agentType: agentType,
		name:      string(agentType) + "-mock",
		installed: installed,
		eventChan: make(chan SecurityEvent, 10),
	}
}

func (m *mockAgent) Type() AgentType                              { return m.agentType }
func (m *mockAgent) Name() string                                  { return m.name }
func (m *mockAgent) Version() (string, error)                      { return "1.0.0-mock", nil }
func (m *mockAgent) Start(ctx context.Context) error               { m.running = true; return nil }
func (m *mockAgent) Stop(ctx context.Context) error                { m.running = false; return nil }
func (m *mockAgent) IsRunning() bool                               { return m.running }
func (m *mockAgent) StartEventListener(ctx context.Context) error  { m.listening = true; return nil }
func (m *mockAgent) StopEventListener() error                      { m.listening = false; return nil }
func (m *mockAgent) EventChannel() <-chan SecurityEvent            { return m.eventChan }
func (m *mockAgent) IsListening() bool                             { return m.listening }
func (m *mockAgent) LoadConfig() error                             { return nil }
func (m *mockAgent) UpdateConfig(config AgentConfig) error         { return nil }
func (m *mockAgent) GetConfigPath() string                         { return "/etc/mock/config.yaml" }
func (m *mockAgent) GetRules() ([]RuleFile, error)                 { return nil, nil }
func (m *mockAgent) UpdateRules(rules []RuleFile) error            { return nil }
func (m *mockAgent) GetRulesDir() string                           { return "/etc/mock/rules.d/" }
func (m *mockAgent) ServiceName() string                           { return "mock.service" }
func (m *mockAgent) GetServiceStatus() (ServiceStatus, error)      { return ServiceStatus{Running: m.running}, nil }
func (m *mockAgent) StartService() error                           { return nil }
func (m *mockAgent) StopService() error                            { return nil }
func (m *mockAgent) RestartService() error                         { return nil }
func (m *mockAgent) GetServiceLogs(lines int) (string, error)      { return "mock logs", nil }
func (m *mockAgent) IsInstalled() bool                             { return m.installed }
func (m *mockAgent) GetBinaryPath() string                         { return "/usr/bin/mock" }

func TestRegisterAndCreate(t *testing.T) {
	// Create a test agent type
	testType := AgentType("test-agent")

	// Register the mock agent
	Register(testType, func() (EBPFAgent, error) {
		return newMockAgent(testType, true), nil
	})
	defer Unregister(testType)

	// Verify it's registered
	if !IsRegistered(testType) {
		t.Error("Expected agent to be registered")
	}

	// Create the agent using factory
	factory := NewFactory()
	agent, err := factory.Create(testType)
	if err != nil {
		t.Fatalf("Failed to create agent: %v", err)
	}

	if agent.Type() != testType {
		t.Errorf("Expected agent type %s, got %s", testType, agent.Type())
	}

	if agent.Name() != "test-agent-mock" {
		t.Errorf("Expected agent name 'test-agent-mock', got %s", agent.Name())
	}
}

func TestUnregister(t *testing.T) {
	testType := AgentType("temp-agent")

	Register(testType, func() (EBPFAgent, error) {
		return newMockAgent(testType, true), nil
	})

	if !IsRegistered(testType) {
		t.Error("Expected agent to be registered")
	}

	Unregister(testType)

	if IsRegistered(testType) {
		t.Error("Expected agent to be unregistered")
	}
}

func TestCreateUnknownAgent(t *testing.T) {
	factory := NewFactory()
	_, err := factory.Create(AgentType("unknown-agent"))

	if err == nil {
		t.Error("Expected error when creating unknown agent")
	}
}

func TestGetRegisteredTypes(t *testing.T) {
	// Register a few test agents
	testType1 := AgentType("test-type-1")
	testType2 := AgentType("test-type-2")

	Register(testType1, func() (EBPFAgent, error) {
		return newMockAgent(testType1, true), nil
	})
	Register(testType2, func() (EBPFAgent, error) {
		return newMockAgent(testType2, true), nil
	})
	defer Unregister(testType1)
	defer Unregister(testType2)

	types := GetRegisteredTypes()

	// Should have at least our 2 test types plus the real ones (falco, tetragon, pixie)
	if len(types) < 2 {
		t.Errorf("Expected at least 2 registered types, got %d", len(types))
	}

	// Check our test types are in there
	found1, found2 := false, false
	for _, typ := range types {
		if typ == testType1 {
			found1 = true
		}
		if typ == testType2 {
			found2 = true
		}
	}

	if !found1 {
		t.Errorf("Expected to find %s in registered types", testType1)
	}
	if !found2 {
		t.Errorf("Expected to find %s in registered types", testType2)
	}
}

func TestCreateAll(t *testing.T) {
	// Register mock agents for the supported types
	Register(AgentTypeFalco, func() (EBPFAgent, error) {
		return newMockAgent(AgentTypeFalco, true), nil
	})
	Register(AgentTypeTetragon, func() (EBPFAgent, error) {
		return newMockAgent(AgentTypeTetragon, true), nil
	})
	Register(AgentTypePixie, func() (EBPFAgent, error) {
		return newMockAgent(AgentTypePixie, true), nil
	})
	defer func() {
		Unregister(AgentTypeFalco)
		Unregister(AgentTypeTetragon)
		Unregister(AgentTypePixie)
	}()

	factory := NewFactory()
	agents, err := factory.CreateAll()

	if err != nil {
		t.Fatalf("CreateAll failed: %v", err)
	}

	// Should have the 3 registered mock agents
	if len(agents) != 3 {
		t.Errorf("Expected 3 agents, got %d", len(agents))
	}
}

func TestGetSupportedAgentTypes(t *testing.T) {
	types := GetSupportedAgentTypes()

	if len(types) != 4 {
		t.Errorf("Expected 4 supported types, got %d", len(types))
	}

	expectedTypes := map[AgentType]bool{
		AgentTypeFalco:    false,
		AgentTypeTetragon: false,
		AgentTypePixie:    false,
		AgentTypeNative:   false,
	}

	for _, typ := range types {
		if _, ok := expectedTypes[typ]; ok {
			expectedTypes[typ] = true
		}
	}

	for typ, found := range expectedTypes {
		if !found {
			t.Errorf("Expected %s to be in supported types", typ)
		}
	}
}

func TestAgentTypeFromString(t *testing.T) {
	tests := []struct {
		input    string
		expected AgentType
		hasError bool
	}{
		{"falco", AgentTypeFalco, false},
		{"tetragon", AgentTypeTetragon, false},
		{"pixie", AgentTypePixie, false},
		{"native", AgentTypeNative, false},
		{"unknown", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := AgentTypeFromString(tt.input)

			if tt.hasError {
				if err == nil {
					t.Errorf("Expected error for input %q", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for input %q: %v", tt.input, err)
				}
				if result != tt.expected {
					t.Errorf("AgentTypeFromString(%q) = %v, want %v", tt.input, result, tt.expected)
				}
			}
		})
	}
}

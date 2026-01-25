package ebpf

import (
	"context"
	"testing"
	"time"
)

// registerTestAgents registers mock agents for testing purposes
// This is needed because the actual agent packages aren't imported in the test
func registerTestAgents() {
	// Register mock Falco agent
	Register(AgentTypeFalco, func() (EBPFAgent, error) {
		return newTestAgent(AgentTypeFalco, "Falco", true), nil
	})
	// Register mock Tetragon agent
	Register(AgentTypeTetragon, func() (EBPFAgent, error) {
		return newTestAgent(AgentTypeTetragon, "Tetragon", false), nil
	})
	// Register mock Pixie agent
	Register(AgentTypePixie, func() (EBPFAgent, error) {
		return newTestAgent(AgentTypePixie, "Pixie", false), nil
	})
}

// testAgent implements EBPFAgent for testing
type testAgent struct {
	agentType   AgentType
	name        string
	installed   bool
	running     bool
	listening   bool
	eventChan   chan SecurityEvent
}

func newTestAgent(agentType AgentType, name string, installed bool) *testAgent {
	return &testAgent{
		agentType: agentType,
		name:      name,
		installed: installed,
		eventChan: make(chan SecurityEvent, 10),
	}
}

func (a *testAgent) Type() AgentType                              { return a.agentType }
func (a *testAgent) Name() string                                 { return a.name }
func (a *testAgent) Version() (string, error)                     { return "1.0.0-test", nil }
func (a *testAgent) Start(ctx context.Context) error              { a.running = true; return nil }
func (a *testAgent) Stop(ctx context.Context) error               { a.running = false; return nil }
func (a *testAgent) IsRunning() bool                              { return a.running }
func (a *testAgent) StartEventListener(ctx context.Context) error { a.listening = true; return nil }
func (a *testAgent) StopEventListener() error                     { a.listening = false; return nil }
func (a *testAgent) EventChannel() <-chan SecurityEvent           { return a.eventChan }
func (a *testAgent) IsListening() bool                            { return a.listening }
func (a *testAgent) LoadConfig() error                            { return nil }
func (a *testAgent) UpdateConfig(config AgentConfig) error        { return nil }
func (a *testAgent) GetConfigPath() string                        { return "/etc/test/config.yaml" }
func (a *testAgent) GetRules() ([]RuleFile, error)                { return nil, nil }
func (a *testAgent) UpdateRules(rules []RuleFile) error           { return nil }
func (a *testAgent) GetRulesDir() string                          { return "/etc/test/rules.d/" }
func (a *testAgent) ServiceName() string                          { return "test.service" }
func (a *testAgent) GetServiceStatus() (ServiceStatus, error)     { return ServiceStatus{Running: a.running}, nil }
func (a *testAgent) StartService() error                          { return nil }
func (a *testAgent) StopService() error                           { return nil }
func (a *testAgent) RestartService() error                        { return nil }
func (a *testAgent) GetServiceLogs(lines int) (string, error)     { return "test logs", nil }
func (a *testAgent) IsInstalled() bool                            { return a.installed }
func (a *testAgent) GetBinaryPath() string                        { return "/usr/bin/test" }

func TestDefaultManagerConfig(t *testing.T) {
	config := DefaultManagerConfig()

	if config.EventBufferSize != 1000 {
		t.Errorf("Expected EventBufferSize to be 1000, got %d", config.EventBufferSize)
	}

	if !config.AutoDetect {
		t.Error("Expected AutoDetect to be true")
	}
}

func TestNewAgentManager(t *testing.T) {
	config := DefaultManagerConfig()
	manager := NewAgentManager(config)

	if manager == nil {
		t.Fatal("Expected non-nil manager")
	}

	if manager.agents == nil {
		t.Error("Expected agents map to be initialized")
	}

	if manager.enabledAgents == nil {
		t.Error("Expected enabledAgents map to be initialized")
	}

	if manager.eventsChan == nil {
		t.Error("Expected eventsChan to be initialized")
	}

	if manager.factory == nil {
		t.Error("Expected factory to be initialized")
	}
}

func TestAgentManagerInitialize(t *testing.T) {
	registerTestAgents()
	defer func() {
		Unregister(AgentTypeFalco)
		Unregister(AgentTypeTetragon)
		Unregister(AgentTypePixie)
	}()

	config := DefaultManagerConfig()
	manager := NewAgentManager(config)

	ctx := context.Background()
	err := manager.Initialize(ctx)

	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Should have agents registered (at least the built-in ones)
	if len(manager.agents) == 0 {
		t.Error("Expected at least one agent after initialization")
	}
}

func TestAgentManagerGetAgent(t *testing.T) {
	registerTestAgents()
	defer func() {
		Unregister(AgentTypeFalco)
		Unregister(AgentTypeTetragon)
		Unregister(AgentTypePixie)
	}()

	config := DefaultManagerConfig()
	manager := NewAgentManager(config)

	ctx := context.Background()
	_ = manager.Initialize(ctx)

	// Try to get Falco agent
	agent, exists := manager.GetAgent(AgentTypeFalco)
	if !exists {
		t.Error("Expected Falco agent to exist")
	}

	if agent != nil && agent.Type() != AgentTypeFalco {
		t.Errorf("Expected agent type to be Falco, got %s", agent.Type())
	}

	// Try to get non-existent agent
	_, exists = manager.GetAgent(AgentType("nonexistent"))
	if exists {
		t.Error("Expected non-existent agent to not exist")
	}
}

func TestAgentManagerGetInstalledAgents(t *testing.T) {
	registerTestAgents()
	defer func() {
		Unregister(AgentTypeFalco)
		Unregister(AgentTypeTetragon)
		Unregister(AgentTypePixie)
	}()

	config := DefaultManagerConfig()
	manager := NewAgentManager(config)

	ctx := context.Background()
	_ = manager.Initialize(ctx)

	installed := manager.GetInstalledAgents()

	// All returned agents should report as installed
	for _, agent := range installed {
		if !agent.IsInstalled() {
			t.Errorf("Agent %s returned by GetInstalledAgents is not installed", agent.Type())
		}
	}
}

func TestAgentManagerGetEnabledAgents(t *testing.T) {
	registerTestAgents()
	defer func() {
		Unregister(AgentTypeFalco)
		Unregister(AgentTypeTetragon)
		Unregister(AgentTypePixie)
	}()

	config := DefaultManagerConfig()
	manager := NewAgentManager(config)

	ctx := context.Background()
	_ = manager.Initialize(ctx)

	// Initially no agents should be enabled
	enabled := manager.GetEnabledAgents()
	if len(enabled) != 0 {
		t.Errorf("Expected no enabled agents initially, got %d", len(enabled))
	}
}

func TestAgentManagerIsEnabled(t *testing.T) {
	registerTestAgents()
	defer func() {
		Unregister(AgentTypeFalco)
		Unregister(AgentTypeTetragon)
		Unregister(AgentTypePixie)
	}()

	config := DefaultManagerConfig()
	manager := NewAgentManager(config)

	ctx := context.Background()
	_ = manager.Initialize(ctx)

	// No agents should be enabled initially
	if manager.IsEnabled(AgentTypeFalco) {
		t.Error("Expected Falco to not be enabled initially")
	}

	if manager.IsEnabled(AgentTypeTetragon) {
		t.Error("Expected Tetragon to not be enabled initially")
	}
}

func TestAgentManagerEventChannel(t *testing.T) {
	config := DefaultManagerConfig()
	manager := NewAgentManager(config)

	ch := manager.EventChannel()

	if ch == nil {
		t.Error("Expected non-nil event channel")
	}
}

func TestAgentManagerGetAllAgentInfo(t *testing.T) {
	registerTestAgents()
	defer func() {
		Unregister(AgentTypeFalco)
		Unregister(AgentTypeTetragon)
		Unregister(AgentTypePixie)
	}()

	config := DefaultManagerConfig()
	manager := NewAgentManager(config)

	ctx := context.Background()
	_ = manager.Initialize(ctx)

	infos := manager.GetAllAgentInfo()

	if len(infos) == 0 {
		t.Error("Expected at least one agent info")
	}

	for _, info := range infos {
		if info.Type == "" {
			t.Error("Agent info has empty type")
		}
		if info.Name == "" {
			t.Error("Agent info has empty name")
		}
	}
}

func TestAgentManagerGetAgentInfo(t *testing.T) {
	registerTestAgents()
	defer func() {
		Unregister(AgentTypeFalco)
		Unregister(AgentTypeTetragon)
		Unregister(AgentTypePixie)
	}()

	config := DefaultManagerConfig()
	manager := NewAgentManager(config)

	ctx := context.Background()
	_ = manager.Initialize(ctx)

	// Get info for existing agent
	info, err := manager.GetAgentInfo(AgentTypeFalco)
	if err != nil {
		t.Fatalf("GetAgentInfo failed for Falco: %v", err)
	}

	if info.Type != AgentTypeFalco {
		t.Errorf("Expected type Falco, got %s", info.Type)
	}

	// Get info for non-existent agent
	_, err = manager.GetAgentInfo(AgentType("nonexistent"))
	if err == nil {
		t.Error("Expected error for non-existent agent")
	}
}

func TestAgentManagerEnableDisableNotInstalled(t *testing.T) {
	registerTestAgents()
	defer func() {
		Unregister(AgentTypeFalco)
		Unregister(AgentTypeTetragon)
		Unregister(AgentTypePixie)
	}()

	config := DefaultManagerConfig()
	manager := NewAgentManager(config)

	ctx := context.Background()
	_ = manager.Initialize(ctx)

	// Try to enable an agent that's not installed
	// This should fail unless the agent is actually installed on the test system
	// We'll test with a type that we know isn't installed
	err := manager.EnableAgent(ctx, AgentType("nonexistent"))
	if err == nil {
		t.Error("Expected error when enabling non-existent agent")
	}
}

func TestAgentManagerShutdown(t *testing.T) {
	registerTestAgents()
	defer func() {
		Unregister(AgentTypeFalco)
		Unregister(AgentTypeTetragon)
		Unregister(AgentTypePixie)
	}()

	config := DefaultManagerConfig()
	manager := NewAgentManager(config)

	ctx := context.Background()
	_ = manager.Initialize(ctx)

	// Shutdown should complete without error
	err := manager.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}
}

func TestAgentManagerConcurrentAccess(t *testing.T) {
	registerTestAgents()
	defer func() {
		Unregister(AgentTypeFalco)
		Unregister(AgentTypeTetragon)
		Unregister(AgentTypePixie)
	}()

	config := DefaultManagerConfig()
	manager := NewAgentManager(config)

	ctx := context.Background()
	_ = manager.Initialize(ctx)

	// Test concurrent access to manager methods
	done := make(chan bool)

	go func() {
		for i := 0; i < 100; i++ {
			_ = manager.GetAllAgentInfo()
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			_ = manager.GetInstalledAgents()
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			_ = manager.IsEnabled(AgentTypeFalco)
		}
		done <- true
	}()

	// Wait for all goroutines with timeout
	for i := 0; i < 3; i++ {
		select {
		case <-done:
			// OK
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent operations")
		}
	}
}

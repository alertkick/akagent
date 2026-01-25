package ebpf

import (
	"context"
	"fmt"
	"sync"
)

// AgentManager orchestrates multiple eBPF security agents
type AgentManager struct {
	mu             sync.RWMutex
	agents         map[AgentType]EBPFAgent
	enabledAgents  map[AgentType]bool
	eventsChan     chan SecurityEvent
	factory        *Factory
	wg             sync.WaitGroup
	shutdownChan   chan struct{}
	eventBufferSize int
}

// ManagerConfig holds configuration for the AgentManager
type ManagerConfig struct {
	EventBufferSize int
	AutoDetect      bool
}

// DefaultManagerConfig returns the default manager configuration
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		EventBufferSize: 1000,
		AutoDetect:      true,
	}
}

// NewAgentManager creates a new AgentManager instance
func NewAgentManager(config ManagerConfig) *AgentManager {
	return &AgentManager{
		agents:          make(map[AgentType]EBPFAgent),
		enabledAgents:   make(map[AgentType]bool),
		eventsChan:      make(chan SecurityEvent, config.EventBufferSize),
		factory:         NewFactory(),
		shutdownChan:    make(chan struct{}),
		eventBufferSize: config.EventBufferSize,
	}
}

// Initialize detects and initializes all available eBPF agents
func (m *AgentManager) Initialize(ctx context.Context) error {
	log.Info().Msg("Initializing eBPF agent manager")

	// Create all registered agents and check which are installed
	allAgents, err := m.factory.CreateAll()
	if err != nil {
		return fmt.Errorf("failed to create agents: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, agent := range allAgents {
		agentType := agent.Type()
		m.agents[agentType] = agent

		if agent.IsInstalled() {
			log.Info().Msgf("Detected installed eBPF agent: %s at %s", agent.Name(), agent.GetBinaryPath())
		} else {
			log.Debug().Msgf("eBPF agent not installed: %s", agent.Name())
		}
	}

	log.Info().Msgf("Agent manager initialized with %d agents", len(m.agents))
	return nil
}

// GetAgent returns an agent by type
func (m *AgentManager) GetAgent(agentType AgentType) (EBPFAgent, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	agent, exists := m.agents[agentType]
	return agent, exists
}

// GetInstalledAgents returns all agents that are installed on the system
func (m *AgentManager) GetInstalledAgents() []EBPFAgent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	installed := make([]EBPFAgent, 0)
	for _, agent := range m.agents {
		if agent.IsInstalled() {
			installed = append(installed, agent)
		}
	}
	return installed
}

// GetEnabledAgents returns all agents that are currently enabled
func (m *AgentManager) GetEnabledAgents() []EBPFAgent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	enabled := make([]EBPFAgent, 0)
	for agentType, isEnabled := range m.enabledAgents {
		if isEnabled {
			if agent, exists := m.agents[agentType]; exists {
				enabled = append(enabled, agent)
			}
		}
	}
	return enabled
}

// EnableAgent enables an agent and starts its event listener
func (m *AgentManager) EnableAgent(ctx context.Context, agentType AgentType) error {
	m.mu.Lock()
	agent, exists := m.agents[agentType]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("agent not found: %s", agentType)
	}

	if !agent.IsInstalled() {
		m.mu.Unlock()
		return fmt.Errorf("agent not installed: %s", agentType)
	}

	m.enabledAgents[agentType] = true
	m.mu.Unlock()

	// Start the agent
	if err := agent.Start(ctx); err != nil {
		log.Warn().Err(err).Msgf("Failed to start agent: %s", agentType)
	}

	// Start event listener
	if err := agent.StartEventListener(ctx); err != nil {
		return fmt.Errorf("failed to start event listener for %s: %w", agentType, err)
	}

	// Start forwarding events from this agent to the unified channel
	m.wg.Add(1)
	go m.forwardEvents(agent)

	log.Info().Msgf("Enabled eBPF agent: %s", agentType)
	return nil
}

// DisableAgent disables an agent and stops its event listener
func (m *AgentManager) DisableAgent(ctx context.Context, agentType AgentType) error {
	m.mu.Lock()
	agent, exists := m.agents[agentType]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("agent not found: %s", agentType)
	}

	m.enabledAgents[agentType] = false
	m.mu.Unlock()

	// Stop event listener
	if err := agent.StopEventListener(); err != nil {
		log.Warn().Err(err).Msgf("Error stopping event listener for %s", agentType)
	}

	// Stop the agent
	if err := agent.Stop(ctx); err != nil {
		log.Warn().Err(err).Msgf("Error stopping agent: %s", agentType)
	}

	log.Info().Msgf("Disabled eBPF agent: %s", agentType)
	return nil
}

// IsEnabled checks if an agent is enabled
func (m *AgentManager) IsEnabled(agentType AgentType) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabledAgents[agentType]
}

// EventChannel returns the unified event channel
func (m *AgentManager) EventChannel() <-chan SecurityEvent {
	return m.eventsChan
}

// forwardEvents forwards events from an agent's channel to the unified channel
func (m *AgentManager) forwardEvents(agent EBPFAgent) {
	defer m.wg.Done()

	agentType := agent.Type()
	eventCh := agent.EventChannel()

	for {
		select {
		case <-m.shutdownChan:
			log.Debug().Msgf("Stopping event forwarding for %s", agentType)
			return
		case event, ok := <-eventCh:
			if !ok {
				log.Debug().Msgf("Event channel closed for %s", agentType)
				return
			}

			// Check if agent is still enabled
			m.mu.RLock()
			enabled := m.enabledAgents[agentType]
			m.mu.RUnlock()

			if !enabled {
				log.Debug().Msgf("Agent %s disabled, discarding event", agentType)
				return
			}

			// Forward to unified channel (non-blocking with drop on full)
			select {
			case m.eventsChan <- event:
				log.Debug().Msgf("Forwarded event from %s: %s", agentType, event.Rule)
			default:
				log.Warn().Msgf("Event channel full, dropping event from %s", agentType)
			}
		}
	}
}

// GetAllAgentInfo returns information about all agents
func (m *AgentManager) GetAllAgentInfo() []AgentInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	infos := make([]AgentInfo, 0, len(m.agents))
	for _, agent := range m.agents {
		info := GetInfo(agent)
		info.Enabled = m.enabledAgents[agent.Type()]
		infos = append(infos, info)
	}
	return infos
}

// GetAgentInfo returns information about a specific agent
func (m *AgentManager) GetAgentInfo(agentType AgentType) (AgentInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	agent, exists := m.agents[agentType]
	if !exists {
		return AgentInfo{}, fmt.Errorf("agent not found: %s", agentType)
	}

	info := GetInfo(agent)
	info.Enabled = m.enabledAgents[agentType]
	return info, nil
}

// StartService starts the systemd service for an agent
func (m *AgentManager) StartService(agentType AgentType) error {
	m.mu.RLock()
	agent, exists := m.agents[agentType]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("agent not found: %s", agentType)
	}

	return agent.StartService()
}

// StopService stops the systemd service for an agent
func (m *AgentManager) StopService(agentType AgentType) error {
	m.mu.RLock()
	agent, exists := m.agents[agentType]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("agent not found: %s", agentType)
	}

	return agent.StopService()
}

// RestartService restarts the systemd service for an agent
func (m *AgentManager) RestartService(agentType AgentType) error {
	m.mu.RLock()
	agent, exists := m.agents[agentType]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("agent not found: %s", agentType)
	}

	return agent.RestartService()
}

// GetServiceLogs gets the service logs for an agent
func (m *AgentManager) GetServiceLogs(agentType AgentType, lines int) (string, error) {
	m.mu.RLock()
	agent, exists := m.agents[agentType]
	m.mu.RUnlock()

	if !exists {
		return "", fmt.Errorf("agent not found: %s", agentType)
	}

	return agent.GetServiceLogs(lines)
}

// GetRules gets the rules for an agent
func (m *AgentManager) GetRules(agentType AgentType) ([]RuleFile, error) {
	m.mu.RLock()
	agent, exists := m.agents[agentType]
	m.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("agent not found: %s", agentType)
	}

	return agent.GetRules()
}

// UpdateRules updates the rules for an agent
func (m *AgentManager) UpdateRules(agentType AgentType, rules []RuleFile) error {
	m.mu.RLock()
	agent, exists := m.agents[agentType]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("agent not found: %s", agentType)
	}

	return agent.UpdateRules(rules)
}

// Shutdown gracefully shuts down the agent manager
func (m *AgentManager) Shutdown(ctx context.Context) error {
	log.Info().Msg("Shutting down agent manager")

	// Signal all goroutines to stop
	close(m.shutdownChan)

	// Disable all agents
	m.mu.Lock()
	agentTypes := make([]AgentType, 0, len(m.enabledAgents))
	for agentType, enabled := range m.enabledAgents {
		if enabled {
			agentTypes = append(agentTypes, agentType)
		}
	}
	m.mu.Unlock()

	for _, agentType := range agentTypes {
		if err := m.DisableAgent(ctx, agentType); err != nil {
			log.Warn().Err(err).Msgf("Error disabling agent during shutdown: %s", agentType)
		}
	}

	// Wait for all goroutines to finish
	m.wg.Wait()

	// Close the events channel
	close(m.eventsChan)

	log.Info().Msg("Agent manager shut down complete")
	return nil
}

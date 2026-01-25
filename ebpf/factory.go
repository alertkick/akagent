package ebpf

import (
	"fmt"
	"sync"

	"apagent/logger"
)

var log = logger.Sublogger("ebpf")

// AgentConstructor is a function that creates a new EBPFAgent instance
type AgentConstructor func() (EBPFAgent, error)

// Registry holds all registered agent constructors
type Registry struct {
	mu           sync.RWMutex
	constructors map[AgentType]AgentConstructor
}

// globalRegistry is the default registry instance
var globalRegistry = &Registry{
	constructors: make(map[AgentType]AgentConstructor),
}

// Register adds a new agent constructor to the registry
func Register(agentType AgentType, constructor AgentConstructor) {
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()
	globalRegistry.constructors[agentType] = constructor
	log.Debug().Msgf("Registered eBPF agent: %s", agentType)
}

// Unregister removes an agent constructor from the registry
func Unregister(agentType AgentType) {
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()
	delete(globalRegistry.constructors, agentType)
}

// GetRegisteredTypes returns all registered agent types
func GetRegisteredTypes() []AgentType {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()

	types := make([]AgentType, 0, len(globalRegistry.constructors))
	for t := range globalRegistry.constructors {
		types = append(types, t)
	}
	return types
}

// IsRegistered checks if an agent type is registered
func IsRegistered(agentType AgentType) bool {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()
	_, exists := globalRegistry.constructors[agentType]
	return exists
}

// Factory creates EBPFAgent instances
type Factory struct {
	registry *Registry
}

// NewFactory creates a new Factory using the global registry
func NewFactory() *Factory {
	return &Factory{
		registry: globalRegistry,
	}
}

// Create instantiates an agent of the specified type
func (f *Factory) Create(agentType AgentType) (EBPFAgent, error) {
	f.registry.mu.RLock()
	constructor, exists := f.registry.constructors[agentType]
	f.registry.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("unknown agent type: %s", agentType)
	}

	return constructor()
}

// CreateAll creates instances of all registered agent types
func (f *Factory) CreateAll() ([]EBPFAgent, error) {
	f.registry.mu.RLock()
	types := make([]AgentType, 0, len(f.registry.constructors))
	for t := range f.registry.constructors {
		types = append(types, t)
	}
	f.registry.mu.RUnlock()

	agents := make([]EBPFAgent, 0, len(types))
	for _, t := range types {
		agent, err := f.Create(t)
		if err != nil {
			log.Warn().Err(err).Msgf("Failed to create agent: %s", t)
			continue
		}
		agents = append(agents, agent)
	}

	return agents, nil
}

// CreateInstalled creates instances of all agents that are detected as installed
func (f *Factory) CreateInstalled() ([]EBPFAgent, error) {
	allAgents, err := f.CreateAll()
	if err != nil {
		return nil, err
	}

	installedAgents := make([]EBPFAgent, 0)
	for _, agent := range allAgents {
		if agent.IsInstalled() {
			installedAgents = append(installedAgents, agent)
			log.Info().Msgf("Detected installed eBPF agent: %s", agent.Name())
		}
	}

	return installedAgents, nil
}

// GetSupportedAgentTypes returns the list of all supported agent types
func GetSupportedAgentTypes() []AgentType {
	return []AgentType{
		AgentTypeFalco,
		AgentTypeTetragon,
		AgentTypePixie,
		AgentTypeNative,
	}
}

// AgentTypeFromString converts a string to AgentType
func AgentTypeFromString(s string) (AgentType, error) {
	switch s {
	case "falco":
		return AgentTypeFalco, nil
	case "tetragon":
		return AgentTypeTetragon, nil
	case "pixie":
		return AgentTypePixie, nil
	case "native":
		return AgentTypeNative, nil
	default:
		return "", fmt.Errorf("unknown agent type: %s", s)
	}
}

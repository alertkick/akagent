package compliance

import (
	"akagent/ebpf/rules"
	"encoding/json"
	"sync"
)

// Handler manages compliance configuration updates
type Handler struct {
	mu         sync.RWMutex
	engine     *rules.RuleEngine
	lastConfig []byte
	enabled    bool
}

// NewHandler creates a new compliance handler
func NewHandler() *Handler {
	return &Handler{
		engine:  rules.NewRuleEngine(),
		enabled: false,
	}
}

// RefreshConfig handles the agent.refresh_compliance command
// It parses and loads the new compliance configuration
func (h *Handler) RefreshConfig(configData []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Parse the profile configuration
	config, err := rules.ParseProfileJSON(configData)
	if err != nil {
		return err
	}

	// Update the rule engine with the new profile
	if err := h.engine.UpdateProfile(config); err != nil {
		return err
	}

	// Store the raw config for debugging
	h.lastConfig = configData
	h.enabled = true

	return nil
}

// GetEngine returns the rule engine for event evaluation
func (h *Handler) GetEngine() *rules.RuleEngine {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.engine
}

// IsEnabled returns true if compliance monitoring is enabled
func (h *Handler) IsEnabled() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.enabled
}

// Disable disables compliance monitoring
func (h *Handler) Disable() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.enabled = false
}

// GetStatus returns the current status of the compliance handler
func (h *Handler) GetStatus() *Status {
	h.mu.RLock()
	defer h.mu.RUnlock()

	status := &Status{
		Enabled:   h.enabled,
		RuleCount: h.engine.GetRuleCount(),
	}

	name, version, lastUpdated := h.engine.GetProfileInfo()
	status.ProfileName = name
	status.ProfileVersion = version
	status.LastUpdated = lastUpdated.Format("2006-01-02T15:04:05Z")

	evaluated, matched := h.engine.GetStats()
	status.EventsEvaluated = evaluated
	status.EventsMatched = matched

	return status
}

// Status represents the compliance handler status
type Status struct {
	Enabled         bool   `json:"enabled"`
	ProfileName     string `json:"profile_name"`
	ProfileVersion  string `json:"profile_version"`
	LastUpdated     string `json:"last_updated"`
	RuleCount       int    `json:"rule_count"`
	EventsEvaluated uint64 `json:"events_evaluated"`
	EventsMatched   uint64 `json:"events_matched"`
}

// ToJSON converts the status to JSON
func (s *Status) ToJSON() ([]byte, error) {
	return json.Marshal(s)
}

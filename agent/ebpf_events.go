package agent

import (
	"apagent/client"
	"apagent/ebpf"
	"apagent/internal/api"
	"apagent/logger"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// StartEBPFEventSender starts processing events from all enabled eBPF agents
func (a *agent) StartEBPFEventSender(shutdown chan struct{}, wg *sync.WaitGroup) {
	a.log.Info().Msg("agent.StartEBPFEventSender - starting")
	defer wg.Done()

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-shutdown:
			a.log.Info().Msg("agent.StartEBPFEventSender - stopping")
			return
		case <-ticker.C:
			if a.conn.IsConnected() {
				a.processQueuedSecurityEvents()
			} else {
				a.log.Warn().Msg("agent.StartEBPFEventSender - not connected to endpoint, skipping event sending")
				if logger.IsSectionEnabled(logger.SectionFalco) {
					a.log.Debug().Msgf("agent.StartEBPFEventSender - queue size: %d", len(a.securityEventQueue))
				}
			}
			// Update service status for all enabled agents
			a.updateAllAgentServiceStatus()
		case event := <-a.ebpfManager.EventChannel():
			if logger.IsSectionEnabled(logger.SectionFalco) {
				a.log.Debug().Msgf("agent.StartEBPFEventSender - received event from %s: %s", event.AgentType, event.Rule)
			}
			a.queueSecurityEvent(event)
			if a.conn.IsConnected() {
				a.processQueuedSecurityEvents()
			} else {
				a.log.Warn().Msg("agent.StartEBPFEventSender - not connected to endpoint, event queued for later sending")
			}
		}
	}
}

func (a *agent) queueSecurityEvent(event ebpf.SecurityEvent) {
	a.securityEventQueueMutex.Lock()
	defer a.securityEventQueueMutex.Unlock()

	if len(a.securityEventQueue) >= a.securityEventMaxQueueSize {
		// Remove the oldest event if the queue is full
		a.securityEventQueue = a.securityEventQueue[1:]
	}
	a.securityEventQueue = append(a.securityEventQueue, event)
}

func (a *agent) processQueuedSecurityEvents() {
	a.securityEventQueueMutex.Lock()
	defer a.securityEventQueueMutex.Unlock()

	if len(a.securityEventQueue) == 0 {
		if logger.IsSectionEnabled(logger.SectionFalco) {
			a.log.Debug().Msg("agent.processQueuedSecurityEvents - no security events to process")
		}
		return
	}

	if logger.IsSectionEnabled(logger.SectionFalco) {
		a.log.Debug().Msgf("agent.processQueuedSecurityEvents - processing %d security events", len(a.securityEventQueue))
	}

	for len(a.securityEventQueue) > 0 {
		event := a.securityEventQueue[0]
		err := a.SendSecurityEvent(event)
		if err != nil {
			// If sending fails, stop processing and keep events in queue
			a.log.Warn().Err(err).Msg("agent.processQueuedSecurityEvents - failed to send security event, will retry later")
			return
		}
		// Remove the sent event from the queue
		a.securityEventQueue = a.securityEventQueue[1:]
	}
}

func (a *agent) SendSecurityEvent(event ebpf.SecurityEvent) error {
	// Convert unified event to JSON
	eventJSON, err := json.Marshal(event)
	if err != nil {
		a.log.Err(err).Msg("agent.SendSecurityEvent - failed to marshal event")
		return err
	}

	msg := client.SecurityEventsPost{
		ID:        "1",
		Version:   "1",
		Timestamp: time.Now().Unix(),
		Params:    json.RawMessage(eventJSON),
		Source:    a.AgentID,
		Tenant:    a.Subdomain,
		Subdomain: a.Subdomain,
		Method:    "security_events.post",
		AgentType: string(event.AgentType),
	}

	err = a.conn.SecurityEventsPost(msg)
	if err != nil {
		if errors.Is(err, client.ErrNotConnected) {
			a.log.Warn().Msg("agent.SendSecurityEvent - not connected to endpoint, event queued for later sending")
			return nil
		}
		a.log.Err(err).Msg("agent.SendSecurityEvent - error during security_events.post")
	}
	return err
}

func (a *agent) updateAllAgentServiceStatus() {
	if a.ebpfManager == nil {
		return
	}

	infos := a.ebpfManager.GetAllAgentInfo()
	for _, info := range infos {
		if info.Installed && info.Enabled {
			a.UpdateEBPFAgentServiceStatus(string(info.Type), info.ServiceStatus)
		}
	}
}

// UpdateEBPFAgentServiceStatus sends the service status for an eBPF agent
func (a *agent) UpdateEBPFAgentServiceStatus(agentType string, status string) {
	params := map[string]interface{}{
		"agent_type":     agentType,
		"service_status": status,
	}

	paramsJSON, err := json.Marshal(params)
	if err != nil {
		a.log.Err(err).Msg("agent.UpdateEBPFAgentServiceStatus - failed to marshal params")
		return
	}

	msg := client.CheckResultsPost{
		Version:   "1",
		ID:        "1",
		Target:    "agent",
		Source:    a.AgentID,
		Tenant:    a.Subdomain,
		Subdomain: a.Subdomain,
		Method:    "ebpf_agent.service_status.post",
		Params: api.CheckMetricParams{
			CheckID: "ebpf_agent.service_status",
			State:   status,
			InventoryData: paramsJSON,
		},
	}

	err = a.conn.CheckResultsPost(msg)
	if err != nil {
		a.log.Err(err).Msgf("agent.UpdateEBPFAgentServiceStatus - error sending status for %s", agentType)
	}
}

// GetEBPFAgentsInfo returns information about all eBPF agents
func (a *agent) GetEBPFAgentsInfo() []ebpf.AgentInfo {
	if a.ebpfManager == nil {
		return nil
	}
	return a.ebpfManager.GetAllAgentInfo()
}

// EnableEBPFAgent enables a specific eBPF agent
func (a *agent) EnableEBPFAgent(agentType string) error {
	if a.ebpfManager == nil {
		return errors.New("ebpf manager not initialized")
	}

	at, err := ebpf.AgentTypeFromString(agentType)
	if err != nil {
		return err
	}

	return a.ebpfManager.EnableAgent(a.ctx, at)
}

// DisableEBPFAgent disables a specific eBPF agent
func (a *agent) DisableEBPFAgent(agentType string) error {
	if a.ebpfManager == nil {
		return errors.New("ebpf manager not initialized")
	}

	at, err := ebpf.AgentTypeFromString(agentType)
	if err != nil {
		return err
	}

	return a.ebpfManager.DisableAgent(a.ctx, at)
}

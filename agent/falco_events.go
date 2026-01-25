package agent

import (
	"apagent/client"
	"apagent/falco_manager"
	"apagent/logger"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

func (a *agent) StartFalcoEventSender(shutdown chan struct{}, wg *sync.WaitGroup) {
	a.log.Info().Msg("agent.StartFalcoEventSender - starting")
	defer wg.Done()

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-shutdown:
			a.log.Info().Msg("agent.StartFalcoEventSender - stopping")
			return
		case <-ticker.C:
			if a.conn.IsConnected() {
				a.processQueuedEvents()
			} else {
				a.log.Warn().Msg("agent.StartFalcoEventSender - not connected to endpoint, skipping Falco event sending")
				if logger.IsSectionEnabled(logger.SectionFalco) {
					a.log.Debug().Msgf("agent.StartFalcoEventSender - queue size: %d", len(a.falcoEventQueue))
				}
			}
			if a.isFalcoServiceAgentRunning() != "running" {
				a.log.Warn().Msg("agent.StartFalcoEventSender - falco-modern-bpf.service is not running, skipping Falco event sending")
				a.UpdateFalcoAgentServiceStatus("stopped")
			}
		case res := <-a.falcoManager.MessageChan:
			if logger.IsSectionEnabled(logger.SectionFalco) {
				a.log.Debug().Msgf("agent.StartFalcoEventSender - received Falco event: %v", res)
			}
			a.queueFalcoEvent(res)
			if a.conn.IsConnected() {
				a.processQueuedEvents()
			} else {
				a.log.Warn().Msg("agent.StartFalcoEventSender - not connected to endpoint, skipping Falco event sending")
			}
		}
	}
}

func (a *agent) queueFalcoEvent(event falco_manager.FalcoEventPayload) {
	a.falcoEventQueueMutex.Lock()
	defer a.falcoEventQueueMutex.Unlock()

	if len(a.falcoEventQueue) >= a.falcoEventMaxQueueSize {
		// Remove the oldest event if the queue is full
		a.falcoEventQueue = a.falcoEventQueue[1:]
	}
	a.falcoEventQueue = append(a.falcoEventQueue, event)
}

func (a *agent) processQueuedEvents() {
	a.falcoEventQueueMutex.Lock()
	defer a.falcoEventQueueMutex.Unlock()

	if len(a.falcoEventQueue) == 0 {
		if logger.IsSectionEnabled(logger.SectionFalco) {
			a.log.Debug().Msg("agent.processQueuedEvents - no Falco events to process")
		}
		return
	}

	if logger.IsSectionEnabled(logger.SectionFalco) {
		a.log.Debug().Msgf("agent.processQueuedEvents - processing %d Falco events", len(a.falcoEventQueue))
	}
	for len(a.falcoEventQueue) > 0 {
		event := a.falcoEventQueue[0]
		err := a.SendFalcoEvents(event)
		if err != nil {
			// If sending fails, stop processing and keep events in queue
			a.log.Warn().Err(err).Msg("agent.processQueuedEvents - failed to send Falco event, will retry later")
			return
		}
		// Remove the sent event from the queue
		a.falcoEventQueue = a.falcoEventQueue[1:]
	}
}

func (a *agent) SendFalcoEvents(payload falco_manager.FalcoEventPayload) error {

	msg := client.FalcoEventsPost{
		ID:        "1",
		Version:   "1",
		Timestamp: time.Now().Unix(),
		Params:    json.RawMessage(payload.String()),
		Source:    a.AgentID,
		Tenant:    a.Subdomain,
		Subdomain: a.Subdomain,
		Method:    "falco_events.post",
	}

	err := a.conn.FalcoEventsPost(msg)
	if err != nil {
		if errors.Is(err, client.ErrNotConnected) {
			// If not connected, log and return without an error
			a.log.Warn().Msg("agent.SendFalcoEvents - not connected to endpoint, event queued for later sending")
			return nil
		}
		a.log.Err(err).Msg("agent.SendFalcoEvents - error during falco_events.post")
	}
	return err
}

// check if falco agent is running
func (a *agent) isFalcoServiceAgentRunning() string {
	return a.falcoManager.FalcoServiceAgentRunning()
}

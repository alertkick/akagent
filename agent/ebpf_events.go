package agent

import (
	"apagent/client"
	"apagent/ebpf"
	"apagent/internal/api"
	"apagent/logger"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// eventGroup tracks a group of deduplicated events sharing the same key.
type eventGroup struct {
	representative ebpf.SecurityEvent
	count          int
	firstSeen      time.Time
	lastSeen       time.Time
}

// EventDeduplicator groups identical events within a batch window.
// NOT thread-safe — owned by the single StartEBPFEventSender goroutine.
type EventDeduplicator struct {
	currentWindow  map[string]*eventGroup
	suppressedKeys map[string]struct{}
	log            zerolog.Logger
}

// NewEventDeduplicator creates a new EventDeduplicator.
func NewEventDeduplicator(log zerolog.Logger) *EventDeduplicator {
	return &EventDeduplicator{
		currentWindow:  make(map[string]*eventGroup),
		suppressedKeys: make(map[string]struct{}),
		log:            log,
	}
}

// Add records an event in the current deduplication window.
func (d *EventDeduplicator) Add(event ebpf.SecurityEvent) {
	key := event.DeduplicationKey()
	if group, exists := d.currentWindow[key]; exists {
		group.count++
		if event.Timestamp.After(group.lastSeen) {
			group.lastSeen = event.Timestamp
		}
		if event.Timestamp.Before(group.firstSeen) {
			group.firstSeen = event.Timestamp
		}
	} else {
		d.currentWindow[key] = &eventGroup{
			representative: event,
			count:          1,
			firstSeen:      event.Timestamp,
			lastSeen:       event.Timestamp,
		}
	}
}

// Flush returns deduplicated events and resets the current window.
// Events with count > 1 have their aggregation fields populated.
func (d *EventDeduplicator) Flush() []ebpf.SecurityEvent {
	if len(d.currentWindow) == 0 {
		// No events this window — evict all previously suppressed keys
		d.suppressedKeys = make(map[string]struct{})
		return nil
	}

	result := make([]ebpf.SecurityEvent, 0, len(d.currentWindow))
	newSuppressed := make(map[string]struct{})
	rawCount := 0

	for key, group := range d.currentWindow {
		rawCount += group.count
		event := group.representative
		if group.count > 1 {
			event.AggregatedCount = group.count
			first := group.firstSeen
			last := group.lastSeen
			event.FirstOccurrence = &first
			event.LastOccurrence = &last
			newSuppressed[key] = struct{}{}
		}
		result = append(result, event)
	}

	if rawCount > len(result) {
		d.log.Info().Msgf("agent.EventDeduplicator - %d raw events deduplicated to %d", rawCount, len(result))
	}

	d.suppressedKeys = newSuppressed
	d.currentWindow = make(map[string]*eventGroup)
	return result
}

const (
	// BatchInterval is how often to send batched events
	BatchInterval = 30 * time.Second
	// MaxBatchSize is the maximum number of events before force flush
	MaxBatchSize = 500
	// HighPriorityFlushThreshold - flush immediately if this many high priority events
	HighPriorityFlushThreshold = 5
)

// StartEBPFEventSender starts processing events from the native eBPF agent
func (a *agent) StartEBPFEventSender(shutdown chan struct{}, wg *sync.WaitGroup) {
	a.log.Info().Msg("agent.StartEBPFEventSender - starting with batch mode (30s interval)")
	defer wg.Done()

	batchTicker := time.NewTicker(BatchInterval)
	defer batchTicker.Stop()

	statusTicker := time.NewTicker(60 * time.Second)
	defer statusTicker.Stop()

	// Get event channel from native agent
	var eventChan <-chan ebpf.SecurityEvent
	if a.nativeAgent != nil {
		eventChan = a.nativeAgent.EventChannel()
	}

	// Event batch buffer (high-priority events go here directly)
	eventBatch := make([]ebpf.SecurityEvent, 0, MaxBatchSize)
	highPriorityCount := 0

	// Deduplicator for non-high-priority events
	dedup := NewEventDeduplicator(a.log)

	for {
		select {
		case <-shutdown:
			a.log.Info().Msg("agent.StartEBPFEventSender - stopping, flushing remaining events")
			// Flush dedup buffer before final send
			if dedupedEvents := dedup.Flush(); len(dedupedEvents) > 0 {
				eventBatch = append(eventBatch, dedupedEvents...)
			}
			if len(eventBatch) > 0 && a.conn.IsConnected() {
				a.sendEventBatch(eventBatch)
			}
			return

		case <-batchTicker.C:
			// Flush dedup buffer and merge into batch
			if dedupedEvents := dedup.Flush(); len(dedupedEvents) > 0 {
				eventBatch = append(eventBatch, dedupedEvents...)
			}

			// Periodic batch flush
			if len(eventBatch) > 0 {
				if a.conn.IsConnected() {
					if logger.IsSectionEnabled(logger.SectionEBPF) {
						a.log.Debug().Msgf("agent.StartEBPFEventSender - batch ticker: flushing %d events", len(eventBatch))
					}
					a.sendEventBatch(eventBatch)
					eventBatch = eventBatch[:0] // Reset slice but keep capacity
					highPriorityCount = 0
				} else {
					a.log.Warn().Msgf("agent.StartEBPFEventSender - not connected, holding %d events", len(eventBatch))
				}
			}

		case <-statusTicker.C:
			// Update service status periodically
			a.updateNativeAgentServiceStatus()

		case event := <-eventChan:
			if logger.IsSectionEnabled(logger.SectionEBPF) {
				a.log.Debug().Msgf("agent.StartEBPFEventSender - received event: %s (pid=%d)", event.Rule, event.Process.PID)
			}

			// High-priority events bypass dedup and go directly into the batch
			if event.IsHighPriority() {
				eventBatch = append(eventBatch, event)
				highPriorityCount++
			} else {
				dedup.Add(event)
			}

			// Force flush conditions:
			// 1. Batch is full
			// 2. Too many high priority events (security-critical)
			shouldFlush := len(eventBatch) >= MaxBatchSize ||
				highPriorityCount >= HighPriorityFlushThreshold

			if shouldFlush && a.conn.IsConnected() {
				// Flush dedup buffer and merge before sending
				if dedupedEvents := dedup.Flush(); len(dedupedEvents) > 0 {
					eventBatch = append(eventBatch, dedupedEvents...)
				}
				if logger.IsSectionEnabled(logger.SectionEBPF) {
					a.log.Debug().Msgf("agent.StartEBPFEventSender - force flush: %d events (high_priority=%d)",
						len(eventBatch), highPriorityCount)
				}
				a.sendEventBatch(eventBatch)
				eventBatch = eventBatch[:0]
				highPriorityCount = 0
			}
		}
	}
}

// sendEventBatch sends a batch of events with gzip compression
func (a *agent) sendEventBatch(events []ebpf.SecurityEvent) error {
	if len(events) == 0 {
		return nil
	}

	// Marshal events to JSON
	eventsJSON, err := json.Marshal(events)
	if err != nil {
		a.log.Err(err).Msg("agent.sendEventBatch - failed to marshal events")
		return err
	}

	originalSize := len(eventsJSON)

	// Compress with gzip
	var compressedBuf bytes.Buffer
	gzWriter := gzip.NewWriter(&compressedBuf)
	_, err = gzWriter.Write(eventsJSON)
	if err != nil {
		a.log.Err(err).Msg("agent.sendEventBatch - failed to compress events")
		gzWriter.Close()
		return err
	}
	gzWriter.Close()

	compressedSize := compressedBuf.Len()
	compressionRatio := float64(compressedSize) / float64(originalSize) * 100

	// Base64 encode the compressed data
	payload := base64.StdEncoding.EncodeToString(compressedBuf.Bytes())

	if logger.IsSectionEnabled(logger.SectionEBPF) {
		a.log.Debug().Msgf("agent.sendEventBatch - sending %d events, original=%d bytes, compressed=%d bytes (%.1f%%)",
			len(events), originalSize, compressedSize, compressionRatio)
	}

	// Determine agent type from first event
	agentType := "native"
	if len(events) > 0 {
		agentType = string(events[0].AgentType)
	}

	// Create batch params and marshal to JSON
	batchParams := client.SecurityEventsBatchParams{
		EventCount: len(events),
		Compressed: true,
		Payload:    payload,
		AgentType:  agentType,
	}
	paramsJSON, err := json.Marshal(batchParams)
	if err != nil {
		a.log.Err(err).Msg("agent.sendEventBatch - failed to marshal batch params")
		return err
	}

	msg := client.SecurityEventsBatchPost{
		ID:        "1",
		Version:   "1",
		Timestamp: time.Now().Unix(),
		Source:    a.AgentID,
		Tenant:    a.Subdomain,
		Subdomain: a.Subdomain,
		Method:    "security_events.batch_post",
		Params:    paramsJSON,
	}

	// Debug: log the params being sent
	a.log.Debug().
		Int("params_len", len(paramsJSON)).
		Int("event_count", len(events)).
		Msg("agent.sendEventBatch - sending batch with params")

	err = a.conn.SecurityEventsBatchPost(msg)
	if err != nil {
		if errors.Is(err, client.ErrNotConnected) {
			a.log.Warn().Msg("agent.sendEventBatch - not connected, events will be lost")
			return nil
		}
		a.log.Err(err).Msg("agent.sendEventBatch - error sending batch")
		return err
	}

	return nil
}

// Legacy single event sending (kept for backwards compatibility)
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

func (a *agent) updateNativeAgentServiceStatus() {
	if a.nativeAgent == nil {
		return
	}

	status, err := a.nativeAgent.GetServiceStatus()
	if err != nil {
		a.log.Warn().Err(err).Msg("agent.updateNativeAgentServiceStatus - failed to get service status")
		return
	}

	statusStr := "unknown"
	if status.Running {
		statusStr = "running"
	} else if status.ActiveState == "inactive" || status.ActiveState == "embedded" {
		statusStr = "stopped"
	} else if status.ActiveState != "" {
		statusStr = status.ActiveState + "/" + status.SubState
	}

	a.UpdateEBPFAgentServiceStatus("native", statusStr)
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
			CheckID:       "ebpf_agent.service_status",
			State:         status,
			InventoryData: paramsJSON,
		},
	}

	err = a.conn.CheckResultsPost(msg)
	if err != nil {
		a.log.Err(err).Msgf("agent.UpdateEBPFAgentServiceStatus - error sending status for %s", agentType)
	}
}

// GetNativeAgentInfo returns information about the native eBPF agent
func (a *agent) GetNativeAgentInfo() *ebpf.AgentInfo {
	if a.nativeAgent == nil {
		return nil
	}
	info := ebpf.GetInfo(a.nativeAgent)
	return &info
}

// EnableNativeAgent enables the native eBPF agent
func (a *agent) EnableNativeAgent() error {
	if a.nativeAgent == nil {
		return errors.New("native agent not initialized")
	}

	if err := a.nativeAgent.Start(a.ctx); err != nil {
		return err
	}

	return a.nativeAgent.StartEventListener(a.ctx)
}

// DisableNativeAgent disables the native eBPF agent
func (a *agent) DisableNativeAgent() error {
	if a.nativeAgent == nil {
		return errors.New("native agent not initialized")
	}

	if err := a.nativeAgent.StopEventListener(); err != nil {
		return err
	}

	return a.nativeAgent.Stop(a.ctx)
}

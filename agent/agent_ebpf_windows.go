//go:build windows

package agent

import (
	"context"

	"akagent/client"
	"akagent/ebpf"
	"akagent/winevt"
)

// platformAgentData holds the Windows security-event source. Windows has no
// eBPF; the winevt collector reads the Windows Event Log and produces the
// same ebpf.SecurityEvent values, drained by the shared event sender.
type platformAgentData struct {
	winCollector *winevt.Collector
}

func newPlatformAgentData() platformAgentData {
	return platformAgentData{}
}

// initEBPF starts the Windows Event Log collector. Named initEBPF for parity
// with the other platforms' agent seam; there is no eBPF involved.
func (a *agent) initEBPF(ctx context.Context) {
	a.log.Info().Msg("agent.initEBPF - starting Windows Event Log collector")
	c := winevt.NewCollector(1000)
	a.platformData.winCollector = c
	if err := c.Start(ctx); err != nil {
		a.log.Warn().Err(err).Msg("agent.initEBPF - failed to start Windows Event Log collector")
		a.platformData.winCollector = nil
	}
}

// securityEventChannel returns the collector's event channel for the shared
// sender, or nil if the collector failed to start.
func (a *agent) securityEventChannel() <-chan ebpf.SecurityEvent {
	if a.platformData.winCollector == nil {
		return nil
	}
	return a.platformData.winCollector.EventChannel()
}

// startEBPFSender launches the shared batch sender.
func (a *agent) startEBPFSender(shutdown chan struct{}) {
	a.wg.Add(1)
	go a.StartEBPFEventSender(shutdown, &a.wg)
}

// updateNativeAgentServiceStatus reports collector liveness to the endpoint,
// mirroring the eBPF agent's status heartbeat.
func (a *agent) updateNativeAgentServiceStatus() {
	if a.platformData.winCollector == nil {
		return
	}
	status := "stopped"
	if a.platformData.winCollector.IsRunning() {
		status = "running"
	}
	a.UpdateEBPFAgentServiceStatus("native", status)
}

// shutdownEBPF stops the collector.
func (a *agent) shutdownEBPF(ctx context.Context) {
	if a.platformData.winCollector != nil {
		if err := a.platformData.winCollector.Stop(ctx); err != nil {
			a.log.Warn().Err(err).Msg("agent.shutdownEBPF - error stopping Windows Event Log collector")
		}
	}
}

// onSystemInfo is a no-op on Windows (no stored native config yet).
func (a *agent) onSystemInfo(req client.Request) {}

// handleEBPFRequest dispatches the Windows-supported server requests. Config
// push for the collector (native_config.update etc.) is a follow-up; only
// self-update is wired today.
func (a *agent) handleEBPFRequest(req client.Request) bool {
	switch req.Method {
	case "update_agent":
		a.goHandle("update_agent", req, a.handleUpdateAgentRequest)
		return true
	}
	return false
}

//go:build !linux && !windows

package agent

import (
	"akagent/client"
	"context"
)

// platformAgentData is empty on non-Linux platforms (no eBPF support)
type platformAgentData struct{}

func newPlatformAgentData() platformAgentData {
	return platformAgentData{}
}

// initEBPF is a no-op on non-Linux platforms
func (a *agent) initEBPF(ctx context.Context) {
	a.log.Info().Msg("agent.initEBPF - eBPF not supported on this platform, skipping")
}

// startEBPFSender is a no-op on non-Linux platforms
func (a *agent) startEBPFSender(shutdown chan struct{}) {}

// shutdownEBPF is a no-op on non-Linux platforms
func (a *agent) shutdownEBPF(ctx context.Context) {}

// onSystemInfo is a no-op on non-Linux platforms
func (a *agent) onSystemInfo(req client.Request) {}

// handleEBPFRequest returns false on non-Linux platforms (no eBPF handlers)
func (a *agent) handleEBPFRequest(req client.Request) bool {
	return false
}

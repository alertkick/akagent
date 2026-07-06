//go:build linux

package agent

import (
	"akagent/ebpf"
	"errors"
)

// securityEventChannel returns the native eBPF agent's event channel, or nil
// if the agent failed to initialize. The shared event sender drains it.
func (a *agent) securityEventChannel() <-chan ebpf.SecurityEvent {
	if a.platformData.nativeAgent == nil {
		return nil
	}
	return a.platformData.nativeAgent.EventChannel()
}

func (a *agent) updateNativeAgentServiceStatus() {
	if a.platformData.nativeAgent == nil {
		return
	}

	status, err := a.platformData.nativeAgent.GetServiceStatus()
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

// GetNativeAgentInfo returns information about the native eBPF agent
func (a *agent) GetNativeAgentInfo() *ebpf.AgentInfo {
	if a.platformData.nativeAgent == nil {
		return nil
	}
	info := ebpf.GetInfo(a.platformData.nativeAgent)
	return &info
}

// EnableNativeAgent enables the native eBPF agent
func (a *agent) EnableNativeAgent() error {
	if a.platformData.nativeAgent == nil {
		return errors.New("native agent not initialized")
	}

	if err := a.platformData.nativeAgent.Start(a.ctx); err != nil {
		return err
	}

	return a.platformData.nativeAgent.StartEventListener(a.ctx)
}

// DisableNativeAgent disables the native eBPF agent
func (a *agent) DisableNativeAgent() error {
	if a.platformData.nativeAgent == nil {
		return errors.New("native agent not initialized")
	}

	if err := a.platformData.nativeAgent.StopEventListener(); err != nil {
		return err
	}

	return a.platformData.nativeAgent.Stop(a.ctx)
}

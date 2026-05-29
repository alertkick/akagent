//go:build linux

package agent

import (
	"akagent/agent/sshlockdown"
	"akagent/agent/sshlockdown/bpflsm"
	"akagent/client"
	"akagent/ebpf"
	"context"
	"sync"
)

// platformAgentData holds Linux-specific eBPF agent fields
type platformAgentData struct {
	nativeAgent               *ebpf.NativeEBPFAgent
	securityEventQueue        []ebpf.SecurityEvent
	securityEventQueueMutex   sync.Mutex
	securityEventMaxQueueSize int

	// lockdownManager owns the SSH lockdown / maintenance window state.
	// nil until initSSHLockdown runs; nil-safe in the request handlers.
	lockdownManager *sshlockdown.Manager

	// lockdownLSM is the concrete LSM-BPF blocker handle when that path
	// is active. The manager talks to the Blocker interface; we hold a
	// typed handle separately so the agent can call Stats() and inspect
	// kernel-side counters without going through Manager. Nil when the
	// host is on the TC or noop fallback.
	lockdownLSM *bpflsm.Blocker

	// lockdownPortsSetter abstracts SetPorts across LSM and TC blockers
	// so the sshd_config refresh callback works regardless of which
	// kernel path is active. Nil only when the NoopBlocker is selected.
	lockdownPortsSetter interface {
		SetPorts(ports []uint16) error
	}

	// lockdownBlockerMechanism + lockdownBlockerReason surface which
	// blocker is active and why. Echoed in the lockdown.get_state
	// response so the UI can tell the operator whether kernel-side
	// enforcement is actually in effect.
	lockdownBlockerMechanism string // "lsm-bpf" | "noop"
	lockdownBlockerReason    string
}

func newPlatformAgentData() platformAgentData {
	return platformAgentData{
		securityEventQueue:        make([]ebpf.SecurityEvent, 0, 1000),
		securityEventMaxQueueSize: 1000,
	}
}

// initEBPF initializes the native eBPF agent on Linux
func (a *agent) initEBPF(ctx context.Context) {
	a.log.Info().Msg("agent.Run - initializing native eBPF agent (disabled by default)")
	nativeAgent, err := ebpf.NewNativeAgent()
	if err != nil {
		a.log.Warn().Err(err).Msg("agent.Run - failed to create native eBPF agent")
		return
	}

	a.platformData.nativeAgent = nativeAgent

	// Start the SSH lockdown manager regardless of whether the native
	// eBPF agent is enabled — the lockdown state machine is independent
	// of the event-collection pipeline. (Once the LSM Blocker ships,
	// it'll require eBPF support; until then NoopBlocker has no kernel
	// dependency.)
	a.initSSHLockdown(ctx)

	// Only start if explicitly enabled in config (rare - usually profile triggers it)
	nativeConfig := a.platformData.nativeAgent.GetNativeConfig()
	if nativeConfig.Enabled {
		if err := a.platformData.nativeAgent.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("agent.Run - failed to start native eBPF agent")
		} else if err := a.platformData.nativeAgent.StartEventListener(ctx); err != nil {
			a.log.Warn().Err(err).Msg("agent.Run - failed to start native eBPF event listener")
		}
	} else {
		a.log.Info().Msg("agent.Run - eBPF agent initialized but not started (waiting for profile)")
	}
}

// startEBPFSender starts the eBPF event sender goroutine on Linux
func (a *agent) startEBPFSender(shutdown chan struct{}) {
	a.wg.Add(1)
	go a.StartEBPFEventSender(shutdown, &a.wg)
}

// shutdownEBPF stops the native eBPF agent on Linux
func (a *agent) shutdownEBPF(ctx context.Context) {
	a.log.Debug().Msg("agent.shutdownEBPF - shutting down native eBPF agent")
	if a.platformData.nativeAgent != nil {
		if err := a.platformData.nativeAgent.StopEventListener(); err != nil {
			a.log.Warn().Err(err).Msg("agent.shutdownEBPF - error stopping native eBPF event listener")
		}
		if err := a.platformData.nativeAgent.Stop(ctx); err != nil {
			a.log.Warn().Err(err).Msg("agent.shutdownEBPF - error stopping native eBPF agent")
		}
	}
}

// onSystemInfo is called after system.info is processed — fetches stored native config
func (a *agent) onSystemInfo(req client.Request) {
	if err := a.NativeConfigGetStored(); err != nil {
		a.log.Warn().Err(err).Msg("agent.onSystemInfo - failed to get stored native config")
	}
}

// handleEBPFRequest dispatches eBPF-specific server requests on Linux.
// Returns true if the method was handled.
func (a *agent) handleEBPFRequest(req client.Request) bool {
	// Any server-pushed request counts as a heartbeat for the lockdown
	// dead-man timer. Doing it here (rather than only on a dedicated
	// heartbeat method) means a quiet host that only gets the occasional
	// config push still keeps the lockdown active — the dead-man only
	// fires when the control plane is genuinely unreachable.
	if a.platformData.lockdownManager != nil {
		a.platformData.lockdownManager.Heartbeat()
	}

	switch req.Method {
	case "native_config.get":
		a.log.Debug().Msg("agent.HandleServerRequest - received native_config.get request")
		a.handleNativeConfigGetRequest(req)
	case "native_config.update":
		a.log.Debug().Msg("agent.HandleServerRequest - received native_config.update request")
		a.handleNativeConfigUpdateRequest(req)
	case "enable_native_agent":
		a.log.Debug().Msg("agent.HandleServerRequest - received enable_native_agent request")
		a.handleEnableNativeAgentRequest(req)
	case "disable_native_agent":
		a.log.Debug().Msg("agent.HandleServerRequest - received disable_native_agent request")
		a.handleDisableNativeAgentRequest(req)
	case "native_agent.status":
		a.log.Debug().Msg("agent.HandleServerRequest - received native_agent.status request")
		a.handleNativeAgentStatusRequest(req)
	case "refresh_native_config", "refresh_security_rules":
		// refresh_security_rules is the current name; refresh_native_config is the
		// older internal alias kept while the API is migrated.
		a.log.Debug().Str("method", req.Method).Msg("agent.HandleServerRequest - received refresh_native_config request")
		a.handleRefreshNativeConfigRequest(req)
	case "agent.refresh_compliance":
		a.log.Debug().Msg("agent.HandleServerRequest - received refresh_compliance request")
		a.handleRefreshComplianceRequest(req)
	case "native_rules.update":
		a.log.Debug().Msg("agent.HandleServerRequest - received native_rules.update request")
		a.handleNativeRulesUpdateRequest(req)
	case "update_agent":
		a.log.Info().Msg("agent.HandleServerRequest - received update_agent request")
		go a.handleUpdateAgentRequest(req)
	case "ssh_lockdown.get_state":
		a.log.Debug().Msg("agent.HandleServerRequest - received ssh_lockdown.get_state request")
		a.handleSSHLockdownGetStateRequest(req)
	case "ssh_lockdown.set":
		a.log.Info().Msg("agent.HandleServerRequest - received ssh_lockdown.set request")
		a.handleSSHLockdownSetRequest(req)
	case "ssh_lockdown.unlock":
		a.log.Info().Msg("agent.HandleServerRequest - received ssh_lockdown.unlock request")
		a.handleSSHLockdownUnlockRequest(req)
	case "ssh_lockdown.lock_now":
		a.log.Info().Msg("agent.HandleServerRequest - received ssh_lockdown.lock_now request")
		a.handleSSHLockdownLockNowRequest(req)
	default:
		return false
	}
	return true
}

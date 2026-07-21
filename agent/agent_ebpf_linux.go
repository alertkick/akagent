//go:build linux

package agent

import (
	"akagent/agent/responder"
	"akagent/agent/sshlockdown"
	"akagent/agent/sshlockdown/bpflsm"
	"akagent/client"
	"akagent/ebpf"
	"context"
	"sync"
	"sync/atomic"
	"time"
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

	// responder performs active-response enforcement (block IP / kill
	// process). Constructed lazily on first command (getResponder), then
	// live-updated via refreshResponderConfig when a new native config is
	// applied. responderMu guards the lazy init + the pointer.
	responder   *responder.Responder
	responderMu sync.Mutex
	// nativeConfigReceived flips true once the control plane's native config
	// has been applied at least once. Until then the responder falls back to
	// the RESPONSE_ENFORCE/RESPONSE_ALLOWLIST env vars (headless installs);
	// after, the pushed config is authoritative so the tenant kill switch and
	// per-host enforce toggle win.
	nativeConfigReceived atomic.Bool

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

	// scanStatusMu guards lastScanRescanAt, which records the last time a
	// re-lock transition triggered a FIM rebaseline. Written by the
	// lockdown ticker (via OnLockChange) and read by the status reporter.
	scanStatusMu     sync.Mutex
	lastScanRescanAt time.Time

	// lockdownApplied is the latest applied enforcement state (post
	// dead-man, including apply errors), written by the manager's
	// OnApplied callback and read by the mechanism/state reporter.
	// lockdownReportKick wakes the reporter for an immediate push on a
	// transition; buffered(1) + non-blocking send so the manager's run
	// loop never stalls on reporting.
	lockdownApplied    atomic.Pointer[sshlockdown.AppliedState]
	lockdownReportKick chan struct{}
}

func newPlatformAgentData() platformAgentData {
	return platformAgentData{
		securityEventQueue:        make([]ebpf.SecurityEvent, 0, 1000),
		securityEventMaxQueueSize: 1000,
		lockdownReportKick:        make(chan struct{}, 1),
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
		a.goHandle("native_config.get", req, a.handleNativeConfigGetRequest)
	case "native_config.update":
		a.goHandle("native_config.update", req, a.handleNativeConfigUpdateRequest)
	case "enable_native_agent":
		a.goHandle("enable_native_agent", req, a.handleEnableNativeAgentRequest)
	case "disable_native_agent":
		a.goHandle("disable_native_agent", req, a.handleDisableNativeAgentRequest)
	case "native_agent.status":
		a.goHandle("native_agent.status", req, a.handleNativeAgentStatusRequest)
	case "refresh_native_config", "refresh_security_rules":
		// refresh_security_rules is the current name; refresh_native_config is the
		// older internal alias kept while the API is migrated.
		a.goHandle(req.Method, req, a.handleRefreshNativeConfigRequest)
	case "agent.refresh_compliance":
		a.goHandle("agent.refresh_compliance", req, a.handleRefreshComplianceRequest)
	case "native_rules.update":
		a.goHandle("native_rules.update", req, a.handleNativeRulesUpdateRequest)
	case "update_agent":
		a.goHandle("update_agent", req, a.handleUpdateAgentRequest)
	case "ssh_lockdown.get_state":
		a.goHandle("ssh_lockdown.get_state", req, a.handleSSHLockdownGetStateRequest)
	case "ssh_lockdown.set":
		a.goHandle("ssh_lockdown.set", req, a.handleSSHLockdownSetRequest)
	case "ssh_lockdown.unlock":
		a.goHandle("ssh_lockdown.unlock", req, a.handleSSHLockdownUnlockRequest)
	case "ssh_lockdown.lock_now":
		a.goHandle("ssh_lockdown.lock_now", req, a.handleSSHLockdownLockNowRequest)
	case "fim.approve_paths":
		a.goHandle("fim.approve_paths", req, a.handleFIMApprovePathsRequest)
	case "fim.rebaseline":
		a.goHandle("fim.rebaseline", req, a.handleFIMRebaselineRequest)
	case "yara.sync_rules":
		a.goHandle("yara.sync_rules", req, a.handleYaraSyncRulesRequest)
	case "response.block_ip":
		a.goHandle("response.block_ip", req, a.handleResponseBlockIPRequest)
	case "response.unblock_ip":
		a.goHandle("response.unblock_ip", req, a.handleResponseUnblockIPRequest)
	case "response.kill_process":
		a.goHandle("response.kill_process", req, a.handleResponseKillProcessRequest)
	default:
		return false
	}
	return true
}

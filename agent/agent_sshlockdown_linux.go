//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"akagent/agent/sshlockdown"
	"akagent/client"
	"akagent/ebpf"

	"github.com/rs/zerolog"
)

// SSH lockdown wire shapes — kept in this file because the alertkick-api
// side has matching structs and we want both sides to evolve together
// when the protocol changes. A new field added on one side won't break
// the other (encoding/json ignores unknown fields by default), but a
// rename will. Run `grep -rn ssh_lockdown.set` across both repos when
// touching these.

type lockdownStateResponse struct {
	Status string `json:"status"` // "success" or "failed"
	Error  string `json:"error,omitempty"`

	// Current decision — what the operator actually wants to see in the UI.
	Locked       bool      `json:"locked"`
	ReleaseUntil time.Time `json:"release_until,omitempty"`
	NextChangeAt time.Time `json:"next_change_at,omitempty"`

	// BlockerMechanism reports whether kernel-side enforcement is
	// active. Values: "lsm-bpf" (real block, sshd accept() returns
	// -EPERM) or "noop" (state-only, sshd still accepts everything).
	// BlockerReason explains the choice — helpful when the UI surfaces
	// "this lockdown is not actually blocking SSH on this host".
	BlockerMechanism string `json:"blocker_mechanism,omitempty"`
	BlockerReason    string `json:"blocker_reason,omitempty"`

	// Echo of the persisted state. Lets the UI render the schedule editor
	// without a second round trip.
	State sshlockdown.State `json:"state"`
}

type lockdownSetRequest struct {
	State sshlockdown.State `json:"state"`
}

type lockdownUnlockRequest struct {
	DurationSeconds int    `json:"duration_seconds"`
	UpdatedBy       string `json:"updated_by"`
}

type lockdownLockNowRequest struct {
	UpdatedBy string `json:"updated_by"`
}

// initSSHLockdown constructs the lockdown manager and starts its run
// loop. Called once at agent startup, after the eBPF agent is up so
// the LSM Blocker (if available) attaches alongside the rest of the
// BPF infrastructure.
//
// Blocker selection happens through sshlockdown.SelectBlocker, which
// probes the kernel and returns either the LSM-BPF implementation or
// the NoopBlocker fallback. The selection's DiagnosticReason is logged
// so an operator can immediately see why a given host is on the
// fallback (kernel cmdline missing lsm=bpf, BPF_LSM not built in,
// program load failed, etc.).
func (a *agent) initSSHLockdown(ctx context.Context) {
	if a.platformData.lockdownManager != nil {
		return
	}

	selection := sshlockdown.SelectBlocker()
	a.log.Info().
		Str("mechanism", selection.Mechanism).
		Str("reason", selection.DiagnosticReason).
		Msg("agent.initSSHLockdown - blocker selected")
	a.platformData.lockdownBlockerMechanism = selection.Mechanism
	a.platformData.lockdownBlockerReason = selection.DiagnosticReason
	a.platformData.lockdownLSM = selection.LSMBlocker()
	a.platformData.lockdownPortsSetter = selection.PortsSetter()

	// Push the mechanism to the server so the UI can render a badge
	// without polling each agent over WebSocket on every page load.
	// Best-effort — the agent's local state is still authoritative, the
	// server-side record is for UX. We retry once a minute until the
	// first push succeeds (covers the "server unreachable at boot" case)
	// and then refresh hourly so an operator who wipes a host record
	// from MongoDB sees the agent re-populate within an hour.
	go a.runLockdownMechanismReporter(ctx)

	// 10-minute dead-man matches the design doc; matches what we tell
	// operators in the help text. If you change this, change both.
	mgr, err := sshlockdown.NewManager(selection.Blocker, sshlockdown.Options{
		StatePath:        sshlockdown.DefaultStatePath,
		Now:              time.Now,
		DeadManThreshold: 10 * time.Minute,
		MinTickInterval:  30 * time.Second,
		Logger:           zerologAdapter{log: a.log.With().Str("subsystem", "ssh_lockdown").Logger()},
		OnLockChange:     a.onLockStateChange(),
	})
	if err != nil {
		a.log.Warn().Err(err).Msg("agent.initSSHLockdown - failed to construct manager")
		_ = selection.Blocker.Close()
		return
	}
	a.platformData.lockdownManager = mgr

	// Feed the SSH session tracker the trusted source-IP allowlist so a login
	// from an address not on the list is classified "untrusted" and alerts at
	// connect time. Two sources contribute, unioned: the lockdown bypass list
	// (mgr.State().AllowedSourceIPs, also used for kernel-side blocking) and the
	// ac-007 alerting allowlist pushed via native config. The latter lets an
	// operator who only wants alerting (no lockdown enforcement) still get the
	// trusted/untrusted classification — without it the badge stays "unverified"
	// unless lockdown is configured. Empty union → "unverified" (no policy).
	if na := a.platformData.nativeAgent; na != nil {
		na.SetSSHAllowlistFunc(func() []string {
			return unionSourceIPs(mgr.State().AllowedSourceIPs, na.GetNativeConfig().SSHAllowedSourceIPs)
		})
	}

	// Seed the BPF map with the host's sshd ports on startup AND
	// subscribe to subsequent refreshes — the sshd_config reader inside
	// the eBPF agent owns the live snapshot; we get a callback after
	// every successful refresh so the kernel map tracks operator edits
	// (e.g. `Port 2222` added, systemctl reload ssh) without an agent
	// restart. Works for both LSM and TC paths because both Blocker
	// implementations satisfy the portsSetter interface.
	if a.platformData.lockdownPortsSetter != nil && a.platformData.nativeAgent != nil {
		setter := a.platformData.lockdownPortsSetter
		seed := func(snap *ebpf.SSHDConfig) {
			if snap == nil {
				return
			}
			ports := make([]uint16, 0, len(snap.Ports))
			for _, p := range snap.Ports {
				ports = append(ports, uint16(p))
			}
			if err := setter.SetPorts(ports); err != nil {
				a.log.Warn().Err(err).Msg("agent.initSSHLockdown - SetPorts failed")
			}
		}
		seed(a.platformData.nativeAgent.SSHDConfigSnapshot())
		a.platformData.nativeAgent.OnSSHDConfigRefresh(seed)
	}

	go mgr.Run(ctx)

	// Report FIM/YARA scan status to the server so the File Integrity tab
	// can show whether the baseline + malware ruleset are built and how the
	// host's lock state is gating integrity monitoring. Lock transitions push
	// out-of-band (OnLockChange); this loop is the periodic refresh.
	go a.runSecurityScanStatusReporter(ctx)
}

// lockdownReportPayload is the wire shape consumed by the endpoint's
// SSHLockdownReportHandler. Keep this struct in sync with
// akagent-endpoint/agent/sshLockdownReportHandler.go — both sides
// serialise the same JSON shape, and a field rename here without the
// matching endpoint change is a silent data-loss bug.
type lockdownReportPayload struct {
	Mechanism string `json:"mechanism"`
	Reason    string `json:"reason"`
}

// runLockdownMechanismReporter retries the initial mechanism push every
// minute until it succeeds, then refreshes hourly. Hourly is "stale
// detection" pacing for the UI — a host whose mechanism updated_at is
// >2h old means the agent is dead and the displayed mechanism is no
// longer trustworthy.
//
// Why a goroutine and not inline in initSSHLockdown: the agent's
// WebSocket may not be connected when initSSHLockdown runs (agent boots
// before the connection is up). The reporter loop is shutdown-aware
// via ctx so agent shutdown stops the retries cleanly.
func (a *agent) runLockdownMechanismReporter(ctx context.Context) {
	initialBackoff := time.Minute
	steady := time.Hour

	// First attempt — gives the connection a few seconds to come up
	// without the operator seeing a missed-push warning on every boot.
	select {
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Second):
	}

	for {
		if err := a.pushLockdownMechanism(); err == nil {
			break
		} else {
			a.log.Debug().Err(err).Msg("agent.runLockdownMechanismReporter - initial push failed, will retry")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(initialBackoff):
		}
	}

	ticker := time.NewTicker(steady)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.pushLockdownMechanism(); err != nil {
				a.log.Debug().Err(err).Msg("agent.runLockdownMechanismReporter - refresh push failed")
			}
		}
	}
}

// pushLockdownMechanism is a fire-and-forget agent → server message.
// The endpoint persists the values on the host record; we don't block
// on the response because nothing on the agent side acts on it. We use
// SendJSONMessage (agent-initiated request) and discard the response
// channel — SendJSONMessageNoResponse is for server-request acks and
// expects a client.Response, not a Request.
func (a *agent) pushLockdownMechanism() error {
	payload, err := json.Marshal(lockdownReportPayload{
		Mechanism: a.platformData.lockdownBlockerMechanism,
		Reason:    a.platformData.lockdownBlockerReason,
	})
	if err != nil {
		return err
	}
	msg := &client.Request{
		Version:   "1",
		ID:        "1",
		Target:    "endpoint",
		Source:    a.AgentID,
		Tenant:    a.Subdomain,
		Subdomain: a.Subdomain,
		Method:    "ssh_lockdown.report_mechanism",
		Params:    payload,
	}
	_, _, err = a.conn.SendJSONMessage(msg)
	return err
}

// UpdateSSHLockdownPorts is called by the sshd_config refresh ticker so
// the kernel blocker's port-set map tracks live config changes. No-op
// when the host is on the NoopBlocker (no kernel enforcement active).
func (a *agent) UpdateSSHLockdownPorts(ports []uint16) {
	if a.platformData.lockdownPortsSetter == nil {
		return
	}
	if err := a.platformData.lockdownPortsSetter.SetPorts(ports); err != nil {
		a.log.Warn().Err(err).Msg("agent.UpdateSSHLockdownPorts - failed")
	}
}

// handleSSHLockdownGetStateRequest returns the current lockdown decision.
// Read-only; never persists. Used by the UI to populate the
// MaintenanceTab without performing any state mutation.
func (a *agent) handleSSHLockdownGetStateRequest(req client.Request) {
	resp := lockdownStateResponse{Status: "success"}
	if mgr := a.platformData.lockdownManager; mgr != nil {
		a.fillLockdownState(mgr, &resp)
	} else {
		// Manager not initialised on this host (Windows agent, eBPF disabled).
		// Treat as "locked, no schedule" — keeps the UI rendering sane.
		resp.Locked = true
		resp.BlockerMechanism = a.platformData.lockdownBlockerMechanism
		resp.BlockerReason = a.platformData.lockdownBlockerReason
	}
	a.sendLockdownResponse(req, resp)
}

// handleSSHLockdownSetRequest replaces the full state — schedule,
// allowlist, ad-hoc release. Validated before persist; an invalid
// payload echoes back as status=failed with the validation message.
func (a *agent) handleSSHLockdownSetRequest(req client.Request) {
	resp := lockdownStateResponse{Status: "success"}
	var body lockdownSetRequest
	if err := json.Unmarshal(req.Params, &body); err != nil {
		resp.Status = "failed"
		resp.Error = "parse: " + err.Error()
		a.sendLockdownResponse(req, resp)
		return
	}

	mgr := a.platformData.lockdownManager
	if mgr == nil {
		resp.Status = "failed"
		resp.Error = "lockdown manager not initialised on this host"
		a.sendLockdownResponse(req, resp)
		return
	}
	if err := mgr.SetState(body.State); err != nil {
		resp.Status = "failed"
		resp.Error = err.Error()
		a.sendLockdownResponse(req, resp)
		return
	}
	a.fillLockdownState(mgr, &resp)
	a.sendLockdownResponse(req, resp)
}

// handleSSHLockdownUnlockRequest pushes ReleaseUntil forward by the
// requested duration. Idempotent for repeated calls during the same
// window — extension never shortens an active unlock (see
// Manager.Unlock).
func (a *agent) handleSSHLockdownUnlockRequest(req client.Request) {
	resp := lockdownStateResponse{Status: "success"}
	var body lockdownUnlockRequest
	if err := json.Unmarshal(req.Params, &body); err != nil {
		resp.Status = "failed"
		resp.Error = "parse: " + err.Error()
		a.sendLockdownResponse(req, resp)
		return
	}
	if body.DurationSeconds <= 0 {
		resp.Status = "failed"
		resp.Error = "duration_seconds must be positive"
		a.sendLockdownResponse(req, resp)
		return
	}

	mgr := a.platformData.lockdownManager
	if mgr == nil {
		resp.Status = "failed"
		resp.Error = "lockdown manager not initialised on this host"
		a.sendLockdownResponse(req, resp)
		return
	}
	if _, err := mgr.Unlock(time.Duration(body.DurationSeconds)*time.Second, body.UpdatedBy); err != nil {
		resp.Status = "failed"
		resp.Error = err.Error()
		a.sendLockdownResponse(req, resp)
		return
	}
	a.fillLockdownState(mgr, &resp)
	a.sendLockdownResponse(req, resp)
}

// handleSSHLockdownLockNowRequest clears any active unlock. The next
// scheduled window opens normally — LockNow doesn't disable the
// schedule, only the ad-hoc release.
func (a *agent) handleSSHLockdownLockNowRequest(req client.Request) {
	resp := lockdownStateResponse{Status: "success"}
	var body lockdownLockNowRequest
	// LockNow takes no required fields; ignore parse errors when the
	// body is empty or just {}.
	_ = json.Unmarshal(req.Params, &body)

	mgr := a.platformData.lockdownManager
	if mgr == nil {
		resp.Status = "failed"
		resp.Error = "lockdown manager not initialised on this host"
		a.sendLockdownResponse(req, resp)
		return
	}
	if err := mgr.LockNow(body.UpdatedBy); err != nil {
		resp.Status = "failed"
		resp.Error = err.Error()
		a.sendLockdownResponse(req, resp)
		return
	}
	a.fillLockdownState(mgr, &resp)
	a.sendLockdownResponse(req, resp)
}

func (a *agent) fillLockdownState(mgr *sshlockdown.Manager, resp *lockdownStateResponse) {
	state := mgr.State()
	decision := sshlockdown.Evaluate(state, time.Now())
	resp.State = state
	resp.Locked = decision.Locked
	resp.ReleaseUntil = decision.ReleaseUntil
	resp.NextChangeAt = decision.NextChangeAt
	resp.BlockerMechanism = a.platformData.lockdownBlockerMechanism
	resp.BlockerReason = a.platformData.lockdownBlockerReason
}

func (a *agent) sendLockdownResponse(req client.Request, response lockdownStateResponse) {
	result, err := json.Marshal(response)
	if err != nil {
		a.log.Err(err).Msg("agent.sendLockdownResponse - error marshalling response")
		return
	}
	resp := client.Response{
		ID:            req.ID,
		Version:       "1",
		Target:        req.Source,
		Source:        a.AgentID,
		Tenant:        a.Subdomain,
		Subdomain:     a.Subdomain,
		Result:        result,
		CorrelationID: req.CorrelationID,
	}
	if err := a.conn.SendJSONMessageNoResponse(resp); err != nil {
		a.log.Err(err).Msg("agent.sendLockdownResponse - error sending response")
	}
}

// zerologAdapter adapts a zerolog.Logger to the sshlockdown.Logger
// interface. Keeps sshlockdown free of the zerolog dependency so it
// stays testable in isolation.
type zerologAdapter struct{ log zerolog.Logger }

func (z zerologAdapter) Warnf(format string, args ...interface{}) {
	z.log.Warn().Msgf(format, args...)
}
func (z zerologAdapter) Infof(format string, args ...interface{}) {
	z.log.Info().Msgf(format, args...)
}

// unionSourceIPs merges the SSH source-IP allowlists from the lockdown bypass
// list and the ac-007 alerting allowlist into one deduped slice. Order is
// stable (lockdown entries first) and empty/blank entries are dropped. Returns
// nil when both inputs are empty so the tracker classifies "unverified".
func unionSourceIPs(lists ...[]string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, list := range lists {
		for _, ip := range list {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			if _, dup := seen[ip]; dup {
				continue
			}
			seen[ip] = struct{}{}
			out = append(out, ip)
		}
	}
	return out
}

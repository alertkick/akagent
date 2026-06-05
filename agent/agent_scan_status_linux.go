//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"time"

	"akagent/agent/sshlockdown"
	"akagent/client"
)

// securityScanStatusPayload is the wire shape consumed by the endpoint's
// SecurityScanStatusReportHandler. Keep this struct in sync with
// akagent-endpoint/agent/securityScanStatusReportHandler.go — both sides
// serialise the same JSON, and a field rename here without the matching
// endpoint change is a silent data-loss bug.
//
// It tells the UI two things it has no other way to know:
//   - whether the FIM baseline and YARA ruleset ("malware database") are
//     actually built and ready on the host, and
//   - the current lock state, which governs how file drift is treated:
//     while the host is unlocked (a maintenance window), FIM changes are
//     expected and suppressed, and the baseline is re-taken when it relocks.
type securityScanStatusPayload struct {
	// FIM — checksum baseline of /etc + system binaries.
	FIMEnabled        bool      `json:"fim_enabled"`
	FIMReady          bool      `json:"fim_ready"`
	FIMFileCount      int       `json:"fim_file_count"`
	FIMHashAlgo       string    `json:"fim_hash_algo,omitempty"`
	FIMMonitoredRoots []string  `json:"fim_monitored_roots,omitempty"`
	FIMLastBaselineAt time.Time `json:"fim_last_baseline_at,omitempty"`

	// YARA — malware-signature scanning. "Available" means the agent has
	// both the yara binary and a synced ruleset on disk.
	YaraEnabled       bool      `json:"yara_enabled"`
	YaraAvailable     bool      `json:"yara_available"`
	YaraBinaryPath    string    `json:"yara_binary_path,omitempty"`
	YaraBinaryPresent bool      `json:"yara_binary_present"`
	YaraRulesPath     string    `json:"yara_rules_path,omitempty"`
	YaraRulesHash     string    `json:"yara_rules_hash,omitempty"`
	YaraRulesSyncedAt time.Time `json:"yara_rules_synced_at,omitempty"`

	// Lock-gated rescan relationship.
	Locked       bool      `json:"locked"`
	LastRescanAt time.Time `json:"last_rescan_at,omitempty"`
}

// onLockStateChange returns the OnLockChange callback handed to the lockdown
// manager. It drives the FIM/lock relationship: while the host is unlocked
// (a maintenance window) FIM treats file changes as expected; when the host
// re-locks it re-baselines so post-maintenance drift is measured from the new
// known-good state. The first invocation only seeds suppression — it must not
// trigger a rebaseline, because FIM already built its baseline at startup.
func (a *agent) onLockStateChange() func(bool) {
	firstEval := true
	return func(locked bool) {
		na := a.platformData.nativeAgent
		if na != nil {
			na.SetMaintenanceSuppression(!locked)
		}
		switch {
		case firstEval:
			firstEval = false
			a.log.Info().Bool("locked", locked).
				Msg("agent.onLockStateChange - seeded FIM maintenance suppression")
		case locked:
			// Unlock/maintenance window just closed — accept current disk
			// state as the new known-good baseline so post-maintenance drift
			// is measured from here onward.
			a.log.Info().Msg("agent.onLockStateChange - host re-locked, rebaselining FIM")
			if na != nil {
				go na.FIMRebaseline()
			}
			a.platformData.scanStatusMu.Lock()
			a.platformData.lastScanRescanAt = time.Now()
			a.platformData.scanStatusMu.Unlock()
		default:
			a.log.Info().Msg("agent.onLockStateChange - host unlocked, FIM changes now treated as expected")
		}
		// Push fresh status so the UI reflects the transition promptly.
		go func() {
			if err := a.pushSecurityScanStatus(); err != nil {
				a.log.Debug().Err(err).Msg("agent.onLockStateChange - status push failed")
			}
		}()
	}
}

// runSecurityScanStatusReporter pushes the FIM/YARA scan status to the server
// on startup (retrying until the WebSocket is up) and then every 15 minutes.
// Lock transitions push out-of-band via onLockStateChange, so the periodic
// refresh mainly keeps the baseline file-count / YARA rules hash fresh and
// lets the UI detect a dead agent via a stale reported_at.
func (a *agent) runSecurityScanStatusReporter(ctx context.Context) {
	// Give the connection a few seconds to come up after boot.
	select {
	case <-ctx.Done():
		return
	case <-time.After(7 * time.Second):
	}

	for {
		if err := a.pushSecurityScanStatus(); err == nil {
			break
		} else {
			a.log.Debug().Err(err).Msg("agent.runSecurityScanStatusReporter - initial push failed, will retry")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
	}

	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.pushSecurityScanStatus(); err != nil {
				a.log.Debug().Err(err).Msg("agent.runSecurityScanStatusReporter - refresh push failed")
			}
		}
	}
}

// buildScanStatusPayload assembles the current FIM + YARA + lock snapshot.
func (a *agent) buildScanStatusPayload() securityScanStatusPayload {
	var p securityScanStatusPayload

	if na := a.platformData.nativeAgent; na != nil {
		f := na.FIMStatusReport()
		p.FIMEnabled = f.Enabled
		p.FIMReady = f.Ready
		p.FIMFileCount = f.FileCount
		p.FIMHashAlgo = f.HashAlgo
		p.FIMMonitoredRoots = f.Roots
		p.FIMLastBaselineAt = f.LastBaselineAt

		y := na.YaraStatusReport()
		p.YaraEnabled = y.Enabled
		p.YaraAvailable = y.Available
		p.YaraBinaryPath = y.BinaryPath
		p.YaraBinaryPresent = y.BinaryPresent
		p.YaraRulesPath = y.RulesPath
		p.YaraRulesHash = y.RulesHash
		p.YaraRulesSyncedAt = y.RulesSyncedAt
	}

	if mgr := a.platformData.lockdownManager; mgr != nil {
		p.Locked = sshlockdown.Evaluate(mgr.State(), time.Now()).Locked
	} else {
		// No manager (eBPF disabled) — default to locked, the safe state.
		p.Locked = true
	}

	a.platformData.scanStatusMu.Lock()
	p.LastRescanAt = a.platformData.lastScanRescanAt
	a.platformData.scanStatusMu.Unlock()

	return p
}

// pushSecurityScanStatus is a fire-and-forget agent → server message; the
// endpoint persists the values on the host record. Mirrors
// pushLockdownMechanism — we use SendJSONMessage (agent-initiated request)
// and discard the response because nothing on the agent acts on it.
func (a *agent) pushSecurityScanStatus() error {
	payload, err := json.Marshal(a.buildScanStatusPayload())
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
		Method:    "security_scan.report_status",
		Params:    payload,
	}
	_, _, err = a.conn.SendJSONMessage(msg)
	return err
}

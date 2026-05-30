//go:build linux

package ebpf

import (
	"fmt"
	"time"

	"akagent/agent/authmonitor"

	"github.com/rs/xid"
)

// initAuthMonitor starts the auth-log brute-force monitor. It tails the system
// auth log and emits a finding when failed logins from one source cross a
// threshold. No-op if already running or if no auth log exists on this host.
func (a *NativeEBPFAgent) initAuthMonitor() {
	if a.authMonitor != nil {
		return
	}
	a.authMonitor = authmonitor.New(authmonitor.Config{}, func(f authmonitor.Finding) {
		ev := buildBruteForceEvent(f)
		select {
		case a.eventChan <- ev:
		default:
			nativeLog.Warn().Msg("Event channel full, dropping brute-force event")
		}
	})
	a.authMonitor.Start()
	nativeLog.Info().Msg("Auth-log brute-force monitor started")
}

// buildBruteForceEvent turns an authmonitor.Finding into a high-severity
// security event. SSH brute force carries the source IP; sudo brute force
// carries the invoking user.
func buildBruteForceEvent(f authmonitor.Finding) SecurityEvent {
	rule := "SSH Brute Force"
	if f.Kind == authmonitor.KindSudoBruteForce {
		rule = "Sudo Brute Force"
	}
	net := NetworkInfo{}
	if f.Kind == authmonitor.KindSSHBruteForce {
		net.SrcIP = f.Source
	}
	return SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  PriorityError,
		Rule:      rule,
		Source:    "authmonitor",
		Category:  "auth",
		Output:    fmt.Sprintf("%d failed logins from %s within %ds (user %s)", f.Count, f.Source, f.Window, f.User),
		Process:   ProcessInfo{Name: string(f.Kind), Username: f.User},
		Network:   net,
		RawFields: map[string]interface{}{
			"brute_force_kind": string(f.Kind),
			"source":           f.Source,
			"user":             f.User,
			"failure_count":    f.Count,
			"window_seconds":   f.Window,
		},
	}
}

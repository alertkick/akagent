//go:build linux

package ebpf

import (
	"time"

	"akagent/agent/rootkitscan"

	"github.com/rs/xid"
)

// initRootkitScanner starts the periodic rootkit-indicator scanner (hidden
// kernel modules, hidden processes, ld.so.preload). No-op if already running.
func (a *NativeEBPFAgent) initRootkitScanner() {
	if a.rootkitScanner != nil {
		return
	}
	a.rootkitScanner = rootkitscan.New(rootkitscan.Config{}, func(f rootkitscan.Finding) {
		ev := buildRootkitEvent(f)
		select {
		case a.eventChan <- ev:
		default:
			nativeLog.Warn().Msg("Event channel full, dropping rootkit event")
		}
	})
	a.rootkitScanner.Start()
	nativeLog.Info().Msg("Rootkit indicator scanner started")
}

// buildRootkitEvent turns a rootkitscan.Finding into a security event. Hidden
// modules/processes are Critical; an active ld.so.preload is High (it has rare
// legitimate uses, so it's surfaced for review rather than treated as certain).
func buildRootkitEvent(f rootkitscan.Finding) SecurityEvent {
	var rule, output string
	priority := PriorityCritical
	switch f.Kind {
	case rootkitscan.KindHiddenModule:
		rule = "Hidden Kernel Module"
		output = "Kernel module loaded but hidden from /proc/modules: " + f.Detail
	case rootkitscan.KindHiddenProcess:
		rule = "Hidden Process"
		output = "Process accessible but hidden from /proc listing: " + f.Detail
	case rootkitscan.KindPreload:
		rule = "ld.so.preload Rootkit Indicator"
		output = "Active /etc/ld.so.preload: " + f.Detail
		priority = PriorityError
	default:
		rule = "Rootkit Indicator"
		output = f.Detail
	}
	ev := SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  priority,
		Rule:      rule,
		Source:    "rootkitscan",
		Category:  "rootkit",
		Output:    output,
		RawFields: map[string]interface{}{
			"rootkit_kind": string(f.Kind),
			"detail":       f.Detail,
		},
	}
	if f.PID > 0 {
		ev.Process = ProcessInfo{PID: f.PID}
		ev.RawFields["pid"] = f.PID
	}
	return ev
}

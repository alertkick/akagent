//go:build linux

package ebpf

import (
	"os"
	"strings"
	"time"

	"akagent/agent/yarascan"

	"github.com/rs/xid"
)

// initYara starts the YARA scanner if YARA_RULES_PATH is set and the yara
// binary is available. Optional YARA_BIN overrides the binary path. No-op
// otherwise.
func (a *NativeEBPFAgent) initYara() {
	if a.yaraScanner != nil {
		return
	}
	a.yaraScanner = yarascan.New(yarascan.Config{
		RulesPath: os.Getenv("YARA_RULES_PATH"),
		Binary:    os.Getenv("YARA_BIN"),
	}, func(m yarascan.Match) {
		ev := buildYaraEvent(m)
		select {
		case a.eventChan <- ev:
		default:
			nativeLog.Warn().Msg("Event channel full, dropping YARA event")
		}
	})
	if a.yaraScanner.Available() {
		a.yaraScanner.Start()
		nativeLog.Info().Msg("YARA malware scanner started")
	}
}

// yaraScan queues a file path for YARA scanning. No-op when the scanner isn't
// configured/available. Used for both executables (on exec) and files the
// integrity monitor reports as changed.
func (a *NativeEBPFAgent) yaraScan(path string) {
	if a.yaraScanner != nil {
		a.yaraScanner.ScanAsync(path)
	}
}

// buildYaraEvent turns a YARA match into a Critical security event.
func buildYaraEvent(m yarascan.Match) SecurityEvent {
	return SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  PriorityCritical,
		Rule:      "YARA Match",
		Source:    "yarascan",
		Category:  "malware",
		Output:    "YARA rules matched " + m.Path + ": " + strings.Join(m.Rules, ", "),
		File:      FileInfo{Path: m.Path},
		RawFields: map[string]interface{}{
			"path":         m.Path,
			"yara_rules":   m.Rules,
			"matched_rule": firstOr(m.Rules, ""),
		},
	}
}

func firstOr(s []string, d string) string {
	if len(s) > 0 {
		return s[0]
	}
	return d
}

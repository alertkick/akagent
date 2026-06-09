//go:build linux

package ebpf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"akagent/agent/yarascan"
	"akagent/agent/yarasync"

	"github.com/rs/xid"
)

// initYara starts the YARA scanner and (when configured) the rules-sync loop.
// The scanner worker always runs; it stays dormant until a ruleset is present
// — either a static YARA_RULES_PATH file or one pulled by the syncer. The yara
// binary is taken from YARA_BIN, else the bundled/PATH "yara".
func (a *NativeEBPFAgent) initYara() {
	if a.yaraScanner != nil {
		return
	}
	rulesPath := os.Getenv("YARA_RULES_PATH")
	if rulesPath == "" {
		rulesPath = yarascan.DefaultRulesPath
	}
	a.yaraScanner = yarascan.New(yarascan.Config{
		RulesPath: rulesPath,
		Binary:    os.Getenv("YARA_BIN"),
	}, func(m yarascan.Match) {
		ev := buildYaraEvent(m)
		select {
		case a.eventChan <- ev:
		default:
			a.recordDroppedEvent()
		}
	})
	a.yaraScanner.Start()

	// Optional rules-sync: pull the curated + tenant-custom ruleset from the
	// control plane and hot-swap it in (the scanner re-checks availability on
	// each update).
	if url := os.Getenv("YARA_SYNC_URL"); url != "" {
		a.yaraSyncer = yarasync.New(yarasync.Config{
			URL:       url,
			Token:     os.Getenv("YARA_SYNC_TOKEN"),
			RulesPath: rulesPath,
		}, func(p string) {
			a.yaraScanner.SetRules(p)
			nativeLog.Info().Msg("YARA ruleset updated")
		})
		a.yaraSyncer.Start()
	}
	nativeLog.Info().Bool("available", a.yaraScanner.Available()).Str("rules", rulesPath).Msg("YARA scanner initialized")
}

// YaraApplyRules writes a pushed ruleset bundle to the scanner's rules file
// and hot-swaps it in, the same way the optional HTTP syncer would. Used by
// the yara.sync_rules command so the control plane can deliver the curated +
// tenant ruleset over the authenticated command channel without distributing
// an API key to every host. The write is atomic (temp file + rename) so the
// scanner never reads a half-written ruleset.
func (a *NativeEBPFAgent) YaraApplyRules(content string) error {
	if a.yaraScanner == nil {
		return fmt.Errorf("yara scanner not initialized")
	}
	if strings.TrimSpace(content) == "" {
		return fmt.Errorf("empty ruleset")
	}
	path := a.yaraScanner.RulesPath()
	if path == "" {
		path = yarascan.DefaultRulesPath
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create rules dir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write rules: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("swap rules: %w", err)
	}
	a.yaraScanner.SetRules(path)
	nativeLog.Info().Str("rules", path).Bool("available", a.yaraScanner.Available()).Msg("YARA ruleset applied from control plane")
	return nil
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

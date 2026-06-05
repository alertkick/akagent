//go:build linux

package ebpf

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"time"
)

// FIMStatusInfo is a snapshot of the file-integrity baseline state, surfaced
// to the control plane so the UI can show whether the baseline has been built.
type FIMStatusInfo struct {
	Enabled        bool
	Ready          bool
	FileCount      int
	HashAlgo       string
	Roots          []string
	LastBaselineAt time.Time
	Maintenance    bool
}

// YaraStatusInfo is a snapshot of the YARA scanner state. "Available" means
// the agent has both a yara binary and a synced ruleset on disk — the
// equivalent of "the malware database is built and ready". RulesHash is the
// SHA-256 of the active ruleset (the content the agent actually scans with),
// and RulesSyncedAt is the ruleset file's mtime (when it was last written by
// the rules-sync loop or installed).
type YaraStatusInfo struct {
	Enabled       bool
	Available     bool
	BinaryPath    string
	BinaryPresent bool
	RulesPath     string
	RulesHash     string
	RulesSyncedAt time.Time
}

// FIMStatusReport returns the current FIM baseline status. When FIM is
// disabled (no manager), Enabled is false and the rest is zero.
func (a *NativeEBPFAgent) FIMStatusReport() FIMStatusInfo {
	if a.fimManager == nil {
		return FIMStatusInfo{Enabled: false}
	}
	st := a.fimManager.Status()
	return FIMStatusInfo{
		Enabled:        true,
		Ready:          st.Ready,
		FileCount:      st.FileCount,
		HashAlgo:       st.HashAlgo,
		Roots:          st.Roots,
		LastBaselineAt: st.LastBaselineAt,
		Maintenance:    st.Maintenance,
	}
}

// YaraStatusReport returns the current YARA scanner status, reading the active
// ruleset file to compute its hash and last-modified time. Reads are cheap and
// infrequent (status reporting only), so we hash on demand rather than caching.
func (a *NativeEBPFAgent) YaraStatusReport() YaraStatusInfo {
	if a.yaraScanner == nil {
		return YaraStatusInfo{Enabled: false}
	}
	info := YaraStatusInfo{
		Enabled:    true,
		Available:  a.yaraScanner.Available(),
		BinaryPath: a.yaraScanner.Binary(),
		RulesPath:  a.yaraScanner.RulesPath(),
	}
	if _, err := exec.LookPath(info.BinaryPath); err == nil {
		info.BinaryPresent = true
	}
	if info.RulesPath != "" {
		if data, err := os.ReadFile(info.RulesPath); err == nil {
			sum := sha256.Sum256(data)
			info.RulesHash = hex.EncodeToString(sum[:])
		}
		if fi, err := os.Stat(info.RulesPath); err == nil {
			info.RulesSyncedAt = fi.ModTime()
		}
	}
	return info
}

// SetMaintenanceSuppression toggles FIM maintenance suppression. While on,
// file changes are treated as expected (silent re-baseline + informational
// audit) rather than Critical integrity violations. No-op when FIM is off.
func (a *NativeEBPFAgent) SetMaintenanceSuppression(on bool) {
	if a.fimManager != nil {
		a.fimManager.SetMaintenanceMode(on)
	}
}

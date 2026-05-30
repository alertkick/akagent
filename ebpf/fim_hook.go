//go:build linux

package ebpf

import (
	"fmt"
	"time"

	"akagent/agent/fim"

	"github.com/rs/xid"
)

// initFIM constructs the file-integrity manager from the agent's config and
// wires its change callbacks to emit security events. No-op when FIM is
// disabled. Safe to call again after a config push — it only (re)builds when
// FIM is enabled and not already running.
func (a *NativeEBPFAgent) initFIM() {
	if !a.config.FileIntegrity.Enabled || a.fimManager != nil {
		return
	}
	fc := a.config.FileIntegrity
	a.fimManager = fim.New(
		fim.Config{
			Paths:          fc.Paths,
			Exclude:        fc.Exclude,
			HashAlgo:       fc.HashAlgo,
			SuppressPkgMgr: fc.SuppressPkgMgr,
			DebounceMs:     fc.DebounceMs,
			StatePath:      fim.DefaultBaselinePath,
		},
		func(c fim.Change) { a.emitFIMEvent(buildFIMEvent(c, false)); a.yaraScanFIMChange(c) },
		func(c fim.Change) { a.emitFIMEvent(buildFIMEvent(c, true)); a.yaraScanFIMChange(c) },
	)
	a.fimManager.Start()
	nativeLog.Info().
		Int("paths", len(fc.Paths)).
		Str("algo", fc.HashAlgo).
		Bool("suppress_pkg_mgr", fc.SuppressPkgMgr).
		Msg("File integrity monitoring enabled")
}

// yaraScanFIMChange queues a changed file for YARA scanning so a modified or
// newly-added baselined file (e.g. a trojaned binary or dropped /etc payload)
// is checked against the malware ruleset. Removals have nothing to scan.
func (a *NativeEBPFAgent) yaraScanFIMChange(c fim.Change) {
	if c.Kind != fim.KindRemoved {
		a.yaraScan(c.Path)
	}
}

// fimNotify routes a parsed file event to the integrity manager when FIM is
// on, the path is monitored, and the operation could have changed the file.
// The manager debounces and re-hashes; only an actual content change emits.
func (a *NativeEBPFAgent) fimNotify(ev *SecurityEvent) {
	if a.fimManager == nil {
		return
	}
	path := ev.File.Path
	if path == "" || !a.fimManager.Monitors(path) || !fimWriteish(ev) {
		return
	}
	// Best-effort process lineage so package-manager attribution can see the
	// ancestor chain (e.g. a maintainer-script shell whose parent is dpkg).
	if a.processCache != nil {
		a.processCache.Enrich(ev)
	}
	ancestry := make([]string, 0, 2)
	if ev.Process.ParentName != "" {
		ancestry = append(ancestry, ev.Process.ParentName)
	}
	if ev.Process.GrandparentName != "" {
		ancestry = append(ancestry, ev.Process.GrandparentName)
	}
	a.fimManager.Notify(path, fim.Trigger{
		Comm:     ev.Process.Name,
		Exe:      ev.Process.ExePath,
		PID:      ev.Process.PID,
		Ancestry: ancestry,
	})
}

// fimWriteish reports whether a file operation could have changed content or
// metadata we baseline. Reads (open without write intent) are ignored so we
// don't re-hash on every access of a hot file.
func fimWriteish(ev *SecurityEvent) bool {
	switch ev.File.Operation {
	case "unlink", "rename", "chmod", "chown", "setxattr", "removexattr", "utimes", "link", "symlink":
		return true
	case "open":
		const oWRONLY, oRDWR, oCREAT, oTRUNC = 0x1, 0x2, 0x40, 0x200
		return rawFlags(ev)&(oWRONLY|oRDWR|oCREAT|oTRUNC) != 0
	default:
		return false
	}
}

// rawFlags extracts the open flags stored in RawFields, tolerant of the
// integer type the BPF struct decoded to.
func rawFlags(ev *SecurityEvent) uint64 {
	if ev.RawFields == nil {
		return 0
	}
	switch v := ev.RawFields["flags"].(type) {
	case uint64:
		return v
	case uint32:
		return uint64(v)
	case int64:
		return uint64(v)
	case int32:
		return uint64(v)
	case int:
		return uint64(v)
	default:
		return 0
	}
}

// emitFIMEvent pushes a FIM finding onto the event channel directly, bypassing
// the noise/rate filters sendEvent applies to raw syscall events — an integrity
// violation is authoritative and must not be dropped because the modifying
// process happens to be on the exclude list.
func (a *NativeEBPFAgent) emitFIMEvent(ev SecurityEvent) {
	select {
	case a.eventChan <- ev:
	default:
		nativeLog.Warn().Msg("Event channel full, dropping FIM event")
	}
}

// buildFIMEvent turns a fim.Change into a SecurityEvent. A genuine violation is
// Critical "File Integrity Violation"; a suppressed package-manager change is
// an Informational "Expected File Change" kept for audit.
func buildFIMEvent(c fim.Change, expected bool) SecurityEvent {
	priority := PriorityCritical
	rule := "File Integrity Violation"
	if expected {
		priority = PriorityInformational
		rule = "Expected File Change"
	}
	var parent string
	if len(c.Trigger.Ancestry) > 0 {
		parent = c.Trigger.Ancestry[0]
	}
	output := fmt.Sprintf("Monitored file %s %s", c.Path, c.Kind)
	if c.Trigger.Comm != "" {
		output += fmt.Sprintf(" by %s (pid %d)", c.Trigger.Comm, c.Trigger.PID)
	}
	return SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  priority,
		Rule:      rule,
		Source:    "fim",
		Category:  "file",
		Output:    output,
		Process: ProcessInfo{
			PID:        c.Trigger.PID,
			Name:       c.Trigger.Comm,
			ExePath:    c.Trigger.Exe,
			ParentName: parent,
		},
		File: FileInfo{Path: c.Path, Operation: string(c.Kind), Hash: c.NewHash},
		RawFields: map[string]interface{}{
			"path":               c.Path,
			"change_kind":        string(c.Kind),
			"old_hash":           c.OldHash,
			"new_hash":           c.NewHash,
			"hash_algo":          c.Algo,
			"modifying_comm":     c.Trigger.Comm,
			"modifying_pid":      c.Trigger.PID,
			"pkg_mgr_attributed": c.PkgMgrAttributed,
		},
	}
}

// FIMApprovePaths re-baselines the given paths (operator approved the change).
// No-op when FIM is disabled.
func (a *NativeEBPFAgent) FIMApprovePaths(paths []string) {
	if a.fimManager != nil {
		a.fimManager.ApprovePaths(paths)
	}
}

// FIMRebaseline rescans all monitored paths, accepting current disk state as
// the new known-good baseline. No-op when FIM is disabled.
func (a *NativeEBPFAgent) FIMRebaseline() {
	if a.fimManager != nil {
		a.fimManager.Rebaseline()
	}
}

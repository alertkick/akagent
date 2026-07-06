//go:build windows

package winevt

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"akagent/agent/fim"
	"akagent/agent/yarascan"
	"akagent/ebpf"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/xid"
)

// defaultFIMPaths are the Windows locations worth integrity-monitoring by
// default: the hosts file, and the startup folders that are classic
// persistence spots. Kept conservative so the initial baseline scan is quick;
// config push can extend this later.
func defaultFIMPaths() []string {
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return []string{
		filepath.Join(sysRoot, `System32\drivers\etc`),
		filepath.Join(programData, `Microsoft\Windows\Start Menu\Programs\StartUp`),
	}
}

// fimWatcher drives the shared fim.Manager from ReadDirectoryChangesW events
// (via fsnotify). It is the Windows analogue of ebpf/fim_hook.go: fsnotify
// replaces the eBPF file-event source, and the manager's debounce + re-hash
// pipeline is reused unchanged.
type fimWatcher struct {
	manager *fim.Manager
	watcher *fsnotify.Watcher
	scanner *yarascan.Scanner
	emit    func(ebpf.SecurityEvent)
}

// StartFIM builds the integrity manager over the default Windows paths and
// begins watching them. FIM events are emitted through the collector's
// channel. No-op if the watcher can't be created.
func (c *Collector) StartFIM(ctx context.Context) {
	paths := defaultFIMPaths()

	fw := &fimWatcher{emit: c.emit}

	// YARA scanner: scans files the integrity monitor flags as changed. It
	// stays dormant (Available()==false) until a ruleset is present at
	// DefaultRulesPath and yara64.exe is on disk, so this is safe to wire even
	// before rules-sync delivers a bundle.
	fw.scanner = yarascan.New(yarascan.Config{
		RulesPath: yarascan.DefaultRulesPath,
	}, func(m yarascan.Match) { fw.emit(buildYaraEvent(m)) })
	fw.scanner.Start()

	onChange := func(ch fim.Change) {
		fw.emit(buildFIMEvent(ch, false))
		if ch.Kind != fim.KindRemoved {
			fw.scanner.ScanAsync(ch.Path)
		}
	}
	onExpected := func(ch fim.Change) {
		fw.emit(buildFIMEvent(ch, true))
		if ch.Kind != fim.KindRemoved {
			fw.scanner.ScanAsync(ch.Path)
		}
	}
	fw.manager = fim.New(
		fim.Config{
			Paths:      paths,
			HashAlgo:   "sha256",
			DebounceMs: 750,
			StatePath:  filepath.Join(fimStateDir(), "fim-baseline.json"),
		},
		onChange, onExpected,
	)
	fw.manager.Start()

	w, err := fsnotify.NewWatcher()
	if err != nil {
		log.Warn().Err(err).Msg("winevt.StartFIM - could not create fsnotify watcher")
		return
	}
	fw.watcher = w

	added := 0
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			continue // path may not exist on this SKU
		}
		if err := w.Add(p); err != nil {
			log.Warn().Err(err).Msgf("winevt.StartFIM - watch %q failed", p)
			continue
		}
		added++
	}
	if added == 0 {
		log.Info().Msg("winevt.StartFIM - no monitorable paths present; FIM idle")
		w.Close()
		return
	}

	c.fim = fw
	go fw.loop(ctx)
	log.Info().Msgf("winevt.StartFIM - file integrity monitoring %d path(s)", added)
}

func (fw *fimWatcher) loop(ctx context.Context) {
	defer fw.watcher.Close()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-fw.watcher.Events:
			if !ok {
				return
			}
			// Writes, creates, renames, removes all warrant a re-check; the
			// manager decides whether content actually changed.
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) == 0 {
				continue
			}
			fw.manager.Notify(ev.Name, fim.Trigger{})
		case err, ok := <-fw.watcher.Errors:
			if !ok {
				return
			}
			log.Debug().Err(err).Msg("winevt.fimWatcher - watch error")
		}
	}
}

// buildFIMEvent mirrors ebpf.buildFIMEvent so Windows FIM findings render
// identically to Linux ones (same rule names, category, priority, RawFields).
func buildFIMEvent(c fim.Change, expected bool) ebpf.SecurityEvent {
	priority := ebpf.PriorityCritical
	rule := "File Integrity Violation"
	if expected {
		priority = ebpf.PriorityInformational
		rule = "Expected File Change"
		if c.SuppressReason == "maintenance" {
			rule = "Maintenance Window Change"
		}
	}
	output := fmt.Sprintf("Monitored file %s %s", c.Path, c.Kind)
	return ebpf.SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: ebpf.AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  priority,
		Rule:      rule,
		Source:    "fim",
		Category:  "file",
		Output:    output,
		File:      ebpf.FileInfo{Path: c.Path, Operation: string(c.Kind), Hash: c.NewHash},
		RawFields: map[string]interface{}{
			"path":        c.Path,
			"change_kind": string(c.Kind),
			"old_hash":    c.OldHash,
			"new_hash":    c.NewHash,
			"hash_algo":   c.Algo,
		},
	}
}

// buildYaraEvent mirrors ebpf.buildYaraEvent so Windows YARA hits render
// identically to Linux ones.
func buildYaraEvent(m yarascan.Match) ebpf.SecurityEvent {
	matched := ""
	if len(m.Rules) > 0 {
		matched = m.Rules[0]
	}
	return ebpf.SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: ebpf.AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  ebpf.PriorityCritical,
		Rule:      "YARA Match",
		Source:    "yarascan",
		Category:  "malware",
		Output:    "YARA rules matched " + m.Path + ": " + strings.Join(m.Rules, ", "),
		File:      ebpf.FileInfo{Path: m.Path},
		RawFields: map[string]interface{}{
			"path":         m.Path,
			"yara_rules":   m.Rules,
			"matched_rule": matched,
		},
	}
}

// fimStateDir returns the writable dir for the FIM baseline (ProgramData).
func fimStateDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return strings.TrimRight(pd, `\`) + `\AlertKick`
}

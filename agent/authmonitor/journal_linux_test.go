//go:build linux

package authmonitor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// writeFakeJournalctl writes an executable script that emits the given stdout
// lines (ignoring its journalctl args) and exits, standing in for a real
// journalctl -f stream that ends.
func writeFakeJournalctl(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "journalctl")
	script := "#!/bin/sh\n" + body
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake journalctl: %v", err)
	}
	return path
}

// TestJournalFollowParsesFailures drives runJournalctl against a fake
// journalctl that prints three failed-password lines, confirming journal lines
// flow through the same processLine path and cross the threshold.
func TestJournalFollowParsesFailures(t *testing.T) {
	fake := writeFakeJournalctl(t, `
printf '%s\n' 'Jul 17 10:00:00 host sshd-session[1]: Failed password for root from 203.0.113.30 port 40000 ssh2'
printf '%s\n' 'Jul 17 10:00:01 host sshd-session[2]: Failed password for root from 203.0.113.30 port 40001 ssh2'
printf '%s\n' 'Jul 17 10:00:02 host sshd-session[3]: Failed password for root from 203.0.113.30 port 40002 ssh2'
`)

	var findings []Finding
	m := New(Config{Threshold: 3, WindowSeconds: 60, CooldownSeconds: 100, JournalctlPath: fake}, func(f Finding) {
		findings = append(findings, f)
	})

	m.runJournalctl(context.Background())

	if len(findings) != 1 || findings[0].Source != "203.0.113.30" {
		t.Fatalf("expected one brute-force finding from journal stream, got %+v", findings)
	}
}

// TestStartUsesJournalWhenNoFile confirms Start reports the journal source when
// no auth-log file exists and journalctl (the fake) is available.
func TestStartUsesJournalWhenNoFile(t *testing.T) {
	fake := writeFakeJournalctl(t, "sleep 0.2\n")
	m := New(Config{
		Paths:          []string{filepath.Join(t.TempDir(), "does-not-exist.log")},
		JournalctlPath: fake,
	}, func(Finding) {})

	source := m.Start()
	defer m.Stop()
	if source != "journal" {
		t.Fatalf("expected Start to select journal source, got %q", source)
	}
}

// TestStartNoSourceWhenJournalDisabled confirms the fallback can be turned off,
// reproducing the historical no-op when there is neither a file nor journal.
func TestStartNoSourceWhenJournalDisabled(t *testing.T) {
	m := New(Config{
		Paths:          []string{filepath.Join(t.TempDir(), "does-not-exist.log")},
		DisableJournal: true,
	}, func(Finding) {})

	if source := m.Start(); source != "" {
		t.Fatalf("expected no source when journal disabled and no file, got %q", source)
	}
}

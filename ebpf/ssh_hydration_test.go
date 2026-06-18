//go:build linux

package ebpf

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestHydrateSSHLogin_AuthLogMatchByPPID(t *testing.T) {
	dir := t.TempDir()
	authLog := filepath.Join(dir, "auth.log")
	contents := "" +
		"May 29 09:55:12 host sshd[11111]: Accepted publickey for someoneelse from 10.99.99.99 port 50000 ssh2: ED25519\n" +
		"May 29 09:57:48 host sshd[12345]: Accepted publickey for ssidhu from 10.0.0.7 port 60123 ssh2: ED25519 SHA256:abc\n" +
		"May 29 09:58:01 host CRON[22222]: pam_unix(cron:session): session opened for user root\n"
	if err := os.WriteFile(authLog, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	h := NewSSHHydrator()
	h.authLogPaths = []string{authLog}
	// who fallback should never run on a clean auth.log hit.
	h.whoRunner = func(_ context.Context) ([]whoEntry, error) {
		t.Fatal("who fallback should not be invoked when auth.log hit succeeds")
		return nil, nil
	}

	event := &SecurityEvent{
		Rule: "Process Clone",
		Process: ProcessInfo{
			PID: 99999, PPID: 12345,
			Name:       "bash",
			ParentExe:  "/usr/sbin/sshd",
			ParentName: "sshd",
			Cmdline:    "-bash",
			Username:   "ssidhu",
		},
	}
	h.HydrateSSHLogin(event)

	if got := event.RawFields["ssh_source_ip"]; got != "10.0.0.7" {
		t.Fatalf("ssh_source_ip = %v, want 10.0.0.7", got)
	}
	if got := event.RawFields["ssh_username"]; got != "ssidhu" {
		t.Fatalf("ssh_username = %v, want ssidhu", got)
	}
	if event.Network.SrcIP != "10.0.0.7" {
		t.Fatalf("Network.SrcIP = %q, want 10.0.0.7", event.Network.SrcIP)
	}
	if !containsString(event.Tags, "ssh_login") {
		t.Fatalf("expected ssh_login tag, got %v", event.Tags)
	}
}

func TestHydrateSSHLogin_WhoFallback(t *testing.T) {
	h := NewSSHHydrator()
	h.authLogPaths = []string{filepath.Join(t.TempDir(), "missing.log")}
	h.whoRunner = func(_ context.Context) ([]whoEntry, error) {
		return parseWhoOutput("ssidhu   pts/0        2026-05-29 09:57   .         99 (203.0.113.42)\n"), nil
	}
	event := &SecurityEvent{
		Rule: "Process Clone",
		Process: ProcessInfo{
			PID: 99999, PPID: 33333,
			ParentName: "sshd",
			Cmdline:    "-bash",
			Username:   "ssidhu",
		},
	}
	h.HydrateSSHLogin(event)
	if got := event.RawFields["ssh_source_ip"]; got != "203.0.113.42" {
		t.Fatalf("ssh_source_ip = %v, want 203.0.113.42", got)
	}
}

func TestHydrateSSHLogin_StampsLoginWhenSourceIPUnresolved(t *testing.T) {
	// A journald-only host (no auth.log) where `who` also can't attribute the
	// session. Source IP is unknown, but it's still an sshd login shell — the
	// event must be marked ssh_login so the session tracker records it.
	h := NewSSHHydrator()
	h.authLogPaths = []string{filepath.Join(t.TempDir(), "missing.log")}
	h.whoRunner = func(_ context.Context) ([]whoEntry, error) {
		return nil, os.ErrNotExist
	}
	event := &SecurityEvent{
		Rule: "Process Execution",
		Process: ProcessInfo{
			PID: 99999, PPID: 44444,
			Name:       "bash",
			ParentExe:  "/usr/sbin/sshd-session", // OpenSSH 9.8+ per-session worker
			Cmdline:    "-bash",
			Username:   "ssidhu",
		},
	}
	h.HydrateSSHLogin(event)

	if v, _ := event.RawFields["ssh_login"].(bool); !v {
		t.Fatal("ssh_login should be stamped even when the source IP is unresolved")
	}
	if !containsString(event.Tags, "ssh_login") {
		t.Fatalf("expected ssh_login tag, got %v", event.Tags)
	}
	if _, ok := event.RawFields["ssh_source_ip"]; ok {
		t.Fatal("ssh_source_ip should be absent when unresolved (it is enrichment only)")
	}
}

func TestHydrateSSHLogin_NoOpForNonSSHParent(t *testing.T) {
	h := NewSSHHydrator()
	// Both lookups should be untouched.
	h.authLogPaths = nil
	h.whoRunner = func(_ context.Context) ([]whoEntry, error) {
		t.Fatal("non-ssh event should not invoke who")
		return nil, nil
	}
	event := &SecurityEvent{
		Rule: "Process Clone",
		Process: ProcessInfo{
			PID: 1, PPID: 2,
			ParentName: "systemd",
			ParentExe:  "/usr/lib/systemd/systemd",
			Cmdline:    "/usr/bin/cron",
		},
	}
	h.HydrateSSHLogin(event)
	if _, ok := event.RawFields["ssh_source_ip"]; ok {
		t.Fatal("ssh_source_ip should not be set for non-sshd parent")
	}
}

func TestHydrateSSHLogin_NoOpForWrongRule(t *testing.T) {
	h := NewSSHHydrator()
	event := &SecurityEvent{
		Rule: "Network Connect",
		Process: ProcessInfo{
			ParentExe: "/usr/sbin/sshd",
			Cmdline:   "-bash",
		},
	}
	h.HydrateSSHLogin(event)
	if _, ok := event.RawFields["ssh_source_ip"]; ok {
		t.Fatal("only Process Clone / Process Execution should hydrate")
	}
}

func TestIsLoginShellCmdline(t *testing.T) {
	cases := map[string]bool{
		"-bash":          true,
		"/bin/bash":      true,
		"/usr/bin/zsh":   true,
		"-sh":            true,
		"sshd: ssidhu":   false,
		"/usr/bin/sleep": false,
		"":               false,
	}
	for in, want := range cases {
		if got := isLoginShellCmdline(in); got != want {
			t.Errorf("isLoginShellCmdline(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestParseWhoOutput(t *testing.T) {
	in := "" +
		"root     tty1         2026-05-29 08:00              :0\n" +
		"ssidhu   pts/0        2026-05-29 09:57   .       99 (10.0.0.7)\n" +
		"alice    pts/1        2026-05-29 10:00   .      100 (10.0.0.8)\n"
	got := parseWhoOutput(in)
	if len(got) != 3 {
		t.Fatalf("len=%d, want 3 (%+v)", len(got), got)
	}
	if got[1].username != "ssidhu" || got[1].sourceIP != "10.0.0.7" {
		t.Errorf("entry[1] = %+v, want ssidhu / 10.0.0.7", got[1])
	}
}

func containsString(s []string, target string) bool {
	for _, v := range s {
		if v == target {
			return true
		}
	}
	return false
}

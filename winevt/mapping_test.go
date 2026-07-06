package winevt

import (
	"testing"
	"time"

	"akagent/ebpf"
)

func rec(id int, data map[string]string) *Record {
	return &Record{
		Channel:   "Security",
		Provider:  "Microsoft-Windows-Security-Auditing",
		EventID:   id,
		Timestamp: time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC),
		Computer:  "WIN-TEST",
		Data:      data,
	}
}

func TestMapLogonSuccessInteractive(t *testing.T) {
	ev, ok := MapEvent(rec(4624, map[string]string{
		"logontype":      "2",
		"targetusername": "alice",
		"ipaddress":      "10.0.0.5",
	}))
	if !ok {
		t.Fatal("expected 4624 to map")
	}
	if ev.Category != "auth" || ev.Rule != "Windows Logon" {
		t.Fatalf("unexpected category/rule: %s/%s", ev.Category, ev.Rule)
	}
	if ev.Process.Username != "alice" {
		t.Fatalf("username = %q", ev.Process.Username)
	}
	if !ev.Validate() {
		t.Fatal("event failed validation")
	}
}

func TestMapLogonSkipsMachineAccount(t *testing.T) {
	if _, ok := MapEvent(rec(4624, map[string]string{
		"logontype":      "3",
		"targetusername": "WIN-TEST$",
	})); ok {
		t.Fatal("machine account logon should be skipped")
	}
	if _, ok := MapEvent(rec(4624, map[string]string{
		"logontype":      "3",
		"targetusername": "SYSTEM",
	})); ok {
		t.Fatal("SYSTEM logon should be skipped")
	}
}

func TestMapRDPSessionShape(t *testing.T) {
	ev, ok := MapEvent(rec(4624, map[string]string{
		"logontype":      "10",
		"targetusername": "bob",
		"ipaddress":      "203.0.113.9",
		"targetlogonid":  "0x1a2b3c",
	}))
	if !ok {
		t.Fatal("expected RDP logon to map")
	}
	// Must bind the ac-012 session UI: ssh_session-shaped fields.
	if ev.Rule != ebpf.RuleSSHInboundLogin {
		t.Fatalf("rule = %q, want %q", ev.Rule, ebpf.RuleSSHInboundLogin)
	}
	if ev.Category != "ssh_session" {
		t.Fatalf("category = %q", ev.Category)
	}
	if ev.RawFields["event_kind"] != "ssh_session" {
		t.Fatalf("event_kind = %v", ev.RawFields["event_kind"])
	}
	if ev.RawFields["ssh_login"] != true {
		t.Fatal("ssh_login should be true")
	}
	if ev.RawFields["ssh_source_ip"] != "203.0.113.9" {
		t.Fatalf("ssh_source_ip = %v", ev.RawFields["ssh_source_ip"])
	}
	if ev.RawFields["ssh_username"] != "bob" {
		t.Fatalf("ssh_username = %v", ev.RawFields["ssh_username"])
	}
	// UUID must be stable (derived from logon id) so the API upserts.
	if ev.UUID != "rdpsess-1a2b3c" {
		t.Fatalf("UUID = %q, want stable session id", ev.UUID)
	}
}

func TestMapServiceInstall7045(t *testing.T) {
	ev, ok := MapEvent(&Record{
		Channel: "System", EventID: 7045, Computer: "WIN-TEST",
		Timestamp: time.Now(),
		Data: map[string]string{
			"servicename": "EvilSvc",
			"imagepath":   `C:\temp\evil.exe`,
			"starttype":   "auto start",
		},
	})
	if !ok {
		t.Fatal("expected 7045 to map")
	}
	if ev.Category != "persistence" || ev.Rule != "Service Installed" {
		t.Fatalf("unexpected: %s/%s", ev.Category, ev.Rule)
	}
	if ev.RawFields["service_file"] != `C:\temp\evil.exe` {
		t.Fatalf("service_file = %v", ev.RawFields["service_file"])
	}
}

func TestMapProcessCreation4688(t *testing.T) {
	ev, ok := MapEvent(rec(4688, map[string]string{
		"newprocessname":    `C:\Windows\System32\cmd.exe`,
		"newprocessid":      "0x1a4",
		"processid":         "0x100",
		"commandline":       `cmd /c whoami`,
		"subjectusername":   "alice",
		"parentprocessname": `C:\Windows\explorer.exe`,
	}))
	if !ok {
		t.Fatal("expected 4688 to map")
	}
	if ev.Process.Name != "cmd.exe" {
		t.Fatalf("process name = %q", ev.Process.Name)
	}
	if ev.Process.PID != 420 { // 0x1a4
		t.Fatalf("pid = %d, want 420", ev.Process.PID)
	}
	if ev.Process.ParentName != "explorer.exe" {
		t.Fatalf("parent = %q", ev.Process.ParentName)
	}
}

func TestMapMsiInstall(t *testing.T) {
	ev, ok := MapEvent(&Record{
		Channel: "Application", EventID: 11707, Computer: "WIN-TEST",
		Timestamp: time.Now(),
		Data: map[string]string{
			"param1": "Product: Wireshark -- Installation completed successfully.",
		},
	})
	if !ok {
		t.Fatal("expected 11707 to map")
	}
	if ev.RawFields["product"] != "Wireshark" {
		t.Fatalf("product = %v", ev.RawFields["product"])
	}
	if ev.RawFields["event_kind"] != "package_installed" {
		t.Fatalf("event_kind = %v", ev.RawFields["event_kind"])
	}
}

func TestMapAuditLogCleared1102(t *testing.T) {
	ev, ok := MapEvent(rec(1102, map[string]string{"subjectusername": "attacker"}))
	if !ok {
		t.Fatal("expected 1102 to map")
	}
	if ev.Category != "defense_evasion" || !ev.IsHighPriority() {
		t.Fatalf("1102 should be high-priority defense_evasion, got %s pri=%v", ev.Category, ev.Priority)
	}
}

func TestUnmappedEventIgnored(t *testing.T) {
	if _, ok := MapEvent(rec(4634, nil)); ok { // 4634 = logoff, not mapped
		t.Fatal("unmapped event should return false")
	}
}

func TestBruteForceWindow(t *testing.T) {
	bf := newBruteForce()
	base := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	cur := base
	bf.now = func() time.Time { return cur }

	r := rec(4625, map[string]string{"ipaddress": "198.51.100.7", "targetusername": "admin"})

	// First 4 failures: below threshold (5).
	for i := 0; i < 4; i++ {
		cur = cur.Add(5 * time.Second)
		if _, ok := bf.Observe(r); ok {
			t.Fatalf("fired early at failure %d", i+1)
		}
	}
	// 5th within window: should fire.
	cur = cur.Add(5 * time.Second)
	ev, ok := bf.Observe(r)
	if !ok {
		t.Fatal("expected brute-force to fire on 5th failure")
	}
	if ev.Rule != "RDP Brute Force" || ev.Network.SrcIP != "198.51.100.7" {
		t.Fatalf("unexpected event: %s src=%s", ev.Rule, ev.Network.SrcIP)
	}
	if !ev.IsHighPriority() {
		t.Fatal("brute-force should be high priority")
	}
	// 6th immediately after: suppressed by cooldown.
	cur = cur.Add(5 * time.Second)
	if _, ok := bf.Observe(r); ok {
		t.Fatal("should be suppressed by cooldown")
	}
}

func TestBruteForceWindowExpiry(t *testing.T) {
	bf := newBruteForce()
	base := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	cur := base
	bf.now = func() time.Time { return cur }
	r := rec(4625, map[string]string{"ipaddress": "198.51.100.8", "targetusername": "x"})

	// 4 failures, then a long gap so they age out, then 4 more — never 5 in-window.
	for i := 0; i < 4; i++ {
		cur = cur.Add(10 * time.Second)
		bf.Observe(r)
	}
	cur = cur.Add(10 * time.Minute) // beyond window
	for i := 0; i < 4; i++ {
		cur = cur.Add(10 * time.Second)
		if _, ok := bf.Observe(r); ok {
			t.Fatal("stale failures should have aged out of the window")
		}
	}
}

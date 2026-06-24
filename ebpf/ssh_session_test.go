//go:build linux

package ebpf

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestMain forces procStartTicks to 0 for the whole package test run so the
// SSH session tracker derives worker identity from the cache start values the
// tests control, rather than from whatever real process happens to occupy the
// chosen pid on the build host.
func TestMain(m *testing.M) {
	procStartTicksFn = func(uint32) uint64 { return 0 }
	os.Exit(m.Run())
}

func testCache(entries map[uint32]*ProcessCacheEntry) *ProcessCache {
	if entries == nil {
		entries = map[uint32]*ProcessCacheEntry{}
	}
	return &ProcessCache{cache: entries, maxSize: 1024, enabled: true}
}

// withFakeAlive swaps the /proc liveness probe so tests can declare which pids
// are "alive" without a real /proc. Returns a restore func.
func withFakeAlive(alive map[uint32]bool) func() {
	prev := procAliveFn
	procAliveFn = func(pid uint32, _ uint64) bool { return alive[pid] }
	return func() { procAliveFn = prev }
}

// newTrackerWithEmit returns a tracker whose open events are collected into the
// returned slice pointer, mirroring how native_readers wires the emit callback.
func newTrackerWithEmit() (*SSHSessionTracker, *[]SecurityEvent) {
	tr := NewSSHSessionTracker()
	var emitted []SecurityEvent
	tr.SetEmit(func(ev SecurityEvent) { emitted = append(emitted, ev) })
	return tr, &emitted
}

// workerChildEvent mimics the first process under a per-connection sshd worker
// (the login shell). Its parent is the worker (sshd-session), so the tracker
// anchors the session on PPID = workerPID.
func workerChildEvent(childPID, workerPID int, ip, user string) *SecurityEvent {
	return &SecurityEvent{
		AgentType: AgentTypeNative,
		Timestamp: time.Now(),
		Rule:      "Process Execution",
		Category:  "process",
		Process: ProcessInfo{
			PID: childPID, PPID: workerPID, Name: "bash", ExePath: "/usr/bin/bash",
			Username: user, TTY: 1, ParentName: "sshd-session",
		},
		RawFields: map[string]interface{}{
			"ssh_login":     true,
			"ssh_source_ip": ip,
			"ssh_username":  user,
		},
	}
}

// workerOwnEvent mimics the per-connection sshd worker's own exec (OpenSSH 9.8+
// "sshd-session"), parented by the sshd listener.
func workerOwnEvent(workerPID, listenerPID int, ip, user string) *SecurityEvent {
	return &SecurityEvent{
		AgentType: AgentTypeNative,
		Timestamp: time.Now(),
		Rule:      "Process Execution",
		Category:  "process",
		Process: ProcessInfo{
			PID: workerPID, PPID: listenerPID, Name: "sshd-session",
			ExePath: "/usr/sbin/sshd-session", ParentName: "sshd",
		},
		RawFields: map[string]interface{}{
			"ssh_login":     true,
			"ssh_source_ip": ip,
			"ssh_username":  user,
		},
	}
}

func execEvent(pid, ppid, gpid int, cmdline string) *SecurityEvent {
	return &SecurityEvent{
		AgentType: AgentTypeNative,
		Timestamp: time.Now(),
		Rule:      "Process Execution",
		Category:  "process",
		Process:   ProcessInfo{PID: pid, PPID: ppid, GrandparentPID: gpid, Cmdline: cmdline, ExePath: strings.Fields(cmdline + " ")[0]},
	}
}

func TestSSHSession_OpensOnConnectionWorkerChild(t *testing.T) {
	tr, emitted := newTrackerWithEmit()
	// worker pid 900 (no /proc in tests → startTicks falls back to cache startNS).
	cache := testCache(map[uint32]*ProcessCacheEntry{900: {PID: 900, StartTimeNS: 111}})

	tr.OnEvent(workerChildEvent(1000, 900, "80.6.38.150", "root"), cache, false)

	if len(tr.sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(tr.sessions))
	}
	if len(*emitted) != 1 {
		t.Fatalf("emitted open events = %d, want 1", len(*emitted))
	}
	ev := (*emitted)[0]
	if ev.Rule != RuleSSHInboundLogin || ev.Category != "ssh_session" {
		t.Fatalf("open event not a session event: rule=%q cat=%q", ev.Rule, ev.Category)
	}
	if ev.RawFields["status"] != "active" {
		t.Fatalf("status = %v", ev.RawFields["status"])
	}
	if got := ev.RawFields["ssh_anchor_pid"]; got != 900 {
		t.Fatalf("ssh_anchor_pid = %v, want 900 (the worker)", got)
	}
	sid, _ := ev.RawFields["ssh_session_id"].(string)
	if sid == "" || ev.UUID != sid {
		t.Fatalf("uuid/session id mismatch: uuid=%q sid=%q", ev.UUID, sid)
	}
}

func TestSSHSession_OpensOnWorkerOwnExec(t *testing.T) {
	tr, emitted := newTrackerWithEmit()
	cache := testCache(map[uint32]*ProcessCacheEntry{900: {PID: 900, StartTimeNS: 111}})

	tr.OnEvent(workerOwnEvent(900, 500, "10.0.0.1", "root"), cache, false)

	if len(tr.sessions) != 1 {
		t.Fatalf("worker-own exec produced %d sessions, want 1", len(tr.sessions))
	}
	ev := (*emitted)[0]
	if got := ev.RawFields["ssh_anchor_pid"]; got != 900 {
		t.Fatalf("anchor pid = %v, want 900", got)
	}
	if got := ev.RawFields["ssh_anchor_ppid"]; got != 500 {
		t.Fatalf("anchor ppid = %v, want 500 (the listener)", got)
	}
}

func TestSSHSession_OneSessionPerConnection(t *testing.T) {
	tr, emitted := newTrackerWithEmit()
	cache := testCache(map[uint32]*ProcessCacheEntry{900: {PID: 900, StartTimeNS: 111}})

	// Worker-own exec, then two children of the same worker. All must collapse
	// onto ONE session (the worker), not three.
	tr.OnEvent(workerOwnEvent(900, 500, "10.0.0.1", "root"), cache, false)
	tr.OnEvent(workerChildEvent(1000, 900, "10.0.0.1", "root"), cache, false)
	tr.OnEvent(execEvent(1001, 900, 0, "/usr/bin/whoami"), cache, false)

	if len(tr.sessions) != 1 {
		t.Fatalf("sessions = %d, want 1 (one connection)", len(tr.sessions))
	}
	if len(*emitted) != 1 {
		t.Fatalf("open events = %d, want 1 (dedup on re-open)", len(*emitted))
	}
}

func TestSSHSession_DeterministicIDSurvivesRestart(t *testing.T) {
	cache := testCache(map[uint32]*ProcessCacheEntry{900: {PID: 900, StartTimeNS: 111}})

	trA, emA := newTrackerWithEmit()
	trA.OnEvent(workerChildEvent(1000, 900, "10.0.0.1", "root"), cache, false)
	idA := (*emA)[0].RawFields["ssh_session_id"].(string)

	// Agent restarts: fresh tracker, same worker re-detected (same pid+startNS).
	trB, emB := newTrackerWithEmit()
	trB.OnEvent(workerChildEvent(1000, 900, "10.0.0.1", "root"), cache, false)
	idB := (*emB)[0].RawFields["ssh_session_id"].(string)

	if idA == "" || idA != idB {
		t.Fatalf("session id not stable across restart: %q vs %q", idA, idB)
	}
}

func TestSSHSession_AttributesChildren(t *testing.T) {
	tr, _ := newTrackerWithEmit()
	defer withFakeAlive(map[uint32]bool{900: true})()
	cache := testCache(map[uint32]*ProcessCacheEntry{
		900:  {PID: 900, StartTimeNS: 111},
		1500: {PID: 1500, ParentPID: 900, StartTimeNS: 222}, // intermediate under the worker
	})
	open := workerChildEvent(1000, 900, "10.0.0.1", "ssidhu")
	tr.OnEvent(open, cache, false)
	sid := open.RawFields["ssh_session_id"].(string)

	// Deep descendant (walk path: PPID=1500 → ParentPID 900 = anchor worker).
	deep := execEvent(2000, 1500, 0, "/usr/bin/cat /etc/passwd")
	tr.OnEvent(deep, cache, false)
	if deep.RawFields["ssh_session_id"] != sid {
		t.Fatalf("deep descendant not attributed: %v", deep.RawFields["ssh_session_id"])
	}

	// Unrelated process: PPID not in any session tree.
	other := execEvent(3000, 4444, 0, "/usr/bin/top")
	tr.OnEvent(other, cache, false)
	if _, ok := other.RawFields["ssh_session_id"]; ok {
		t.Fatal("unrelated process wrongly attributed")
	}

	evs := tr.sweep(time.Now(), cache, false)
	if len(evs) != 1 {
		t.Fatalf("sweep events = %d", len(evs))
	}
	// The login shell (workerChildEvent) and the deep descendant both count.
	if got := evs[0].RawFields["process_count"]; got != 2 {
		t.Fatalf("process_count = %v, want 2", got)
	}
}

func TestSSHSession_CommandCaptureRedacts(t *testing.T) {
	tr, _ := newTrackerWithEmit()
	defer withFakeAlive(map[uint32]bool{900: true})()
	cache := testCache(map[uint32]*ProcessCacheEntry{900: {PID: 900, StartTimeNS: 111}})
	tr.OnEvent(workerChildEvent(1000, 900, "10.0.0.1", "root"), cache, true)

	tr.OnEvent(execEvent(1200, 900, 0, "mysql -phunter2 appdb"), cache, true)

	evs := tr.sweep(time.Now(), cache, true)
	cmds, ok := evs[0].RawFields["commands"].([]sshSessionCommand)
	if !ok || len(cmds) == 0 {
		t.Fatalf("commands = %v", evs[0].RawFields["commands"])
	}
	for _, c := range cmds {
		if strings.Contains(c.Cmdline, "hunter2") {
			t.Fatalf("secret not redacted: %q", c.Cmdline)
		}
	}
}

func TestSSHSession_PIDReuseIsolatesSessions(t *testing.T) {
	tr, _ := newTrackerWithEmit()
	cache := testCache(map[uint32]*ProcessCacheEntry{900: {PID: 900, StartTimeNS: 111}})
	tr.OnEvent(workerChildEvent(1000, 900, "10.0.0.1", "a"), cache, false)

	// Same worker PID, different start time → a genuinely different connection.
	cache.cache[900] = &ProcessCacheEntry{PID: 900, StartTimeNS: 999}
	tr.OnEvent(workerChildEvent(1001, 900, "10.0.0.2", "b"), cache, false)

	if len(tr.sessions) != 2 {
		t.Fatalf("sessions = %d, want 2 (pid reuse must not collide)", len(tr.sessions))
	}
}

func TestSSHSession_SweepClosesOnWorkerExit(t *testing.T) {
	tr, _ := newTrackerWithEmit()
	restore := withFakeAlive(map[uint32]bool{900: true})
	cache := testCache(map[uint32]*ProcessCacheEntry{900: {PID: 900, StartTimeNS: 111}})
	open := workerChildEvent(1000, 900, "10.0.0.1", "root")
	open.Timestamp = time.Now().Add(-1 * time.Minute)
	tr.OnEvent(open, cache, false)

	// Worker still alive → stays active.
	if evs := tr.sweep(time.Now(), cache, false); len(evs) != 1 || evs[0].RawFields["status"] != "active" {
		t.Fatalf("expected one active event, got %+v", evs)
	}
	if len(tr.sessions) != 1 {
		t.Fatal("active session wrongly evicted")
	}

	// Worker dies → session closes with duration.
	restore()
	defer withFakeAlive(map[uint32]bool{})()
	evs := tr.sweep(time.Now(), cache, false)
	if len(evs) != 1 || evs[0].RawFields["status"] != "closed" {
		t.Fatalf("expected one closed event, got %+v", evs)
	}
	if _, ok := evs[0].RawFields["duration_seconds"]; !ok {
		t.Fatal("closed event missing duration_seconds")
	}
	if len(tr.sessions) != 0 {
		t.Fatal("closed session not evicted")
	}
}

func TestSSHSession_IdleButOpenStaysActive(t *testing.T) {
	tr, _ := newTrackerWithEmit()
	defer withFakeAlive(map[uint32]bool{900: true})()
	cache := testCache(map[uint32]*ProcessCacheEntry{900: {PID: 900, StartTimeNS: 111}})
	tr.OnEvent(workerChildEvent(1000, 900, "10.0.0.1", "root"), cache, false)

	// Long time later, no activity, but the worker is still alive: must NOT close
	// (the old inactivity-TTL false-close is gone).
	future := time.Now().Add(24 * time.Hour)
	evs := tr.sweep(future, cache, false)
	if len(evs) != 1 || evs[0].RawFields["status"] != "active" {
		t.Fatalf("idle-but-open session should stay active, got %+v", evs)
	}
}

func TestSSHSession_ClassifyAgainstAllowlist(t *testing.T) {
	cache := testCache(map[uint32]*ProcessCacheEntry{900: {PID: 900, StartTimeNS: 1}, 901: {PID: 901, StartTimeNS: 2}})

	// Trusted: source IP within an allowlisted CIDR.
	trA, emA := newTrackerWithEmit()
	trA.SetAllowlistFunc(func() []string { return []string{"10.0.0.0/8", "203.0.113.5"} })
	trA.OnEvent(workerChildEvent(1000, 900, "10.1.2.3", "root"), cache, false)
	if got := (*emA)[0].RawFields["classification"]; got != sshClassTrusted {
		t.Fatalf("classification = %v, want trusted", got)
	}
	if (*emA)[0].Priority != PriorityError {
		t.Fatalf("trusted login priority = %v, want Error", (*emA)[0].Priority)
	}

	// Untrusted: resolved IP not on the list → CRITICAL + tag.
	trB, emB := newTrackerWithEmit()
	trB.SetAllowlistFunc(func() []string { return []string{"10.0.0.0/8"} })
	trB.OnEvent(workerChildEvent(1001, 901, "80.6.38.150", "root"), cache, false)
	ev := (*emB)[0]
	if got := ev.RawFields["classification"]; got != sshClassUntrusted {
		t.Fatalf("classification = %v, want untrusted", got)
	}
	if ev.Priority != PriorityCritical {
		t.Fatalf("untrusted login priority = %v, want Critical", ev.Priority)
	}
	hasTag := false
	for _, tag := range ev.Tags {
		if tag == "ssh_untrusted_source" {
			hasTag = true
		}
	}
	if !hasTag {
		t.Fatalf("untrusted login missing ssh_untrusted_source tag: %v", ev.Tags)
	}
}

func TestSSHSession_UnresolvedSourceIsNotUntrusted(t *testing.T) {
	tr, em := newTrackerWithEmit()
	tr.SetAllowlistFunc(func() []string { return []string{"10.0.0.0/8"} })
	cache := testCache(map[uint32]*ProcessCacheEntry{900: {PID: 900, StartTimeNS: 1}})

	// No source IP resolvable (privsep / journald-only host) and no resolver
	// wired → classification "unresolved", not an untrusted alert.
	ev := workerChildEvent(1000, 900, "", "root")
	tr.OnEvent(ev, cache, false)
	open := (*em)[0]
	if got := open.RawFields["classification"]; got != sshClassUnresolved {
		t.Fatalf("classification = %v, want unresolved", got)
	}
	if open.Priority != PriorityError {
		t.Fatalf("unresolved login should not escalate to critical, got %v", open.Priority)
	}
}

func TestSSHSession_NoAllowlistIsUnverified(t *testing.T) {
	// Allowlist not configured (nil func): a resolved IP must classify
	// "unverified", NOT untrusted — no connect-time alert spam.
	tr, em := newTrackerWithEmit()
	cache := testCache(map[uint32]*ProcessCacheEntry{900: {PID: 900, StartTimeNS: 1}})
	tr.OnEvent(workerChildEvent(1000, 900, "80.6.38.150", "root"), cache, false)
	open := (*em)[0]
	if got := open.RawFields["classification"]; got != sshClassUnverified {
		t.Fatalf("classification = %v, want unverified", got)
	}
	if open.Priority != PriorityError {
		t.Fatalf("unverified login should not be critical, got %v", open.Priority)
	}
}

func TestSSHSession_CommandCapIsBounded(t *testing.T) {
	tr, _ := newTrackerWithEmit()
	defer withFakeAlive(map[uint32]bool{900: true})()
	cache := testCache(map[uint32]*ProcessCacheEntry{900: {PID: 900, StartTimeNS: 111}})
	tr.OnEvent(workerChildEvent(1000, 900, "10.0.0.1", "root"), cache, true)

	for i := 0; i < maxCommandsPerSSHSession+50; i++ {
		tr.OnEvent(execEvent(2000+i, 900, 0, "/bin/true"), cache, true)
	}
	evs := tr.sweep(time.Now(), cache, true)
	cmds := evs[0].RawFields["commands"].([]sshSessionCommand)
	if len(cmds) != maxCommandsPerSSHSession {
		t.Fatalf("commands len = %d, want cap %d", len(cmds), maxCommandsPerSSHSession)
	}
	// process_count includes the login shell child plus the loop's processes.
	if got := evs[0].RawFields["process_count"]; got != maxCommandsPerSSHSession+50+1 {
		t.Fatalf("process_count = %v, want %d", got, maxCommandsPerSSHSession+50+1)
	}
}

func TestIPAllowed(t *testing.T) {
	list := []string{"10.0.0.0/8", "192.168.1.10", "2001:db8::/32"}
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.255.1.1", true},
		{"192.168.1.10", true},
		{"192.168.1.11", false},
		{"203.0.113.7", false},
		{"2001:db8::1", true},
		{"2001:dba::1", false},
		{"", false},
		{"not-an-ip", false},
	}
	for _, c := range cases {
		if got := ipAllowed(c.ip, list); got != c.want {
			t.Errorf("ipAllowed(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestIsSSHWorkerProcess(t *testing.T) {
	cases := []struct {
		name string
		p    ProcessInfo
		want bool
	}{
		{"sshd-session binary", ProcessInfo{Name: "sshd-session"}, true},
		{"interactive worker title", ProcessInfo{Name: "sshd", Cmdline: "sshd: root@pts/0"}, true},
		{"exec worker title", ProcessInfo{Name: "sshd", Cmdline: "sshd: ansible"}, true},
		{"listener", ProcessInfo{Name: "sshd", Cmdline: "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"}, false},
		{"privsep monitor", ProcessInfo{Name: "sshd", Cmdline: "sshd: root [priv]"}, false},
		{"net child", ProcessInfo{Name: "sshd", Cmdline: "sshd: root [net]"}, false},
		{"plain sshd", ProcessInfo{Name: "sshd", Cmdline: "/usr/sbin/sshd -D"}, false},
		{"a shell", ProcessInfo{Name: "bash"}, false},
	}
	for _, c := range cases {
		if got := isSSHWorkerProcess(c.p); got != c.want {
			t.Errorf("%s: isSSHWorkerProcess = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestRedactArgv(t *testing.T) {
	cases := []struct {
		in     string
		secret string
	}{
		{"mysql -phunter2 appdb", "hunter2"},
		{"app --password=s3cr3t --host db", "s3cr3t"},
		{"app --token abc123def", "abc123def"},
		{"curl -H 'Authorization: Bearer eyJhbGci'", "eyJhbGci"},
		{"DB_PASSWORD=topsecret ./run", "topsecret"},
		{"API_KEY=zzz node app.js", "zzz"},
	}
	for _, c := range cases {
		got := redactArgv(c.in)
		if strings.Contains(got, c.secret) {
			t.Errorf("redactArgv(%q) = %q, still contains secret %q", c.in, got, c.secret)
		}
		if !strings.Contains(got, "********") {
			t.Errorf("redactArgv(%q) = %q, expected mask", c.in, got)
		}
	}

	// A bare -p (interactive password prompt) has no value to leak and should
	// be left intact.
	if got := redactArgv("mysql -p"); got != "mysql -p" {
		t.Errorf("redactArgv(bare -p) = %q, want unchanged", got)
	}
}

func TestParseStatFields(t *testing.T) {
	cases := []struct {
		name      string
		stat      string
		wantStart uint64
		wantPPID  uint32
		wantComm  string
	}{
		{
			name:      "simple comm",
			stat:      "1234 (bash) S 1200 1234 1234 34816 1234 4194304 100 0 0 0 1 2 0 0 20 0 1 0 9876543 12345678 200 18446744073709551615",
			wantStart: 9876543,
			wantPPID:  1200,
			wantComm:  "bash",
		},
		{
			name:      "comm with spaces and parens",
			stat:      "4321 (sshd: root@pts/0) S 900 4321 4321 0 -1 4194304 50 0 0 0 0 0 0 0 20 0 1 0 5550000 9000000 100 0",
			wantStart: 5550000,
			wantPPID:  900,
			wantComm:  "sshd: root@pts/0",
		},
		{
			name:      "truncated returns zero",
			stat:      "1 (init) S 0 1 1",
			wantStart: 0,
			wantPPID:  0, // field 4 present here (0)
			wantComm:  "init",
		},
		{
			name:      "no paren returns zero",
			stat:      "garbage line without parens",
			wantStart: 0,
			wantPPID:  0,
			wantComm:  "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseStartTicks(c.stat); got != c.wantStart {
				t.Errorf("parseStartTicks = %d, want %d", got, c.wantStart)
			}
			if got := statPPID(c.stat); got != c.wantPPID {
				t.Errorf("statPPID = %d, want %d", got, c.wantPPID)
			}
			if got := statComm(c.stat); got != c.wantComm {
				t.Errorf("statComm = %q, want %q", got, c.wantComm)
			}
		})
	}
}

func TestDeterministicSessionIDStableAcrossStartValue(t *testing.T) {
	a := deterministicSessionID(4242, 9876543)
	b := deterministicSessionID(4242, 9876543)
	if a != b {
		t.Fatalf("expected stable id, got %q and %q", a, b)
	}
	if !strings.HasPrefix(a, "sshsess-") {
		t.Fatalf("unexpected id format: %q", a)
	}
	if deterministicSessionID(4242, 9876544) == a {
		t.Fatalf("expected different id for different start time")
	}
}

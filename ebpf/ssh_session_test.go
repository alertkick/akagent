//go:build linux

package ebpf

import (
	"strings"
	"testing"
	"time"
)

func testCache(entries map[uint32]*ProcessCacheEntry) *ProcessCache {
	if entries == nil {
		entries = map[uint32]*ProcessCacheEntry{}
	}
	return &ProcessCache{cache: entries, maxSize: 1024, enabled: true}
}

func loginEvent(shellPID int, ip, user string) *SecurityEvent {
	return &SecurityEvent{
		AgentType: AgentTypeNative,
		Timestamp: time.Now(),
		Rule:      "Process Execution",
		Category:  "process",
		Process:   ProcessInfo{PID: shellPID, Name: "bash", ExePath: "/usr/bin/bash", Username: user, TTY: 1},
		RawFields: map[string]interface{}{
			"ssh_login":     true,
			"ssh_source_ip": ip,
			"ssh_username":  user,
		},
	}
}

// sshdWorkerClone mimics the intermediate sshd worker process events the
// hydrator also stamps ssh_login on (parent=sshd, not a real shell). These
// must NOT open a session, else one login records several sessions.
func sshdWorkerClone(pid int) *SecurityEvent {
	return &SecurityEvent{
		AgentType: AgentTypeNative,
		Timestamp: time.Now(),
		Rule:      "Process Clone",
		Category:  "process",
		Process:   ProcessInfo{PID: pid, Name: "sshd", ExePath: "/usr/sbin/sshd"},
		RawFields: map[string]interface{}{"ssh_login": true},
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

func TestSSHSession_StartRewritesEvent(t *testing.T) {
	tr := NewSSHSessionTracker()
	cache := testCache(map[uint32]*ProcessCacheEntry{1000: {PID: 1000, StartTimeNS: 111}})

	ev := loginEvent(1000, "80.6.38.150", "root")
	tr.OnEvent(ev, cache, false)

	if ev.Rule != RuleSSHInboundLogin {
		t.Fatalf("rule = %q, want %q", ev.Rule, RuleSSHInboundLogin)
	}
	if ev.Category != "ssh_session" {
		t.Fatalf("category = %q", ev.Category)
	}
	sid, _ := ev.RawFields["ssh_session_id"].(string)
	if sid == "" {
		t.Fatal("missing ssh_session_id")
	}
	if ev.UUID != sid {
		t.Fatalf("uuid %q != session id %q", ev.UUID, sid)
	}
	if ev.RawFields["event_kind"] != "ssh_session" {
		t.Fatalf("event_kind = %v", ev.RawFields["event_kind"])
	}
	if ev.RawFields["status"] != "active" {
		t.Fatalf("status = %v", ev.RawFields["status"])
	}
	if !strings.Contains(ev.Output, "80.6.38.150") || !strings.Contains(ev.Output, "root") {
		t.Fatalf("summary = %q", ev.Output)
	}
	if len(tr.sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(tr.sessions))
	}
}

func TestSSHSession_OnlyShellExecveStartsSession(t *testing.T) {
	tr := NewSSHSessionTracker()
	cache := testCache(map[uint32]*ProcessCacheEntry{
		2000: {PID: 2000, StartTimeNS: 1},
		2001: {PID: 2001, StartTimeNS: 2},
		1000: {PID: 1000, StartTimeNS: 111},
	})

	// sshd worker clones (stamped ssh_login by the hydrator) must not start sessions.
	tr.OnEvent(sshdWorkerClone(2000), cache, false)
	tr.OnEvent(sshdWorkerClone(2001), cache, false)
	// The shell's pre-exec clone (also ssh_login-stamped) must not start one either.
	cloneOfShell := &SecurityEvent{
		AgentType: AgentTypeNative, Timestamp: time.Now(), Rule: "Process Clone", Category: "process",
		Process:   ProcessInfo{PID: 1000, Name: "sshd"},
		RawFields: map[string]interface{}{"ssh_login": true},
	}
	tr.OnEvent(cloneOfShell, cache, false)
	if len(tr.sessions) != 0 {
		t.Fatalf("clones/workers started %d sessions, want 0", len(tr.sessions))
	}

	// Only the shell's execve opens exactly one session.
	tr.OnEvent(loginEvent(1000, "10.0.0.1", "root"), cache, false)
	if len(tr.sessions) != 1 {
		t.Fatalf("shell execve produced %d sessions, want 1", len(tr.sessions))
	}
}

func TestSSHSession_DeterministicIDSurvivesRestart(t *testing.T) {
	cache := testCache(map[uint32]*ProcessCacheEntry{1000: {PID: 1000, StartTimeNS: 111}})

	// First agent run.
	trA := NewSSHSessionTracker()
	evA := loginEvent(1000, "10.0.0.1", "root")
	trA.OnEvent(evA, cache, false)
	idA := evA.RawFields["ssh_session_id"].(string)

	// Agent restarts: fresh tracker, same shell re-detected (same pid+startNS).
	trB := NewSSHSessionTracker()
	evB := loginEvent(1000, "10.0.0.1", "root")
	trB.OnEvent(evB, cache, false)
	idB := evB.RawFields["ssh_session_id"].(string)

	if idA == "" || idA != idB {
		t.Fatalf("session id not stable across restart: %q vs %q", idA, idB)
	}
}

func TestSSHSession_AttributesChildren(t *testing.T) {
	tr := NewSSHSessionTracker()
	cache := testCache(map[uint32]*ProcessCacheEntry{
		1000: {PID: 1000, StartTimeNS: 111},
		1500: {PID: 1500, ParentPID: 1000, StartTimeNS: 222}, // intermediate process
	})
	login := loginEvent(1000, "10.0.0.1", "ssidhu")
	tr.OnEvent(login, cache, false)
	sid := login.RawFields["ssh_session_id"].(string)

	// Direct child (fast path: PPID is the anchor).
	direct := execEvent(1200, 1000, 0, "/usr/bin/wget http://x")
	tr.OnEvent(direct, cache, false)
	if direct.RawFields["ssh_session_id"] != sid {
		t.Fatalf("direct child not attributed: %v", direct.RawFields["ssh_session_id"])
	}

	// Deep descendant (walk path: PPID=1500 → ParentPID 1000 = anchor).
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
	if got := evs[0].RawFields["process_count"]; got != 2 {
		t.Fatalf("process_count = %v, want 2", got)
	}
	if _, ok := evs[0].RawFields["commands"]; ok {
		t.Fatal("commands recorded with capture disabled")
	}
}

func TestSSHSession_CommandCaptureRedacts(t *testing.T) {
	tr := NewSSHSessionTracker()
	cache := testCache(map[uint32]*ProcessCacheEntry{1000: {PID: 1000, StartTimeNS: 111}})
	login := loginEvent(1000, "10.0.0.1", "root")
	tr.OnEvent(login, cache, true)

	tr.OnEvent(execEvent(1200, 1000, 0, "mysql -phunter2 appdb"), cache, true)

	evs := tr.sweep(time.Now(), cache, true)
	cmds, ok := evs[0].RawFields["commands"].([]sshSessionCommand)
	if !ok || len(cmds) != 1 {
		t.Fatalf("commands = %v", evs[0].RawFields["commands"])
	}
	if strings.Contains(cmds[0].Cmdline, "hunter2") {
		t.Fatalf("secret not redacted: %q", cmds[0].Cmdline)
	}
}

func TestSSHSession_PIDReuseIsolatesSessions(t *testing.T) {
	tr := NewSSHSessionTracker()
	cache := testCache(map[uint32]*ProcessCacheEntry{1000: {PID: 1000, StartTimeNS: 111}})
	tr.OnEvent(loginEvent(1000, "10.0.0.1", "a"), cache, false)

	// Same PID, different start time → a genuinely different shell.
	cache.cache[1000] = &ProcessCacheEntry{PID: 1000, StartTimeNS: 999}
	tr.OnEvent(loginEvent(1000, "10.0.0.2", "b"), cache, false)

	if len(tr.sessions) != 2 {
		t.Fatalf("sessions = %d, want 2 (pid reuse must not collide)", len(tr.sessions))
	}
}

func TestSSHSession_SweepClosesOnExit(t *testing.T) {
	tr := NewSSHSessionTracker()
	cache := testCache(map[uint32]*ProcessCacheEntry{1000: {PID: 1000, StartTimeNS: 111}})
	login := loginEvent(1000, "10.0.0.1", "root")
	login.Timestamp = time.Now().Add(-1 * time.Minute)
	tr.OnEvent(login, cache, false)

	// Shell gone from the cache → session should close.
	delete(cache.cache, 1000)
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

func TestSSHSession_SweepClosesOnIdleTTL(t *testing.T) {
	tr := NewSSHSessionTracker()
	cache := testCache(map[uint32]*ProcessCacheEntry{1000: {PID: 1000, StartTimeNS: 111}})
	tr.OnEvent(loginEvent(1000, "10.0.0.1", "root"), cache, false)

	// Anchor still present, but no activity past the TTL.
	future := time.Now().Add(sshSessionInactivityTTL + time.Minute)
	evs := tr.sweep(future, cache, false)
	if len(evs) != 1 || evs[0].RawFields["status"] != "closed" {
		t.Fatalf("expected idle close, got %+v", evs)
	}
}

func TestSSHSession_CommandCapIsBounded(t *testing.T) {
	tr := NewSSHSessionTracker()
	cache := testCache(map[uint32]*ProcessCacheEntry{1000: {PID: 1000, StartTimeNS: 111}})
	tr.OnEvent(loginEvent(1000, "10.0.0.1", "root"), cache, true)

	for i := 0; i < maxCommandsPerSSHSession+50; i++ {
		tr.OnEvent(execEvent(2000+i, 1000, 0, "/bin/true"), cache, true)
	}
	evs := tr.sweep(time.Now(), cache, true)
	cmds := evs[0].RawFields["commands"].([]sshSessionCommand)
	if len(cmds) != maxCommandsPerSSHSession {
		t.Fatalf("commands len = %d, want cap %d", len(cmds), maxCommandsPerSSHSession)
	}
	if got := evs[0].RawFields["process_count"]; got != maxCommandsPerSSHSession+50 {
		t.Fatalf("process_count = %v, want %d", got, maxCommandsPerSSHSession+50)
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

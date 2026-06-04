//go:build linux

package ebpf

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SSHSessionTracker turns an inbound SSH login into a long-lived "session"
// rather than a scatter of disconnected process events. When the SSH hydrator
// classifies an event as an sshd-spawned login shell, the tracker opens a
// session anchored on that shell's PID, attributes every process subsequently
// run beneath that shell to the session, and emits a session event that is
// periodically re-emitted (under a stable uuid the API upserts on) so its
// lifecycle — login time, last activity, process count, logout/duration —
// stays current on the dashboard.
//
// Privacy: by default the session records only its lifecycle and a numeric
// count of processes started. The actual command lines are recorded ONLY when
// the per-server SSHSessionCommandCapture toggle is on, and even then each
// command line is redacted at the source (see redactArgv) so secrets passed as
// argv never leave the host.
//
// Concurrency: the tracker owns its own mutex and never touches the agent's
// mu — the 1.7.x startup deadlock came from a callback re-entering the agent's
// RWMutex. Per-event work (OnEvent) is cheap map ops plus a depth-capped,
// lock-free ancestry walk. The heartbeat (sweep) snapshots and emits outside
// any lock held across I/O.
type SSHSessionTracker struct {
	mu         sync.Mutex
	sessions   map[sshSessionKey]*sshSessionState
	anchorPIDs map[uint32]sshSessionKey // shell pid → session key (fast attribution)
}

const (
	// maxConcurrentSSHSessions bounds memory: new logins past this are not
	// tracked (logged once) until existing sessions close.
	maxConcurrentSSHSessions = 1024
	// maxCommandsPerSSHSession caps the per-session command ledger; the true
	// total is kept separately in processCount so the cap never loses it.
	maxCommandsPerSSHSession = 100
	// sshSessionInactivityTTL closes a session whose shell produced no new
	// process for this long, when the shell's exit can't otherwise be confirmed.
	sshSessionInactivityTTL = 7 * time.Minute
	// sshAncestryWalkMaxDepth caps the parent-chain walk so a pathological
	// process tree can't turn per-event attribution into a long loop.
	sshAncestryWalkMaxDepth = 16
)

// sshSessionKey identifies a session by shell PID *and* its start time, so a
// recycled PID belonging to a different process can never be mistaken for the
// original login shell.
type sshSessionKey struct {
	pid     uint32
	startNS uint64
}

// sshSessionCommand is one process run during a session (only populated when
// command capture is enabled). Cmdline is already redacted.
type sshSessionCommand struct {
	PID     int       `json:"pid"`
	Exe     string    `json:"exe,omitempty"`
	Cmdline string    `json:"cmdline,omitempty"`
	TS      time.Time `json:"ts"`
}

type sshSessionState struct {
	sessionID    string
	anchorPID    uint32
	startNS      uint64
	sourceIP     string
	username     string
	tty          int
	loginTime    time.Time
	lastActivity time.Time
	processCount int
	commands     []sshSessionCommand
}

// NewSSHSessionTracker returns an empty tracker ready to receive events.
func NewSSHSessionTracker() *SSHSessionTracker {
	return &SSHSessionTracker{
		sessions:   make(map[sshSessionKey]*sshSessionState),
		anchorPIDs: make(map[uint32]sshSessionKey),
	}
}

// OnEvent is called for every event after SSH hydration. It opens a session
// when the event is an sshd login shell, and otherwise attributes process
// executions to an existing session. Safe to call on every event.
func (t *SSHSessionTracker) OnEvent(event *SecurityEvent, cache *ProcessCache, captureCommands bool) {
	if t == nil || event == nil {
		return
	}
	if isSSHLoginShellEvent(event) {
		t.startSession(event, cache)
		return
	}
	// Attribute only execve ("a command ran") — counting clone too would
	// double-count the fork+exec pair, and "processes started during the
	// shell" is exactly the execve signal.
	if event.Category == "process" && event.Rule == "Process Execution" {
		t.attribute(event, cache, captureCommands)
	}
}

// isSSHLoginShellEvent reports whether this event is the interactive login
// shell opening an SSH session.
//
// The SSH hydrator stamps ssh_login=true generously — including on the
// intermediate sshd worker processes (parent=sshd, empty cmdline) that fork
// before the user's shell, and on the shell's pre-exec clone. Starting a
// session on any of those would record several sessions for one login. So we
// open a session only on the shell's own execve, identified by the process
// being a real interactive shell. Clone events (and the sshd workers) are
// ignored for session-start; the shell's children are picked up by attribute.
func isSSHLoginShellEvent(event *SecurityEvent) bool {
	if v, _ := event.RawFields["ssh_login"].(bool); !v {
		return false
	}
	if event.Rule != "Process Execution" {
		return false
	}
	return isInteractiveShellName(event.Process.Name) || isInteractiveShellName(baseName(event.Process.ExePath))
}

// isInteractiveShellName reports whether a process name/exe basename is a
// common interactive login shell (mirrors the set isLoginShellCmdline uses).
func isInteractiveShellName(name string) bool {
	name = strings.TrimPrefix(name, "-") // login shells set argv[0] to "-bash"
	switch name {
	case "bash", "sh", "zsh", "dash", "fish", "ash", "ksh":
		return true
	}
	return false
}

func baseName(p string) string {
	if idx := strings.LastIndex(p, "/"); idx >= 0 {
		return p[idx+1:]
	}
	return p
}

// startSession opens (or no-ops on an already-open) session for the login
// shell, then rewrites the in-flight event into the session-start event so it
// lands as the first version of the session document.
func (t *SSHSessionTracker) startSession(event *SecurityEvent, cache *ProcessCache) {
	shellPID := uint32(event.Process.PID)
	if shellPID == 0 {
		return
	}
	key := sshSessionKey{pid: shellPID, startNS: lookupStartNS(cache, shellPID)}

	t.mu.Lock()
	st, ok := t.sessions[key]
	if !ok {
		if len(t.sessions) >= maxConcurrentSSHSessions {
			t.mu.Unlock()
			nativeLog.Warn().Int("max", maxConcurrentSSHSessions).
				Msg("SSH session tracker at capacity; new login not tracked")
			return
		}
		st = &sshSessionState{
			sessionID:    deterministicSessionID(shellPID, key.startNS),
			anchorPID:    shellPID,
			startNS:      key.startNS,
			sourceIP:     rawString(event.RawFields, "ssh_source_ip"),
			username:     rawString(event.RawFields, "ssh_username"),
			tty:          event.Process.TTY,
			loginTime:    event.Timestamp,
			lastActivity: event.Timestamp,
		}
		if st.username == "" {
			st.username = event.Process.Username
		}
		if st.loginTime.IsZero() {
			st.loginTime = time.Now()
			st.lastActivity = st.loginTime
		}
		t.sessions[key] = st
		t.anchorPIDs[shellPID] = key
	}
	st.stamp(event, "active", time.Time{}, false)
	t.mu.Unlock()
}

// attribute links a process execution to the session it descends from (if any),
// bumping the count and — when enabled — recording the redacted command line.
func (t *SSHSessionTracker) attribute(event *SecurityEvent, cache *ProcessCache, captureCommands bool) {
	key, ok := t.findAncestorSession(event, cache)
	if !ok {
		return
	}
	t.mu.Lock()
	st := t.sessions[key]
	if st == nil {
		t.mu.Unlock()
		return
	}
	st.processCount++
	st.lastActivity = time.Now()
	if captureCommands {
		cmd := sshSessionCommand{
			PID:     event.Process.PID,
			Exe:     event.Process.ExePath,
			Cmdline: redactArgv(event.Process.Cmdline),
			TS:      st.lastActivity,
		}
		if len(st.commands) >= maxCommandsPerSSHSession {
			st.commands = append(st.commands[1:], cmd) // ring: drop oldest
		} else {
			st.commands = append(st.commands, cmd)
		}
	}
	sessionID := st.sessionID
	t.mu.Unlock()

	if event.RawFields == nil {
		event.RawFields = make(map[string]interface{})
	}
	event.RawFields["ssh_session_id"] = sessionID
}

// findAncestorSession returns the session key for the nearest tracked shell
// ancestor of the event's process, if any. The parent chain is built lock-free
// (direct parent + grandparent from the event, then a depth-capped walk via the
// process cache), and the anchor-set membership test takes the lock once.
func (t *SSHSessionTracker) findAncestorSession(event *SecurityEvent, cache *ProcessCache) (sshSessionKey, bool) {
	chain := make([]uint32, 0, sshAncestryWalkMaxDepth+2)
	if ppid := uint32(event.Process.PPID); ppid > 1 {
		chain = append(chain, ppid)
	}
	if gp := event.Process.GrandparentPID; gp > 1 {
		chain = append(chain, uint32(gp))
	}
	if cache != nil {
		cur := uint32(event.Process.PPID)
		for depth := 0; depth < sshAncestryWalkMaxDepth; depth++ {
			if cur <= 1 {
				break
			}
			entry := cache.Lookup(cur)
			if entry == nil {
				break
			}
			next := entry.ParentPID
			if next == cur || next <= 1 {
				break
			}
			chain = append(chain, next)
			cur = next
		}
	}
	if len(chain) == 0 {
		return sshSessionKey{}, false
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.anchorPIDs) == 0 {
		return sshSessionKey{}, false
	}
	for _, pid := range chain {
		if k, ok := t.anchorPIDs[pid]; ok {
			return k, true
		}
	}
	return sshSessionKey{}, false
}

// sweep is the heartbeat: it returns a session event for every live session
// (status "active") and a final event for sessions whose shell has exited or
// gone idle (status "closed", with logout time + duration), evicting the closed
// ones. The caller emits the returned events; nothing here touches the channel.
func (t *SSHSessionTracker) sweep(now time.Time, cache *ProcessCache, captureCommands bool) []SecurityEvent {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.sessions) == 0 {
		return nil
	}
	out := make([]SecurityEvent, 0, len(t.sessions))
	for key, st := range t.sessions {
		closed := false
		// Confirm the shell still exists: gone from the cache, or its PID slot
		// reused by a different process (StartTimeNS changed) → session ended.
		if cache != nil {
			entry := cache.Lookup(st.anchorPID)
			if entry == nil || (st.startNS != 0 && entry.StartTimeNS != st.startNS) {
				closed = true
			}
		}
		if !closed && now.Sub(st.lastActivity) > sshSessionInactivityTTL {
			closed = true
		}
		status := "active"
		if closed {
			status = "closed"
		}
		ev := SecurityEvent{AgentType: AgentTypeNative, Timestamp: now}
		st.stamp(&ev, status, now, captureCommands)
		out = append(out, ev)
		if closed {
			delete(t.sessions, key)
			delete(t.anchorPIDs, st.anchorPID)
		}
	}
	return out
}

// stamp writes the session's current state onto event. Callers hold t.mu (the
// state fields are read here). For status "closed" it records logout_time and
// duration_seconds using now.
func (st *sshSessionState) stamp(event *SecurityEvent, status string, now time.Time, captureCommands bool) {
	event.UUID = st.sessionID
	event.Rule = RuleSSHInboundLogin
	event.Category = "ssh_session"
	event.Source = "session"
	// High priority so the event bypasses agent-side dedup and rate limiting
	// and is delivered promptly; these are low-volume audit events.
	event.Priority = PriorityError

	summary := st.summary(status, now)
	event.Output = summary
	event.Message = summary

	if event.RawFields == nil {
		event.RawFields = make(map[string]interface{})
	}
	rf := event.RawFields
	rf["summary"] = summary
	rf["event_kind"] = "ssh_session"
	rf["ssh_session_id"] = st.sessionID
	rf["ssh_login"] = true
	rf["status"] = status
	rf["process_count"] = st.processCount
	rf["login_time"] = st.loginTime.UTC().Format(time.RFC3339)
	rf["last_activity"] = st.lastActivity.UTC().Format(time.RFC3339)
	if st.sourceIP != "" {
		rf["ssh_source_ip"] = st.sourceIP
		if event.Network.SrcIP == "" {
			event.Network.SrcIP = st.sourceIP
		}
	}
	if st.username != "" {
		rf["ssh_username"] = st.username
	}
	if st.tty > 0 {
		rf["tty"] = st.tty
	}
	if status == "closed" {
		rf["logout_time"] = now.UTC().Format(time.RFC3339)
		rf["duration_seconds"] = int(now.Sub(st.loginTime).Seconds())
	}
	if captureCommands {
		// Always emit the commands array when capture is on — even when empty —
		// so the dashboard can tell "capture enabled, nothing recorded yet"
		// (empty array) from "capture disabled" (field absent). Without this a
		// freshly-enabled or idle session looks identical to a disabled one.
		cmds := make([]sshSessionCommand, len(st.commands))
		copy(cmds, st.commands)
		rf["commands"] = cmds
	}
	event.Tags = appendUniqueTag(event.Tags, "ssh_session")
}

// summary is the human-readable one-liner. The endpoint may rewrite it to a
// reason-specific phrasing (off-hours / weekend / unknown IP) once it has run
// rule matching; this is the always-available base.
func (st *sshSessionState) summary(status string, now time.Time) string {
	who := st.username
	if who == "" {
		who = "unknown user"
	}
	from := st.sourceIP
	if from == "" {
		from = "unknown source"
	}
	if status == "closed" {
		dur := now.Sub(st.loginTime).Round(time.Second)
		return fmt.Sprintf("SSH login from %s by %s ended after %s (%d processes)", from, who, dur, st.processCount)
	}
	return fmt.Sprintf("SSH login from %s by %s", from, who)
}

func lookupStartNS(cache *ProcessCache, pid uint32) uint64 {
	if cache == nil {
		return 0
	}
	if e := cache.Lookup(pid); e != nil {
		return e.StartTimeNS
	}
	return 0
}

func rawString(m map[string]interface{}, k string) string {
	if m == nil {
		return ""
	}
	s, _ := m[k].(string)
	return s
}

var (
	hostnameOnce sync.Once
	cachedHost   string
)

func hostname() string {
	hostnameOnce.Do(func() {
		if h, err := os.Hostname(); err == nil {
			cachedHost = h
		}
	})
	return cachedHost
}

// deterministicSessionID derives a stable session id from the host and the
// shell's identity (pid + kernel start time). Because it's a pure function of
// the shell — not of the moment we detected it — re-detecting the same shell
// (e.g. a buffered event replayed after an agent restart) yields the same id,
// so the API upsert updates the same session document instead of creating a
// duplicate. pid+startNS is unique per process on a host; the hostname guards
// against collisions across hosts in a tenant.
func deterministicSessionID(pid uint32, startNS uint64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d", hostname(), pid, startNS)))
	return "sshsess-" + hex.EncodeToString(sum[:12])
}

// ── argv redaction ──────────────────────────────────────────────────────────
//
// Best-effort masking of secrets passed on the command line, applied before a
// captured command leaves the host. It is conservative (a missed secret is
// worse than an over-masked benign arg, but over-masking is acceptable). It
// can never be exhaustive — operators who need a hard guarantee should leave
// command capture off entirely.

var argvRedactors = []*regexp.Regexp{
	// mysql/pg style short password glued to the flag: `-pSECRET` (a bare `-p`
	// with the value on the next arg, i.e. followed by space, is left alone).
	regexp.MustCompile(`(?i)(\s-p)(\S+)`),
	// long options carrying a secret value: --password=, --token tok, etc.
	regexp.MustCompile(`(?i)(--(?:password|passwd|pass|secret|token|api[-_]?key|key|auth|credential)[=\s]+)(\S+)`),
	// Authorization headers (e.g. inside `curl -H 'Authorization: Bearer …'`).
	regexp.MustCompile(`(?i)(authorization:\s*(?:bearer|basic)\s+)(\S+)`),
	// sensitive KEY=VALUE environment assignments.
	regexp.MustCompile(`(?i)\b([A-Za-z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)[A-Za-z0-9_]*=)(\S+)`),
}

// redactArgv masks known secret patterns in a command line, preserving the
// flag/key so the command is still legible.
func redactArgv(cmdline string) string {
	if cmdline == "" {
		return ""
	}
	out := cmdline
	for _, re := range argvRedactors {
		out = re.ReplaceAllString(out, "${1}********")
	}
	return out
}

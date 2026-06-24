//go:build linux

package ebpf

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SSHSessionTracker turns an inbound SSH connection into a long-lived "session"
// rather than a scatter of disconnected process events. The session is anchored
// on the per-connection sshd worker process (OpenSSH 9.8+ "sshd-session", or the
// older "sshd: user@pts/N" privsep child) — NOT on the interactive login shell.
// The worker's lifetime IS the connection's: it appears when the connection is
// accepted and dies when the client disconnects, so:
//
//   - one connection → one session (the worker pid dedupes it), covering not
//     just interactive shells but sftp, scp, `ssh host cmd`, and port-forwards;
//   - close is driven by the worker's process death (observed via /proc), never
//     by a heartbeat/inactivity timeout — an idle-but-open connection stays
//     "active";
//   - the session survives an agent restart: on start the tracker re-adopts
//     every live worker from /proc under the same deterministic uuid, so it
//     resumes watching and still emits the close when the worker later exits.
//
// Identity & dedup: the session uuid is sha256(host|workerPID|workerStartTicks)
// where workerStartTicks is the kernel's real process start time from
// /proc/<pid>/stat (invariant for the process's life), so re-detecting or
// re-adopting the same worker yields the same uuid and the endpoint upserts onto
// one document instead of minting a new "active" row.
//
// Classification: on open, the source IP is checked against the allowlist
// (AlertPolicy.AllowedSourceIPs, shared with ac-007 / SSH lockdown). A login
// from an address not on the list is classified "untrusted" and emitted at
// CRITICAL priority immediately at connect time, so the alert does not wait for
// the next heartbeat.
//
// Privacy: by default the session records only its lifecycle and a numeric count
// of processes started. Command lines are recorded ONLY when the per-server
// SSHSessionCommandCapture toggle is on, and even then each is redacted at the
// source (see redactArgv) so secrets passed as argv never leave the host.
//
// Concurrency: the tracker owns its own mutex and never touches the agent's mu.
// Per-event work is cheap map ops plus a depth-capped, lock-free ancestry walk.
// The heartbeat (sweep) snapshots and emits outside any lock held across I/O.
type SSHSessionTracker struct {
	mu         sync.Mutex
	sessions   map[sshSessionKey]*sshSessionState
	anchorPIDs map[uint32]sshSessionKey // worker pid → session key (fast attribution)

	// emit pushes a synthetic session event to the agent's channel immediately
	// (used for the session-open event so an untrusted login alerts at connect
	// time). Nil-safe: when unset, the open event is published by the next
	// sweep instead.
	emit func(SecurityEvent)

	// allowlistFn returns the current source-IP allowlist (CIDRs or IPs). Wired
	// to the SSH lockdown manager's AllowedSourceIPs so operators curate one
	// list. Nil → every resolved IP classifies as untrusted is avoided; see
	// classify (a nil/empty allowlist yields "untrusted" only for resolved IPs).
	allowlistFn func() []string

	// resolveIPFn resolves a worker pid to its remote source IP + username when
	// the triggering event did not already carry it (worker-own events aren't
	// hydrated). Wired to the SSH hydrator. Nil-safe.
	resolveIPFn func(workerPID int, username string, tty int) (ip, user string)
}

const (
	// maxConcurrentSSHSessions bounds memory: new connections past this are not
	// tracked (logged once) until existing sessions close.
	maxConcurrentSSHSessions = 1024
	// maxCommandsPerSSHSession caps the per-session command ledger; the true
	// total is kept separately in processCount so the cap never loses it.
	maxCommandsPerSSHSession = 100
	// sshAncestryWalkMaxDepth caps the parent-chain walk so a pathological
	// process tree can't turn per-event attribution into a long loop.
	sshAncestryWalkMaxDepth = 16
)

// SSH session source-IP classifications.
const (
	sshClassTrusted    = "trusted"    // source IP matched the allowlist
	sshClassUntrusted  = "untrusted"  // source IP resolved, allowlist set, not on it → alert
	sshClassUnverified = "unverified" // source IP resolved but no allowlist configured → no judgement
	sshClassUnresolved = "unresolved" // source IP could not be determined
)

// sshSessionKey identifies a session by the connection worker's PID *and* its
// kernel start time, so a recycled PID belonging to a different connection can
// never be mistaken for the original.
type sshSessionKey struct {
	pid        uint32
	startTicks uint64
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
	sessionID      string
	anchorPID      uint32 // the per-connection sshd worker
	listenerPID    uint32 // the sshd listener (worker's parent), best-effort
	startTicks     uint64 // worker /proc start ticks — liveness + uuid identity
	startNS        uint64 // BPF cache start ns — fallback identity when /proc unreadable
	sourceIP       string
	username       string
	tty            int
	classification string
	sessionType    string // shell | sftp | exec | "" (unknown)
	loginTime      time.Time
	lastActivity   time.Time
	processCount   int
	commands       []sshSessionCommand
}

// NewSSHSessionTracker returns an empty tracker ready to receive events.
func NewSSHSessionTracker() *SSHSessionTracker {
	return &SSHSessionTracker{
		sessions:   make(map[sshSessionKey]*sshSessionState),
		anchorPIDs: make(map[uint32]sshSessionKey),
	}
}

// SetEmit wires the immediate-emit callback (typically a non-blocking send to
// the agent's event channel). Safe to call once during listener startup.
func (t *SSHSessionTracker) SetEmit(fn func(SecurityEvent)) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.emit = fn
	t.mu.Unlock()
}

// SetAllowlistFunc wires the source-IP allowlist provider (the SSH lockdown
// manager's AllowedSourceIPs).
func (t *SSHSessionTracker) SetAllowlistFunc(fn func() []string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.allowlistFn = fn
	t.mu.Unlock()
}

// SetResolveIPFunc wires the worker-pid → source-IP resolver (the SSH hydrator).
func (t *SSHSessionTracker) SetResolveIPFunc(fn func(workerPID int, username string, tty int) (string, string)) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.resolveIPFn = fn
	t.mu.Unlock()
}

// OnEvent is called for every event after SSH hydration. It opens a session
// when the event is (or is a child of) a per-connection sshd worker, and
// attributes process executions to an existing session. Safe to call on every
// event.
func (t *SSHSessionTracker) OnEvent(event *SecurityEvent, cache *ProcessCache, captureCommands bool) {
	if t == nil || event == nil {
		return
	}
	if worker, listener, ok := workerForEvent(event); ok {
		t.openSession(worker, listener, event, cache)
		// Fall through: a child of the worker (the shell, sftp-server, the
		// exec'd command) is itself a process run within the connection, so let
		// attribute() count it below.
	}
	// Attribute only execve ("a command ran") — counting clone too would
	// double-count the fork+exec pair.
	if event.Category == "process" && event.Rule == "Process Execution" {
		t.attribute(event, cache, captureCommands)
	}
}

// workerForEvent decides which per-connection sshd worker, if any, this event
// implies a session for, returning (workerPID, listenerPID, ok). Two cases:
//
//  1. The event IS the worker's own clone/exec (sshd-session, or "sshd: u@..").
//     Then workerPID is the event's own PID and listenerPID its parent.
//  2. The event is a direct child of a worker (shell/sftp/exec). Then the
//     worker is the event's parent. The listener is unknown from here (0).
//
// sshd-named processes are excluded from case 2 so the worker's own pre-exec
// clone (parented by the listener) never anchors a session on the listener.
func workerForEvent(event *SecurityEvent) (worker, listener uint32, ok bool) {
	switch event.Rule {
	case "Process Clone", "Process Execution":
	default:
		return 0, 0, false
	}
	p := event.Process
	if isSSHWorkerProcess(p) && p.PID > 1 {
		lp := uint32(0)
		if p.PPID > 1 {
			lp = uint32(p.PPID)
		}
		return uint32(p.PID), lp, true
	}
	if isParentSSHD(p) && p.PPID > 1 && !isSSHDProcessName(p) {
		return uint32(p.PPID), 0, true
	}
	return 0, 0, false
}

// isSSHWorkerProcess reports whether p is a per-connection sshd worker (the
// process whose lifetime equals the connection's).
func isSSHWorkerProcess(p ProcessInfo) bool {
	name := procName(p)
	// OpenSSH 9.8+ (Ubuntu 24.10+, Fedora 41+): the per-connection worker is a
	// distinct binary, unambiguous by name.
	if name == "sshd-session" {
		return true
	}
	// Pre-9.8: the worker re-execs as "sshd" and rewrites its title to
	// "sshd: user@pts/N" (interactive) or "sshd: user" (exec/sftp). The
	// privsep/listener forms — "sshd: [listener]", "sshd: user [priv]",
	// "sshd: user [net]" — are NOT per-connection sessions, so require the
	// user@/user form and reject the bracketed monitor forms.
	if name == "sshd" && strings.Contains(p.Cmdline, "sshd:") {
		if strings.Contains(p.Cmdline, "[") {
			return false
		}
		// "sshd: user@notty" / "sshd: user@pts/0" / "sshd: user" (exec).
		title := p.Cmdline
		if i := strings.Index(title, "sshd:"); i >= 0 {
			title = strings.TrimSpace(title[i+len("sshd:"):])
		}
		return title != "" && !strings.HasPrefix(title, "[")
	}
	return false
}

// isSSHDProcessName reports whether the process itself is an sshd binary
// (listener or worker), used to keep case 2 of workerForEvent from anchoring on
// sshd processes.
func isSSHDProcessName(p ProcessInfo) bool {
	name := procName(p)
	return name == "sshd" || name == "sshd-session"
}

func procName(p ProcessInfo) string {
	if p.Name != "" {
		return p.Name
	}
	return baseName(p.ExePath)
}

// isInteractiveShellName reports whether a process name/exe basename is a common
// interactive login shell.
func isInteractiveShellName(name string) bool {
	name = strings.TrimPrefix(name, "-") // login shells set argv[0] to "-bash"
	switch name {
	case "bash", "sh", "zsh", "dash", "fish", "ash", "ksh":
		return true
	}
	return false
}

// classifySessionType labels what the connection is doing, from its first
// observed child process.
func classifySessionType(p ProcessInfo) string {
	name := procName(p)
	switch {
	case isInteractiveShellName(name):
		return "shell"
	case name == "sftp-server" || strings.Contains(p.Cmdline, "sftp-server"):
		return "sftp"
	case name == "" || name == "sshd" || name == "sshd-session":
		return "" // worker-own open; type not yet known
	default:
		return "exec"
	}
}

func baseName(p string) string {
	if idx := strings.LastIndex(p, "/"); idx >= 0 {
		return p[idx+1:]
	}
	return p
}

// openSession opens (or no-ops on an already-open) session for a connection
// worker, then classifies the source IP and emits the session-open event
// immediately so an untrusted login alerts at connect time.
func (t *SSHSessionTracker) openSession(workerPID, listenerPID uint32, event *SecurityEvent, cache *ProcessCache) {
	if workerPID <= 1 {
		return
	}

	// The worker's kernel start time is the durable identity that makes the
	// session uuid stable across agent/BPF restarts (see procStartTicks). Fall
	// back to the BPF cache value only when /proc is unreadable.
	startTicks := procStartTicksFn(workerPID)
	startNS := lookupStartNS(cache, workerPID)
	if startTicks == 0 {
		startTicks = startNS
	}
	key := sshSessionKey{pid: workerPID, startTicks: startTicks}

	t.mu.Lock()
	if _, exists := t.sessions[key]; exists {
		t.mu.Unlock()
		return
	}
	if len(t.sessions) >= maxConcurrentSSHSessions {
		t.mu.Unlock()
		nativeLog.Warn().Int("max", maxConcurrentSSHSessions).
			Msg("SSH session tracker at capacity; new connection not tracked")
		return
	}
	st := &sshSessionState{
		sessionID:   deterministicSessionID(workerPID, startTicks),
		anchorPID:   workerPID,
		listenerPID: listenerPID,
		startTicks:  startTicks,
		startNS:     startNS,
		sourceIP:    rawString(event.RawFields, "ssh_source_ip"),
		username:    rawString(event.RawFields, "ssh_username"),
		tty:         event.Process.TTY,
		sessionType: classifySessionType(event.Process),
		loginTime:   event.Timestamp,
	}
	if st.username == "" {
		st.username = event.Process.Username
	}
	if st.loginTime.IsZero() {
		// Re-adopted sessions arrive with no event timestamp; reconstruct the
		// real login instant from the worker's start ticks so duration is right.
		st.loginTime = ticksToWall(startTicks)
	}
	if st.loginTime.IsZero() {
		st.loginTime = time.Now()
	}
	st.lastActivity = st.loginTime
	t.sessions[key] = st
	t.anchorPIDs[workerPID] = key
	emit := t.emit
	resolve := t.resolveIPFn
	t.mu.Unlock()

	// Best-effort source-IP enrichment when the triggering event didn't carry
	// it (worker-own events aren't hydrated). Done outside the lock — may read
	// auth.log / run `who`.
	ip := st.sourceIP
	usr := st.username
	if ip == "" && resolve != nil {
		if rip, ruser := resolve(int(workerPID), usr, st.tty); rip != "" {
			ip = rip
			if usr == "" {
				usr = ruser
			}
		}
	}
	class := t.classify(ip)

	t.mu.Lock()
	st.sourceIP = ip
	if usr != "" {
		st.username = usr
	}
	st.classification = class
	var openEv SecurityEvent
	if emit != nil {
		openEv = SecurityEvent{AgentType: AgentTypeNative, Timestamp: st.loginTime}
		st.stamp(&openEv, "active", time.Time{}, false)
	}
	t.mu.Unlock()

	if emit != nil {
		emit(openEv)
	}
}

// classify maps a source IP to a trust classification using the allowlist.
func (t *SSHSessionTracker) classify(ip string) string {
	if ip == "" {
		return sshClassUnresolved
	}
	var list []string
	if t.allowlistFn != nil {
		list = t.allowlistFn()
	}
	if len(list) == 0 {
		// No allowlist configured — there's no policy to judge the source
		// against, so don't cry wolf on every login. Operators opt into the
		// trusted/untrusted distinction (and the connect-time alert) by curating
		// AllowedSourceIPs.
		return sshClassUnverified
	}
	if ipAllowed(ip, list) {
		return sshClassTrusted
	}
	return sshClassUntrusted
}

// ipAllowed reports whether ip matches any allowlist entry (exact IP or CIDR).
func ipAllowed(ip string, allowlist []string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, entry := range allowlist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if _, cidr, err := net.ParseCIDR(entry); err == nil && cidr.Contains(parsed) {
				return true
			}
			continue
		}
		if eip := net.ParseIP(entry); eip != nil && eip.Equal(parsed) {
			return true
		}
	}
	return false
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
	if st.sessionType == "" {
		st.sessionType = classifySessionType(event.Process)
	}
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

// findAncestorSession returns the session key for the nearest tracked worker
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

// procAliveFn is the liveness probe used by sweep, indirected so tests can
// supply fake pids without a real /proc.
var procAliveFn = procAlive

// sweep is the heartbeat: it returns a session event for every live session
// (status "active") and a final event for sessions whose worker has exited
// (status "closed", with logout time + duration), evicting the closed ones.
// Liveness is authoritative — the worker either exists in /proc with a matching
// start time or it's gone — so an idle-but-open connection is never closed.
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
		closed := !procAliveFn(st.anchorPID, st.startTicks)
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

// Readopt re-opens a session for every per-connection sshd worker currently
// alive on the host. Called once at agent startup so connections that were open
// before the agent (re)started are tracked again under their stable uuid, and
// will still emit a proper close when their worker later exits — without this,
// a restart orphans every in-flight session as permanently "active".
func (t *SSHSessionTracker) Readopt(cache *ProcessCache) {
	if t == nil {
		return
	}
	workers := scanProcForSSHWorkers()
	for _, w := range workers {
		ev := &SecurityEvent{
			AgentType: AgentTypeNative,
			Rule:      "Process Execution",
			Category:  "process",
			Process: ProcessInfo{
				PID:      int(w.pid),
				PPID:     int(w.ppid),
				Name:     w.comm,
				Cmdline:  w.cmdline,
				Username: w.username,
			},
			RawFields: map[string]interface{}{},
		}
		t.openSession(w.pid, w.ppid, ev, cache)
	}
	if len(workers) > 0 {
		nativeLog.Info().Int("count", len(workers)).Msg("Re-adopted live SSH connection sessions on startup")
	}
}

// stamp writes the session's current state onto event. Callers hold t.mu. For
// status "closed" it records logout_time and duration_seconds using now.
func (st *sshSessionState) stamp(event *SecurityEvent, status string, now time.Time, captureCommands bool) {
	event.UUID = st.sessionID
	event.Rule = RuleSSHInboundLogin
	event.Category = "ssh_session"
	event.Source = "session"
	// Synthetic session events carry no kernel-sourced hostname; stamp the host
	// explicitly so the endpoint's "fill if empty" enrichment doesn't fall back
	// to the endpoint node's own hostname (which mis-attributes the session in
	// cross-host views). host_uuid is set by the endpoint from the agent id.
	event.Hostname = hostname()
	// High priority so the event bypasses agent-side rate limiting and is
	// delivered promptly. An untrusted source IP is escalated to CRITICAL so it
	// alerts immediately at connect time.
	event.Priority = PriorityError
	if st.classification == sshClassUntrusted {
		event.Priority = PriorityCritical
	}

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
	rf["classification"] = st.classification
	// PID/PPID make duplicates legible on the dashboard and pin the session to a
	// concrete kernel object. ssh_anchor_pid is the connection worker;
	// ssh_anchor_ppid is the sshd listener (best-effort).
	rf["ssh_anchor_pid"] = int(st.anchorPID)
	rf["ssh_connection_pid"] = int(st.anchorPID)
	if st.listenerPID > 0 {
		rf["ssh_anchor_ppid"] = int(st.listenerPID)
	}
	if st.sessionType != "" {
		rf["session_type"] = st.sessionType
	}
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
		// from "capture disabled" (field absent).
		cmds := make([]sshSessionCommand, len(st.commands))
		copy(cmds, st.commands)
		rf["commands"] = cmds
	}
	event.Tags = appendUniqueTag(event.Tags, "ssh_session")
	if st.classification == sshClassUntrusted {
		event.Tags = appendUniqueTag(event.Tags, "ssh_untrusted_source")
	}
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
	prefix := ""
	if st.classification == sshClassUntrusted {
		prefix = "Untrusted "
	}
	if status == "closed" {
		dur := now.Sub(st.loginTime).Round(time.Second)
		return fmt.Sprintf("%sSSH login from %s by %s ended after %s (%d processes)", prefix, from, who, dur, st.processCount)
	}
	return fmt.Sprintf("%sSSH login from %s by %s", prefix, from, who)
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
// connection worker's identity (pid + its kernel start time). Because it's a
// pure function of the worker — not of the moment we detected it — re-detecting
// or re-adopting the same worker yields the same id, so the endpoint upsert
// updates the same session document instead of creating a duplicate. The start
// value MUST be the kernel's real process start time (see procStartTicks), not
// a value captured at observation time, or the id is no longer restart-stable.
func deterministicSessionID(pid uint32, start uint64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d", hostname(), pid, start)))
	return "sshsess-" + hex.EncodeToString(sum[:12])
}

// procAlive reports whether pid is a live process whose start time matches
// wantTicks (defeating PID reuse). A missing /proc/<pid>/stat means the process
// exited. wantTicks==0 means "can't verify identity" — existence alone counts.
func procAlive(pid uint32, wantTicks uint64) bool {
	if pid == 0 {
		return false
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	if wantTicks == 0 {
		return true
	}
	return parseStartTicks(string(data)) == wantTicks
}

// procStartTicksFn reads a process's start ticks, indirected so tests can
// supply deterministic values without depending on whatever real pid happens to
// occupy the test's chosen pid number.
var procStartTicksFn = procStartTicks

// procStartTicks reads the kernel's process start time (field 22 of
// /proc/<pid>/stat, in clock ticks since boot) — fixed for the life of the
// process and therefore stable across agent/BPF restarts. Returns 0 if the
// process is gone or the file can't be parsed.
func procStartTicks(pid uint32) uint64 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	return parseStartTicks(string(data))
}

// parseStartTicks extracts the starttime (field 22) from a /proc/<pid>/stat
// line. The comm field (field 2) is parenthesised and may contain spaces and
// parentheses, so we split on the final ')' before tokenising the rest.
func parseStartTicks(s string) uint64 {
	rest, ok := statAfterComm(s)
	if !ok {
		return 0
	}
	fields := strings.Fields(rest)
	// After the comm field, fields[0] is "state" (stat field 3), so stat field
	// 22 (starttime) is index 19 in this slice.
	const starttimeIdx = 19
	if len(fields) <= starttimeIdx {
		return 0
	}
	v, err := strconv.ParseUint(fields[starttimeIdx], 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// statPPID extracts the parent pid (field 4) from a /proc/<pid>/stat line.
func statPPID(s string) uint32 {
	rest, ok := statAfterComm(s)
	if !ok {
		return 0
	}
	fields := strings.Fields(rest)
	// fields[0]=state(3), fields[1]=ppid(4).
	if len(fields) < 2 {
		return 0
	}
	v, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return 0
	}
	return uint32(v)
}

// statComm extracts the comm (field 2) from a /proc/<pid>/stat line, stripping
// the surrounding parentheses.
func statComm(s string) string {
	l := strings.IndexByte(s, '(')
	r := strings.LastIndexByte(s, ')')
	if l < 0 || r <= l {
		return ""
	}
	return s[l+1 : r]
}

// statAfterComm returns the portion of a stat line after the comm field's
// closing ')'. The comm may itself contain spaces and parens, so we split on
// the final ')'.
func statAfterComm(s string) (string, bool) {
	rparen := strings.LastIndex(s, ")")
	if rparen < 0 || rparen+1 >= len(s) {
		return "", false
	}
	return s[rparen+1:], true
}

// userHZ is the kernel's USER_HZ; 100 on virtually every Linux build (the value
// CLK_TCK reports). Used to convert /proc start ticks to wall-clock time.
const userHZ = 100

// ticksToWall converts a process start time (in USER_HZ ticks since boot) to
// wall-clock time using the host boot time. Returns the zero time if either
// input is unavailable.
func ticksToWall(startTicks uint64) time.Time {
	if startTicks == 0 {
		return time.Time{}
	}
	bt := bootTime()
	if bt.IsZero() {
		return time.Time{}
	}
	return bt.Add(time.Duration(startTicks) * time.Second / userHZ)
}

var (
	bootTimeOnce sync.Once
	cachedBoot   time.Time
)

// bootTime reads the host boot instant from /proc/stat's "btime" line.
func bootTime() time.Time {
	bootTimeOnce.Do(func() {
		data, err := os.ReadFile("/proc/stat")
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(line, "btime ") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) != 2 {
				continue
			}
			if sec, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				cachedBoot = time.Unix(sec, 0)
			}
			return
		}
	})
	return cachedBoot
}

// procWorker is one live sshd connection worker discovered by scanProcForSSHWorkers.
type procWorker struct {
	pid      uint32
	ppid     uint32
	comm     string
	cmdline  string
	username string
}

// scanProcForSSHWorkers walks /proc and returns every live per-connection sshd
// worker. Used by Readopt at startup.
func scanProcForSSHWorkers() []procWorker {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []procWorker
	for _, e := range entries {
		pid64, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)
		statData, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			continue
		}
		stat := string(statData)
		comm := statComm(stat)
		// The setproctitle "sshd: user@pts/N" lands in /proc/<pid>/cmdline; comm
		// stays "sshd". sshd-session is identified by comm alone.
		cmdline := procCmdline(pid)
		p := ProcessInfo{PID: int(pid), Name: comm, Cmdline: cmdline}
		if !isSSHWorkerProcess(p) {
			continue
		}
		out = append(out, procWorker{
			pid:      pid,
			ppid:     statPPID(stat),
			comm:     comm,
			cmdline:  cmdline,
			username: procUsername(pid),
		})
	}
	return out
}

// procCmdline reads /proc/<pid>/cmdline (NUL-separated argv) as a space-joined
// string. sshd workers rewrite this to "sshd: user@pts/N" via setproctitle.
func procCmdline(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(data) == 0 {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", " "))
}

// procUsername resolves the real UID of pid (from /proc/<pid>/status) to a
// username, best-effort.
func procUsername(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return ""
		}
		if u, err := user.LookupId(fields[1]); err == nil {
			return u.Username
		}
		return ""
	}
	return ""
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

//go:build linux

package ebpf

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SSHHydrator stamps SSH source-IP context onto shell processes spawned by
// sshd. Without it a "Process Clone" / "Process Execution" row on the
// dashboard shows only the local pid/comm — the actual remote IP that just
// logged in is invisible. We pull it from auth.log (matching the sshd
// session worker PID, which is the event's PPID) and fall back to `who`
// when auth.log is unreadable (small distros, journal-only setups).
//
// Lookups are cached per sshd worker PID; an active SSH session can spawn
// hundreds of processes, and re-scanning auth.log per event would dwarf
// the agent's own CPU footprint.
type SSHHydrator struct {
	mu          sync.RWMutex
	cache       map[int]sshSession // ppid → resolved session
	cacheTTL    time.Duration
	negativeTTL time.Duration // shorter TTL on misses so we retry while the session is still warm

	// Overridable for tests. Production paths use the real defaults.
	authLogPaths []string
	whoRunner    func(ctx context.Context) ([]whoEntry, error)
}

type sshSession struct {
	sourceIP string
	username string
	resolved time.Time
	hit      bool // false → recorded miss; ignore until negativeTTL elapses
}

type whoEntry struct {
	username string
	tty      string
	sourceIP string
}

// NewSSHHydrator returns a hydrator configured for the standard Linux
// distros — auth.log (Debian/Ubuntu) and secure (RHEL/CentOS/Fedora).
func NewSSHHydrator() *SSHHydrator {
	return &SSHHydrator{
		cache:        make(map[int]sshSession),
		cacheTTL:     1 * time.Hour,
		negativeTTL:  15 * time.Second,
		authLogPaths: []string{"/var/log/auth.log", "/var/log/secure"},
		whoRunner:    runWho,
	}
}

// sshAcceptLine matches a successful sshd login line. Example:
//
//	sshd[12345]: Accepted publickey for ssidhu from 10.0.0.1 port 50000 ssh2: ED25519 SHA256:...
//
// The PID capture is the sshd worker PID — that's the PPID a user's
// login shell will carry, which is what we key the cache on.
var sshAcceptLine = regexp.MustCompile(`sshd\[(\d+)\]:\s+Accepted\s+\S+\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+\d+`)

// HydrateSSHLogin marks the event as an SSH login (ssh_login=true) and, when
// resolvable, annotates it with the remote source IP. Quietly no-ops on events
// that aren't sshd-spawned login shells, so it's safe to call on every event.
//
// Heuristic for "this is an SSH login shell":
//   - Rule is "Process Clone" or "Process Execution" (the agent's two
//     entry points for "new process appeared").
//   - parent is sshd (parent_exe /usr/sbin/sshd or parent_name "sshd",
//     including the OpenSSH 9.8+ per-session "sshd-session" binary).
//   - cmdline mentions a login-shell binary — bash/sh/zsh/dash/fish/ash.
//     For Process Clone the cmdline is sometimes still the parent's
//     (pre-execve), so this check is best-effort: if cmdline is empty we
//     still treat it as a login shell.
//
// The source IP is enrichment, not a gate: a host with no readable auth.log
// (journald-only) or a privsep PID mismatch still gets its session tracked.
func (h *SSHHydrator) HydrateSSHLogin(event *SecurityEvent) {
	if event == nil {
		return
	}
	switch event.Rule {
	case "Process Clone", "Process Execution":
	default:
		return
	}
	p := event.Process
	if !isParentSSHD(p) {
		return
	}
	if p.Cmdline != "" && !isLoginShellCmdline(p.Cmdline) {
		return
	}
	if p.PPID <= 0 {
		return
	}

	// This event is an sshd-spawned login shell — that fact alone makes it an
	// SSH login, so stamp ssh_login now, BEFORE attempting source-IP lookup.
	// Source-IP resolution is best-effort (auth.log PID match / `who`) and
	// frequently unavailable — journald-only hosts with no /var/log/auth.log,
	// or privilege-separated sshd where the login shell's PPID isn't the sshd
	// pid that logged "Accepted ... from <ip>". Gating ssh_login on a resolved
	// IP meant those sessions were never tracked at all, even though who/when/
	// duration are perfectly knowable. The IP is enrichment, not a precondition.
	if event.RawFields == nil {
		event.RawFields = make(map[string]interface{})
	}
	event.RawFields["ssh_login"] = true
	event.Tags = appendUniqueTag(event.Tags, "ssh_login")

	// Best-effort source-IP + username enrichment. A miss leaves the session
	// with an "unknown source" — the tracker still records it.
	session, ok := h.lookup(p.PPID)
	if !ok {
		session = h.resolve(p.PPID, p.Username, p.TTY)
		h.store(p.PPID, session)
	}
	if session.hit && session.sourceIP != "" {
		if event.Network.SrcIP == "" {
			event.Network.SrcIP = session.sourceIP
		}
		event.RawFields["ssh_source_ip"] = session.sourceIP
		if session.username != "" {
			event.RawFields["ssh_username"] = session.username
		}
	}
}

func isParentSSHD(p ProcessInfo) bool {
	// OpenSSH 9.8 split the per-connection worker into a separate "sshd-session"
	// binary (Ubuntu 24.10+, Fedora 41+), so the login shell's parent there is
	// sshd-session rather than sshd. Match both.
	switch p.ParentExe {
	case "/usr/sbin/sshd", "/usr/bin/sshd", "/usr/sbin/sshd-session", "/usr/bin/sshd-session":
		return true
	}
	switch p.ParentName {
	case "sshd", "sshd-session":
		return true
	}
	return false
}

// isLoginShellCmdline returns true when cmdline names a common interactive
// shell. We match the basename so "-bash" (login shell convention) and
// "/bin/bash -c" both qualify.
func isLoginShellCmdline(cmdline string) bool {
	fields := strings.Fields(cmdline)
	if len(fields) == 0 {
		return false
	}
	head := strings.TrimPrefix(fields[0], "-") // login shells prefix with '-'
	if idx := strings.LastIndex(head, "/"); idx >= 0 {
		head = head[idx+1:]
	}
	switch head {
	case "bash", "sh", "zsh", "dash", "fish", "ash", "ksh":
		return true
	}
	return false
}

// ResolveForPID resolves a connection worker's PID to its remote source IP and
// username, going through the same cache + auth.log/who path as login hydration.
// Used by the SSH session tracker to enrich worker-anchored sessions whose
// triggering event carried no source IP (worker-own events aren't hydrated).
// Returns empty strings on a miss.
func (h *SSHHydrator) ResolveForPID(workerPID int, username string, tty int) (string, string) {
	if workerPID <= 0 {
		return "", ""
	}
	s, ok := h.lookup(workerPID)
	if !ok {
		s = h.resolve(workerPID, username, tty)
		h.store(workerPID, s)
	}
	if s.hit {
		return s.sourceIP, s.username
	}
	return "", ""
}

func (h *SSHHydrator) lookup(ppid int) (sshSession, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	s, ok := h.cache[ppid]
	if !ok {
		return sshSession{}, false
	}
	ttl := h.cacheTTL
	if !s.hit {
		ttl = h.negativeTTL
	}
	if time.Since(s.resolved) > ttl {
		return sshSession{}, false
	}
	return s, true
}

func (h *SSHHydrator) store(ppid int, s sshSession) {
	s.resolved = time.Now()
	h.mu.Lock()
	h.cache[ppid] = s
	h.mu.Unlock()
}

// resolve looks up the source IP using auth.log first (canonical), then
// falls back to `who` output (which lists active sessions with the source
// host in parentheses). Returns a session with hit=false when neither hit.
func (h *SSHHydrator) resolve(ppid int, username string, tty int) sshSession {
	if ip, user := h.scanAuthLog(ppid); ip != "" {
		return sshSession{sourceIP: ip, username: user, hit: true}
	}
	if ip := h.scanWho(username, tty); ip != "" {
		return sshSession{sourceIP: ip, username: username, hit: true}
	}
	return sshSession{hit: false}
}

// scanAuthLog walks auth.log/secure bottom-up looking for the most recent
// "Accepted" line whose sshd[pid] matches ppid. We tail the last ~2 MiB
// instead of opening the whole file — sshd Accepted lines for an active
// session are virtually always within the last few thousand log lines.
func (h *SSHHydrator) scanAuthLog(ppid int) (string, string) {
	target := strconv.Itoa(ppid)
	for _, path := range h.authLogPaths {
		ip, user := scanAuthLogFile(path, target)
		if ip != "" {
			return ip, user
		}
	}
	return "", ""
}

const authLogTailBytes = 2 * 1024 * 1024

func scanAuthLogFile(path, ppidStr string) (string, string) {
	f, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return "", ""
	}
	offset := int64(0)
	if stat.Size() > authLogTailBytes {
		offset = stat.Size() - authLogTailBytes
		if _, err := f.Seek(offset, 0); err != nil {
			return "", ""
		}
	}

	scanner := bufio.NewScanner(f)
	// Auth log lines can be long when keys/cipher names are echoed; raise
	// the per-line limit so a single huge line doesn't truncate scanning.
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	var lastIP, lastUser string
	for scanner.Scan() {
		line := scanner.Text()
		// Cheap pre-filter — most lines have nothing to do with sshd.
		if !strings.Contains(line, "sshd[") || !strings.Contains(line, "Accepted") {
			continue
		}
		m := sshAcceptLine.FindStringSubmatch(line)
		if len(m) != 4 {
			continue
		}
		if m[1] != ppidStr {
			continue
		}
		// Keep walking — multiple matching lines mean the same worker pid
		// got reused; the last one wins.
		lastUser = m[2]
		lastIP = m[3]
	}
	// scanner.Err() returns the underlying read error so a truncated tail
	// scan is visible. Ignored on purpose: this is best-effort hydration —
	// a partial scan that found a match is still useful, and one that
	// found nothing degrades to the who-fallback anyway.
	_ = scanner.Err()
	return lastIP, lastUser
}

// scanWho parses `who -u` output to find an active session matching the
// username (and TTY when available). The host column is the source —
// either an IP, a hostname, or empty when the session isn't network-backed.
func (h *SSHHydrator) scanWho(username string, tty int) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	entries, err := h.whoRunner(ctx)
	if err != nil {
		return ""
	}
	ttyStr := ""
	if tty > 0 {
		// Linux TTY field on /proc is a minor:major mash, not directly
		// matchable to "pts/N". We use it as a hint when present but match
		// loosely so an absent or unknown tty still allows a username hit.
		ttyStr = "pts/" + strconv.Itoa(tty)
	}
	for _, e := range entries {
		if username != "" && e.username != username {
			continue
		}
		if ttyStr != "" && e.tty != ttyStr {
			continue
		}
		if isLikelyIP(e.sourceIP) {
			return e.sourceIP
		}
	}
	// If no exact match, return the first IP-shaped entry for the user.
	for _, e := range entries {
		if username == "" || e.username == username {
			if isLikelyIP(e.sourceIP) {
				return e.sourceIP
			}
		}
	}
	return ""
}

func runWho(ctx context.Context) ([]whoEntry, error) {
	out, err := exec.CommandContext(ctx, "who", "-u").Output()
	if err != nil {
		return nil, err
	}
	return parseWhoOutput(string(out)), nil
}

// parseWhoOutput parses the columns of `who -u`. Each line is roughly:
//
//	user  pts/0  2026-05-29 09:57  .  12345  (10.0.0.1)
//
// The host column is the last parenthesised value; absent rows (no
// network) we skip.
func parseWhoOutput(s string) []whoEntry {
	var out []whoEntry
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		entry := whoEntry{username: fields[0], tty: fields[1]}
		if open := strings.LastIndex(line, "("); open >= 0 {
			if close := strings.LastIndex(line, ")"); close > open {
				entry.sourceIP = line[open+1 : close]
			}
		}
		out = append(out, entry)
	}
	return out
}

// isLikelyIP filters out the placeholders `who` prints for local consoles
// (":0", "tmux(...)", "") so we don't surface them as remote IPs.
func isLikelyIP(s string) bool {
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, ":") || strings.Contains(s, "tmux") || strings.Contains(s, "screen") {
		return false
	}
	// IPv4 dotted quad or IPv6 colon-hex — be permissive, downstream can
	// validate further.
	return strings.ContainsAny(s, ".:")
}

func appendUniqueTag(tags []string, tag string) []string {
	for _, t := range tags {
		if t == tag {
			return tags
		}
	}
	return append(tags, tag)
}

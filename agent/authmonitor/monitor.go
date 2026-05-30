// Package authmonitor watches the system auth log for failed-login bursts and
// raises a brute-force finding when one source crosses a threshold inside a
// sliding window. It is independent of ebpf (auth events aren't syscalls) so it
// unit-tests in isolation; the agent wiring turns Findings into security events.
package authmonitor

import (
	"bufio"
	"os"
	"regexp"
	"sync"
	"syscall"
	"time"
)

// Kind classifies a brute-force finding.
type Kind string

const (
	KindSSHBruteForce  Kind = "ssh_brute_force"
	KindSudoBruteForce Kind = "sudo_brute_force"
)

// Finding is emitted when a source crosses the failure threshold.
type Finding struct {
	Kind   Kind
	Source string // source IP for SSH, invoking user for sudo
	User   string // targeted/again invoking user
	Count  int
	Window int // window in seconds the count was observed over
}

// Config tunes the detector. Zero values fall back to sane defaults.
type Config struct {
	Paths           []string // auth log candidates; first existing one is used
	Threshold       int      // failures within the window to trigger (default 5)
	WindowSeconds   int      // sliding window (default 120)
	CooldownSeconds int      // per-source re-alert suppression (default 300)
	PollSeconds     int      // file poll interval (default 3)
}

func (c *Config) applyDefaults() {
	if len(c.Paths) == 0 {
		c.Paths = []string{"/var/log/auth.log", "/var/log/secure"}
	}
	if c.Threshold <= 0 {
		c.Threshold = 5
	}
	if c.WindowSeconds <= 0 {
		c.WindowSeconds = 120
	}
	if c.CooldownSeconds <= 0 {
		c.CooldownSeconds = 300
	}
	if c.PollSeconds <= 0 {
		c.PollSeconds = 3
	}
}

// sshFail matches an sshd failed-password line, with or without "invalid user".
var sshFail = regexp.MustCompile(`sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\S+) from (\S+) port \d+`)

// sudoFail matches a sudo authentication failure line; group 1 is the invoking
// user.
var sudoFail = regexp.MustCompile(`sudo:\s+(\S+)\s+:\s+.*authentication failure`)

// Monitor tails the auth log and emits brute-force findings.
type Monitor struct {
	cfg       Config
	onFinding func(Finding)

	mu        sync.Mutex
	failures  map[string][]int64 // key → unix timestamps of recent failures
	lastAlert map[string]int64   // key → unix time of last emitted finding
	users     map[string]string  // key → most recent associated username

	path   string
	offset int64
	inode  uint64
	stop   chan struct{}
}

// New builds a Monitor. onFinding is invoked (from the poll goroutine) for each
// brute-force finding.
func New(cfg Config, onFinding func(Finding)) *Monitor {
	cfg.applyDefaults()
	return &Monitor{
		cfg:       cfg,
		onFinding: onFinding,
		failures:  make(map[string][]int64),
		lastAlert: make(map[string]int64),
		users:     make(map[string]string),
		stop:      make(chan struct{}),
	}
}

// Start resolves the auth-log path and launches the poll loop. No-op when no
// candidate path exists (journal-only hosts).
func (m *Monitor) Start() {
	for _, p := range m.cfg.Paths {
		if _, err := os.Stat(p); err == nil {
			m.path = p
			break
		}
	}
	if m.path == "" {
		return
	}
	// Start reading from the current end so we don't replay history on boot.
	if fi, err := os.Stat(m.path); err == nil {
		m.offset = fi.Size()
		m.inode = inodeOf(fi)
	}
	go m.loop()
}

// Stop ends the poll loop.
func (m *Monitor) Stop() { close(m.stop) }

func (m *Monitor) loop() {
	ticker := time.NewTicker(time.Duration(m.cfg.PollSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			m.readNew()
		}
	}
}

// readNew reads any lines appended since the last poll, handling rotation
// (inode change) and truncation by resetting the offset.
func (m *Monitor) readNew() {
	fi, err := os.Stat(m.path)
	if err != nil {
		return // rotated away mid-cycle; pick it up next tick
	}
	ino := inodeOf(fi)
	if ino != m.inode {
		m.inode = ino
		m.offset = 0 // new file after rotation — read from the top
	} else if fi.Size() < m.offset {
		m.offset = 0 // truncated in place
	}
	if fi.Size() == m.offset {
		return
	}
	f, err := os.Open(m.path)
	if err != nil {
		return
	}
	defer f.Close()
	if _, err := f.Seek(m.offset, 0); err != nil {
		return
	}
	now := time.Now().Unix()
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	read := int64(0)
	for scanner.Scan() {
		line := scanner.Text()
		read += int64(len(line)) + 1
		m.processLine(line, now)
	}
	m.offset += read
}

// processLine updates the per-source failure window and emits a finding when
// the threshold is crossed (subject to the cooldown). Exported indirectly via
// tests.
func (m *Monitor) processLine(line string, now int64) {
	var key string
	var kind Kind
	var source, user string

	if mt := sshFail.FindStringSubmatch(line); mt != nil {
		user, source = mt[1], mt[2]
		key = "ssh:" + source
		kind = KindSSHBruteForce
	} else if mt := sudoFail.FindStringSubmatch(line); mt != nil {
		user = mt[1]
		source = mt[1]
		key = "sudo:" + user
		kind = KindSudoBruteForce
	} else {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := now - int64(m.cfg.WindowSeconds)
	times := append(m.failures[key], now)
	pruned := times[:0]
	for _, t := range times {
		if t >= cutoff {
			pruned = append(pruned, t)
		}
	}
	m.failures[key] = pruned
	m.users[key] = user

	if len(pruned) < m.cfg.Threshold {
		return
	}
	if last, ok := m.lastAlert[key]; ok && now-last < int64(m.cfg.CooldownSeconds) {
		return
	}
	m.lastAlert[key] = now
	count := len(pruned)
	if m.onFinding != nil {
		m.onFinding(Finding{Kind: kind, Source: source, User: user, Count: count, Window: m.cfg.WindowSeconds})
	}
}

func inodeOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

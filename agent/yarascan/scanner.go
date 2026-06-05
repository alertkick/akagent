// Package yarascan scans files against YARA rules to catch known malware. It
// shells out to the `yara` CLI rather than linking libyara via cgo, so it adds
// no build-toolchain requirements to the agent. The active ruleset can be
// swapped at runtime (SetRules) so the rules-sync component can push updates
// without restarting the agent. Scans run on a bounded worker so a burst of
// exec events can't spawn unbounded yara processes.
package yarascan

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// DefaultRulesPath is where the rules-sync component writes the bundle and the
// scanner reads it when YARA_RULES_PATH isn't set explicitly.
const DefaultRulesPath = "/var/lib/alertkick-agent/yara/rules.yar"

// BundledBinaryPath is where the agent package installs the static yara binary
// it ships per arch. Preferred over a system yara so the rule-compilation
// version matches across hosts.
const BundledBinaryPath = "/usr/lib/alertkick-agent/bin/yara"

// resolveBinary picks the yara binary: an explicit override, else the bundled
// static binary if present, else "yara" from PATH.
func resolveBinary(override string) string {
	if override != "" {
		return override
	}
	if _, err := os.Stat(BundledBinaryPath); err == nil {
		return BundledBinaryPath
	}
	return "yara"
}

// Config controls the scanner.
type Config struct {
	RulesPath string // initial rules file/dir; may be empty and set later
	Binary    string // yara binary name/path (default "yara")
	QueueSize int    // pending-scan buffer (default 256)
}

// Match is a YARA hit on a file.
type Match struct {
	Path  string
	Rules []string
}

// Scanner runs YARA scans asynchronously against a swappable ruleset.
type Scanner struct {
	binary  string
	onMatch func(Match)
	run     func(rulesPath, target string) (string, error) // injectable for tests

	queue     chan string
	stop      chan struct{}
	startOnce sync.Once

	mu        sync.Mutex
	rulesPath string
	available bool
	seen      map[string]int64 // path → mtime already scanned (de-dupe)
}

// New builds a Scanner. The yara binary must be on PATH and a ruleset present
// for scanning to be "available"; both can become true later via SetRules.
func New(cfg Config, onMatch func(Match)) *Scanner {
	binary := resolveBinary(cfg.Binary)
	qs := cfg.QueueSize
	if qs <= 0 {
		qs = 256
	}
	s := &Scanner{
		binary:  binary,
		onMatch: onMatch,
		queue:   make(chan string, qs),
		stop:    make(chan struct{}),
		seen:    make(map[string]int64),
	}
	s.run = s.execYara
	s.SetRules(cfg.RulesPath)
	return s
}

// SetRules points the scanner at a new ruleset path and recomputes
// availability. Called by rules-sync after an atomic swap; safe concurrently.
func (s *Scanner) SetRules(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rulesPath = path
	s.available = s.checkAvailable(path)
}

func (s *Scanner) checkAvailable(path string) bool {
	if path == "" {
		return false
	}
	if _, err := os.Stat(path); err != nil {
		return false
	}
	if _, err := exec.LookPath(s.binary); err != nil {
		return false
	}
	return true
}

// Available reports whether scanning is currently usable.
func (s *Scanner) Available() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.available
}

// RulesPath returns the active ruleset path (may be empty if never set).
func (s *Scanner) RulesPath() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rulesPath
}

// Binary returns the resolved yara binary path/name. Set once at
// construction, so no lock is needed.
func (s *Scanner) Binary() string { return s.binary }

// Start launches the scan worker (idempotent). The worker runs regardless of
// availability; ScanAsync gates enqueues, so rules arriving later just work.
func (s *Scanner) Start() {
	s.startOnce.Do(func() {
		go func() {
			for {
				select {
				case <-s.stop:
					return
				case path := <-s.queue:
					s.scanOne(path)
				}
			}
		}()
	})
}

// Stop ends the worker.
func (s *Scanner) Stop() { close(s.stop) }

// ScanAsync enqueues a path for scanning (non-blocking; drops if full). No-op
// when unavailable or path is empty.
func (s *Scanner) ScanAsync(path string) {
	if path == "" || !s.Available() {
		return
	}
	select {
	case s.queue <- path:
	default:
	}
}

func (s *Scanner) scanOne(path string) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	mtime := info.ModTime().UnixNano()

	s.mu.Lock()
	rulesPath, available := s.rulesPath, s.available
	if !available || rulesPath == "" {
		s.mu.Unlock()
		return
	}
	if s.seen[path] == mtime {
		s.mu.Unlock()
		return // same content already scanned
	}
	s.seen[path] = mtime
	s.mu.Unlock()

	out, err := s.run(rulesPath, path)
	if err != nil {
		return
	}
	if rules := parseYaraOutput(out); len(rules) > 0 && s.onMatch != nil {
		s.onMatch(Match{Path: path, Rules: rules})
	}
}

func (s *Scanner) execYara(rulesPath, target string) (string, error) {
	out, err := exec.Command(s.binary, "-r", "-w", rulesPath, target).Output()
	return string(out), err
}

// parseYaraOutput turns yara CLI stdout into the set of matched rule names. Each
// match line is "RuleName /path/to/file" (rule name is the first field).
func parseYaraOutput(out string) []string {
	seen := map[string]bool{}
	var rules []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name := strings.Fields(line)[0]
		if _, err := strconv.ParseInt(strings.TrimPrefix(name, "0x"), 0, 64); err == nil {
			continue // skip offset/meta lines
		}
		if !seen[name] {
			seen[name] = true
			rules = append(rules, name)
		}
	}
	return rules
}

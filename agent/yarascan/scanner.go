// Package yarascan scans files against YARA rules to catch known malware. It
// shells out to the `yara` CLI rather than linking libyara via cgo, so it adds
// no build-toolchain requirements to the agent — YARA and the rules are an
// optional host-side dependency the operator supplies. Scans run on a bounded
// worker so a burst of exec events can't spawn unbounded yara processes.
package yarascan

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// Config controls the scanner.
type Config struct {
	RulesPath string // file or directory of .yar rules; empty disables scanning
	Binary    string // yara binary name/path (default "yara")
	QueueSize int    // pending-scan buffer (default 256)
}

// Match is a YARA hit on a file.
type Match struct {
	Path  string
	Rules []string
}

// Scanner runs YARA scans asynchronously.
type Scanner struct {
	cfg       Config
	onMatch   func(Match)
	run       func(rulesPath, target string) (string, error) // injectable for tests
	available bool

	queue chan string
	stop  chan struct{}

	mu   sync.Mutex
	seen map[string]int64 // path → mtime already scanned (de-dupe)
}

// New builds a Scanner. It is "available" only when a rules path is configured,
// the rules exist, and the yara binary is on PATH — otherwise every method is a
// cheap no-op.
func New(cfg Config, onMatch func(Match)) *Scanner {
	if cfg.Binary == "" {
		cfg.Binary = "yara"
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 256
	}
	s := &Scanner{
		cfg:     cfg,
		onMatch: onMatch,
		seen:    make(map[string]int64),
		queue:   make(chan string, cfg.QueueSize),
		stop:    make(chan struct{}),
	}
	s.run = s.execYara
	if cfg.RulesPath != "" {
		if _, err := os.Stat(cfg.RulesPath); err == nil {
			if _, err := exec.LookPath(cfg.Binary); err == nil {
				s.available = true
			}
		}
	}
	return s
}

// Available reports whether scanning is configured and usable.
func (s *Scanner) Available() bool { return s.available }

// Start launches the scan worker. No-op when unavailable.
func (s *Scanner) Start() {
	if !s.available {
		return
	}
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
}

// Stop ends the worker.
func (s *Scanner) Stop() { close(s.stop) }

// ScanAsync enqueues a path for scanning (non-blocking; drops if the queue is
// full). No-op when unavailable or path is empty.
func (s *Scanner) ScanAsync(path string) {
	if !s.available || path == "" {
		return
	}
	select {
	case s.queue <- path:
	default: // queue full — best-effort, drop
	}
}

func (s *Scanner) scanOne(path string) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	mtime := info.ModTime().UnixNano()
	s.mu.Lock()
	if s.seen[path] == mtime {
		s.mu.Unlock()
		return // same content already scanned
	}
	s.seen[path] = mtime
	s.mu.Unlock()

	out, err := s.run(s.cfg.RulesPath, path)
	if err != nil {
		return
	}
	if rules := parseYaraOutput(out); len(rules) > 0 && s.onMatch != nil {
		s.onMatch(Match{Path: path, Rules: rules})
	}
}

func (s *Scanner) execYara(rulesPath, target string) (string, error) {
	// -r recurse rule dirs, -f fast match, -w no warnings; positional: rules target
	out, err := exec.Command(s.cfg.Binary, "-r", "-w", rulesPath, target).Output()
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
		fields := strings.Fields(line)
		name := fields[0]
		// Skip namespace/meta lines that some yara versions emit (start with "0x"
		// offsets or contain ':' from string-id dumps without -s, defensively).
		if _, err := strconv.ParseInt(strings.TrimPrefix(name, "0x"), 0, 64); err == nil {
			continue
		}
		if !seen[name] {
			seen[name] = true
			rules = append(rules, name)
		}
	}
	return rules
}

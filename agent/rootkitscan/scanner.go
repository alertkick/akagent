// Package rootkitscan periodically checks a Linux host for common rootkit
// indicators that eBPF syscall tracing alone won't surface: kernel modules
// hidden from lsmod, processes hidden from /proc readdir, and an active
// /etc/ld.so.preload (the classic userland-rootkit hook). It is independent of
// ebpf so it unit-tests in isolation; the agent wiring turns Findings into
// security events.
package rootkitscan

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Kind classifies a rootkit indicator.
type Kind string

const (
	KindHiddenModule  Kind = "hidden_kernel_module"
	KindHiddenProcess Kind = "hidden_process"
	KindPreload       Kind = "ld_preload"
)

// Finding is a single rootkit indicator.
type Finding struct {
	Kind   Kind
	Detail string // module name, "pid comm", or the preload file contents
	PID    int    // populated for hidden processes
}

// Config tunes the scanner. Zero values fall back to defaults.
type Config struct {
	IntervalSeconds int
	MaxPIDScan      int // upper bound for the hidden-process probe
	ProcRoot        string
	SysModuleRoot   string
	PreloadPath     string
}

func (c *Config) applyDefaults() {
	if c.IntervalSeconds <= 0 {
		c.IntervalSeconds = 300
	}
	if c.MaxPIDScan <= 0 {
		c.MaxPIDScan = 65536
	}
	if c.ProcRoot == "" {
		c.ProcRoot = "/proc"
	}
	if c.SysModuleRoot == "" {
		c.SysModuleRoot = "/sys/module"
	}
	if c.PreloadPath == "" {
		c.PreloadPath = "/etc/ld.so.preload"
	}
}

// Scanner runs the periodic checks.
type Scanner struct {
	cfg       Config
	onFinding func(Finding)

	mu   sync.Mutex
	seen map[string]bool // de-dupe key → already reported
	stop chan struct{}
}

// New builds a Scanner. onFinding is invoked (from the scan goroutine) per new
// indicator.
func New(cfg Config, onFinding func(Finding)) *Scanner {
	cfg.applyDefaults()
	return &Scanner{cfg: cfg, onFinding: onFinding, seen: make(map[string]bool), stop: make(chan struct{})}
}

// Start runs the first scan shortly after launch, then on the configured
// interval.
func (s *Scanner) Start() {
	go func() {
		t := time.NewTimer(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-t.C:
				s.scan()
				t.Reset(time.Duration(s.cfg.IntervalSeconds) * time.Second)
			}
		}
	}()
}

// Stop ends the scan loop.
func (s *Scanner) Stop() { close(s.stop) }

func (s *Scanner) scan() {
	for _, m := range s.scanHiddenModules() {
		s.emit(Finding{Kind: KindHiddenModule, Detail: m})
	}
	if libs, ok := s.scanPreload(); ok {
		s.emit(Finding{Kind: KindPreload, Detail: libs})
	}
	for _, p := range s.scanHiddenProcesses() {
		s.emit(Finding{Kind: KindHiddenProcess, Detail: p.detail, PID: p.pid})
	}
}

func (s *Scanner) emit(f Finding) {
	key := string(f.Kind) + "|" + f.Detail
	s.mu.Lock()
	if s.seen[key] {
		s.mu.Unlock()
		return
	}
	s.seen[key] = true
	s.mu.Unlock()
	if s.onFinding != nil {
		s.onFinding(f)
	}
}

// ── Hidden kernel modules ───────────────────────────────────────────────

// findHiddenModules returns loaded modules present in sysfs (with a refcnt, so
// loadable not built-in) that are absent from /proc/modules — the signature of
// an LKM rootkit hiding itself from lsmod.
func findHiddenModules(procModules map[string]bool, sysLoaded []string) []string {
	var hidden []string
	for _, m := range sysLoaded {
		if !procModules[m] {
			hidden = append(hidden, m)
		}
	}
	return hidden
}

func (s *Scanner) scanHiddenModules() []string {
	return findHiddenModules(readProcModules(filepath.Join(s.cfg.ProcRoot, "modules")), readSysLoadedModules(s.cfg.SysModuleRoot))
}

func readProcModules(path string) map[string]bool {
	out := make(map[string]bool)
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) > 0 {
			out[fields[0]] = true
		}
	}
	return out
}

// readSysLoadedModules lists /sys/module entries that have a refcnt file —
// i.e. loadable modules currently loaded (built-ins have no refcnt).
func readSysLoadedModules(root string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, e.Name(), "refcnt")); err == nil {
			out = append(out, e.Name())
		}
	}
	return out
}

// ── ld.so.preload ───────────────────────────────────────────────────────

func (s *Scanner) scanPreload() (string, bool) {
	data, err := os.ReadFile(s.cfg.PreloadPath)
	if err != nil {
		return "", false
	}
	libs := strings.Join(strings.Fields(string(data)), " ")
	if libs == "" {
		return "", false
	}
	return libs, true
}

// ── Hidden processes ────────────────────────────────────────────────────

type hiddenProc struct {
	pid    int
	detail string
}

// findHiddenPIDs returns PIDs that are directly accessible (a rootkit can't
// easily hide /proc/<pid> from a direct stat) but absent from the /proc readdir
// listing — the libprocesshider signature.
func findHiddenPIDs(visible map[int]bool, accessible []int) []int {
	var hidden []int
	for _, pid := range accessible {
		if !visible[pid] {
			hidden = append(hidden, pid)
		}
	}
	return hidden
}

func (s *Scanner) scanHiddenProcesses() []hiddenProc {
	visible := readVisiblePIDs(s.cfg.ProcRoot)
	maxPID := s.cfg.MaxPIDScan
	if pm := readPidMax(filepath.Join(s.cfg.ProcRoot, "sys/kernel/pid_max")); pm > 0 && pm < maxPID {
		maxPID = pm
	}
	var accessible []int
	for pid := 2; pid <= maxPID; pid++ {
		if _, err := os.Stat(filepath.Join(s.cfg.ProcRoot, strconv.Itoa(pid))); err == nil {
			accessible = append(accessible, pid)
		}
	}
	var out []hiddenProc
	for _, pid := range findHiddenPIDs(visible, accessible) {
		out = append(out, hiddenProc{pid: pid, detail: strconv.Itoa(pid) + " " + readComm(s.cfg.ProcRoot, pid)})
	}
	return out
}

func readVisiblePIDs(procRoot string) map[int]bool {
	out := make(map[int]bool)
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			out[pid] = true
		}
	}
	return out
}

func readPidMax(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return v
}

func readComm(procRoot string, pid int) string {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "comm"))
	if err != nil {
		return "(unknown)"
	}
	return strings.TrimSpace(string(data))
}

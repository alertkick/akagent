package fim

import (
	"os"
	"strings"
	"sync"
	"time"
)

// Config is the runtime configuration the Manager needs. The agent wiring
// builds this from ebpf.FileIntegrityConfig so this package stays
// ebpf-independent and unit-testable.
type Config struct {
	Paths          []string
	Exclude        []string
	HashAlgo       string
	SuppressPkgMgr bool
	DebounceMs     int
	StatePath      string
}

// ChangeKind classifies what happened to a monitored file.
type ChangeKind string

const (
	KindModified ChangeKind = "modified"
	KindAdded    ChangeKind = "added"
	KindRemoved  ChangeKind = "removed"
)

// Trigger carries the attribution of the file event that prompted a re-check:
// the modifying process, and (best-effort) its ancestor comms, used for
// package-manager suppression.
type Trigger struct {
	Comm     string
	Exe      string
	PID      int
	Ancestry []string
}

// Change is the result of a detected integrity change, handed to the agent
// wiring which turns it into a SecurityEvent.
type Change struct {
	Path             string
	Kind             ChangeKind
	OldHash          string
	NewHash          string
	Algo             string
	Trigger          Trigger
	PkgMgrAttributed bool
	// SuppressReason explains why a change was routed to onExpected rather
	// than onChange: "pkg-mgr" (attributed to a package manager) or
	// "maintenance" (the host was in an unlock/maintenance window, so the
	// operator is expected to be changing files). Empty for a genuine
	// finding delivered via onChange.
	SuppressReason string
}

// Status is a point-in-time snapshot of the manager's baseline, surfaced up
// the stack so the UI can show whether the integrity baseline has been built.
type Status struct {
	Ready          bool
	FileCount      int
	LastBaselineAt time.Time
	HashAlgo       string
	Roots          []string
	Maintenance    bool
}

// Manager owns the baseline and the re-check pipeline. onChange is invoked for
// a genuine integrity violation; onExpected (optional) for a package-manager
// change that suppression silently re-baselined, so the agent can still emit an
// informational audit trail.
type Manager struct {
	cfg        Config
	onChange   func(Change)
	onExpected func(Change)

	mu             sync.Mutex
	baseline       Baseline
	ready          bool
	lastBaselineAt time.Time         // when the baseline was last (re)built or loaded
	maintenance    bool              // true while the host is in an unlock/maintenance window
	emitted        map[string]string // path → last-emitted hash (alert-once de-dupe)
	timers         map[string]*time.Timer
	pending        map[string]Trigger
}

// New builds a Manager, applying defaults for any unset config field.
func New(cfg Config, onChange, onExpected func(Change)) *Manager {
	if cfg.HashAlgo == "" {
		cfg.HashAlgo = "sha256"
	}
	if cfg.DebounceMs <= 0 {
		cfg.DebounceMs = 750
	}
	if cfg.StatePath == "" {
		cfg.StatePath = DefaultBaselinePath
	}
	return &Manager{
		cfg:        cfg,
		onChange:   onChange,
		onExpected: onExpected,
		baseline:   make(Baseline),
		emitted:    make(map[string]string),
		timers:     make(map[string]*time.Timer),
		pending:    make(map[string]Trigger),
	}
}

// Start loads a persisted baseline, or performs the initial scan in the
// background when none exists (the scan can take a while on a large /etc plus
// the binary dirs, so it must not block agent startup).
func (m *Manager) Start() {
	if b, err := LoadBaseline(m.cfg.StatePath); err == nil && b != nil {
		// The baseline file is rewritten on every save, so its mtime is a
		// good proxy for "last built" when we load a persisted baseline.
		built := time.Now()
		if fi, statErr := os.Stat(m.cfg.StatePath); statErr == nil {
			built = fi.ModTime()
		}
		m.mu.Lock()
		m.baseline = b
		m.ready = true
		m.lastBaselineAt = built
		m.mu.Unlock()
		return
	}
	go func() {
		scanned := Scan(m.cfg.Paths, m.cfg.Exclude, m.cfg.HashAlgo, nil)
		m.mu.Lock()
		m.baseline = scanned
		m.ready = true
		m.lastBaselineAt = time.Now()
		m.mu.Unlock()
		_ = m.save()
	}()
}

// Ready reports whether the baseline has been loaded/built yet. Re-checks
// before readiness are dropped (we can't compare against a baseline we don't
// have).
func (m *Manager) Ready() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ready
}

// Status returns a snapshot of the baseline state for status reporting.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Status{
		Ready:          m.ready,
		FileCount:      len(m.baseline),
		LastBaselineAt: m.lastBaselineAt,
		HashAlgo:       m.cfg.HashAlgo,
		Roots:          append([]string(nil), m.cfg.Paths...),
		Maintenance:    m.maintenance,
	}
}

// SetMaintenanceMode toggles maintenance suppression. While on, genuine
// content changes are treated as expected: the baseline is silently updated
// and the change is reported via onExpected (informational audit) instead of
// onChange (a Critical violation). The operator is assumed to be patching the
// host during an unlock/maintenance window, so file drift is not alarming.
func (m *Manager) SetMaintenanceMode(on bool) {
	m.mu.Lock()
	m.maintenance = on
	m.mu.Unlock()
}

// Monitors reports whether path falls under a configured root and isn't
// excluded — the cheap gate the eBPF hook uses before bothering to debounce.
func (m *Manager) Monitors(path string) bool {
	if path == "" || IsExcluded(path, m.cfg.Exclude) {
		return false
	}
	for _, root := range m.cfg.Paths {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}

// Notify is called by the eBPF hook when a write-ish event hits a monitored
// path. It debounces per-path so the burst of events from a single edit
// collapses into one re-check.
func (m *Manager) Notify(path string, t Trigger) {
	if path == "" {
		return
	}
	d := time.Duration(m.cfg.DebounceMs) * time.Millisecond
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pending[path] = t
	if timer, ok := m.timers[path]; ok {
		timer.Reset(d)
		return
	}
	m.timers[path] = time.AfterFunc(d, func() {
		m.mu.Lock()
		trig := m.pending[path]
		delete(m.pending, path)
		delete(m.timers, path)
		m.mu.Unlock()
		m.check(path, trig)
	})
}

// check re-hashes path and compares to the baseline, emitting a Change when the
// content differs. Exported as CheckNow for tests/manual triggers.
func (m *Manager) check(path string, t Trigger) {
	m.mu.Lock()
	if !m.ready {
		m.mu.Unlock()
		return
	}
	base, hadBase := m.baseline[path]
	algo := m.cfg.HashAlgo
	m.mu.Unlock()

	cur, exists, err := hashOne(path, algo)
	if err != nil {
		return
	}

	var kind ChangeKind
	var oldHash, newHash string
	switch {
	case !exists && hadBase:
		kind, oldHash = KindRemoved, base.Hash
	case !exists && !hadBase:
		return // a never-baselined transient file vanished — nothing to report
	case !hadBase:
		kind, newHash = KindAdded, cur.Hash
	case cur.Hash == base.Hash:
		// Reverted/unchanged — clear any prior emission so a later real change
		// re-alerts.
		m.mu.Lock()
		delete(m.emitted, path)
		m.mu.Unlock()
		return
	default:
		kind, oldHash, newHash = KindModified, base.Hash, cur.Hash
	}

	pkgmgr := AttributedToPkgMgr(t)
	change := Change{
		Path: path, Kind: kind, OldHash: oldHash, NewHash: newHash,
		Algo: algo, Trigger: t, PkgMgrAttributed: pkgmgr,
	}

	m.mu.Lock()
	if last, ok := m.emitted[path]; ok && last == newHash {
		m.mu.Unlock()
		return // already reported this exact change
	}
	// Suppress when attributed to a package manager, or when the host is in a
	// maintenance window (operator is expected to be changing files). Both
	// paths silently re-baseline and report informationally via onExpected.
	suppress, reason := false, ""
	switch {
	case pkgmgr && m.cfg.SuppressPkgMgr:
		suppress, reason = true, "pkg-mgr"
	case m.maintenance:
		suppress, reason = true, "maintenance"
	}
	if suppress {
		change.SuppressReason = reason
		if kind == KindRemoved {
			delete(m.baseline, path)
		} else {
			m.baseline[path] = cur
		}
		delete(m.emitted, path)
		m.mu.Unlock()
		_ = m.save()
		if m.onExpected != nil {
			m.onExpected(change)
		}
		return
	}
	// Genuine finding: do NOT re-baseline — the path stays "changed" until an
	// operator approves it (ApprovePaths). Mark emitted so repeated edits to
	// the same content don't spam.
	m.emitted[path] = newHash
	m.mu.Unlock()
	if m.onChange != nil {
		m.onChange(change)
	}
}

// CheckNow runs a synchronous re-check, bypassing the debounce. Mainly for
// tests and explicit operator triggers.
func (m *Manager) CheckNow(path string, t Trigger) { m.check(path, t) }

// ApprovePaths accepts the current on-disk content of each path as the new
// known-good baseline (the operator reviewed and approved the change) and
// clears the pending/de-dupe state so the path is no longer flagged.
func (m *Manager) ApprovePaths(paths []string) {
	type upd struct {
		path   string
		entry  Entry
		exists bool
	}
	updates := make([]upd, 0, len(paths))
	algo := m.cfg.HashAlgo
	for _, p := range paths {
		cur, exists, err := hashOne(p, algo)
		if err != nil {
			continue
		}
		updates = append(updates, upd{p, cur, exists})
	}
	m.mu.Lock()
	for _, u := range updates {
		if u.exists {
			m.baseline[u.path] = u.entry
		} else {
			delete(m.baseline, u.path)
		}
		delete(m.emitted, u.path)
	}
	m.mu.Unlock()
	_ = m.save()
}

// Rebaseline rescans every monitored path and replaces the baseline wholesale,
// accepting current disk state as known-good.
func (m *Manager) Rebaseline() {
	scanned := Scan(m.cfg.Paths, m.cfg.Exclude, m.cfg.HashAlgo, nil)
	m.mu.Lock()
	m.baseline = scanned
	m.emitted = make(map[string]string)
	m.ready = true
	m.lastBaselineAt = time.Now()
	m.mu.Unlock()
	_ = m.save()
}

// save persists a snapshot of the baseline to disk (I/O performed outside the
// lock).
func (m *Manager) save() error {
	m.mu.Lock()
	clone := make(Baseline, len(m.baseline))
	for k, v := range m.baseline {
		clone[k] = v
	}
	path := m.cfg.StatePath
	m.mu.Unlock()
	return SaveBaseline(path, clone)
}

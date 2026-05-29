package sshlockdown

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Blocker is the kernel-side enforcement surface — what actually denies
// or permits SSH accepts. The interface is small on purpose: the LSM
// program (or TC fallback) lives behind it, and the manager doesn't
// need to know which is active. A nil Blocker turns the manager into a
// no-op state tracker, useful for tests and dry-run rollouts.
//
// Implementations:
//   - bpflsm.Blocker (production, kernel >= 5.7 + CONFIG_BPF_LSM)
//   - tc.Blocker    (production fallback, packet drop on ingress)
//   - NoopBlocker   (default at agent start, until kernel cap check
//     decides which real one to load; also used by tests)
type Blocker interface {
	// Lock denies all new sshd accept()s except for the supplied
	// allowlist. Called whenever the manager transitions LOCKED, and
	// whenever the allowlist changes during a lockdown. Idempotent —
	// the manager may call Lock several times consecutively with the
	// same allowlist after a tick re-eval.
	Lock(allowlist []string) error

	// Unlock removes the block through releaseUntil (or until Lock is
	// called sooner). Passing zero time means "unlock until further
	// notice"; the manager always supplies the real expiry so the
	// kernel-side BPF map's release_until cell carries the same
	// deadline the userspace state tracks. The allowlist is still
	// applied — the kernel honors allowlist entries regardless of lock
	// state, so it's loaded once and read on every accept.
	Unlock(allowlist []string, releaseUntil time.Time) error

	// Close releases kernel resources (detach LSM program, remove BPF
	// maps, delete TC qdisc, etc.). Called once during agent shutdown.
	Close() error
}

// NoopBlocker is the default Blocker used before the manager has wired
// the real kernel implementation, and in unit tests. It records the last
// call so tests can assert intent without needing a kernel.
type NoopBlocker struct {
	mu             sync.Mutex
	LastLocked     bool
	LastAllowlist  []string
	LockCalls      int
	UnlockCalls    int
	CloseCalled    bool
}

func (b *NoopBlocker) Lock(allowlist []string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.LastLocked = true
	b.LastAllowlist = append(b.LastAllowlist[:0], allowlist...)
	b.LockCalls++
	return nil
}

func (b *NoopBlocker) Unlock(allowlist []string, _ time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.LastLocked = false
	b.LastAllowlist = append(b.LastAllowlist[:0], allowlist...)
	b.UnlockCalls++
	return nil
}

func (b *NoopBlocker) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.CloseCalled = true
	return nil
}

// Snapshot returns a read-only view of the recorded calls. Tests use
// this instead of touching the fields directly so we don't have to
// expose the mutex in the public type.
func (b *NoopBlocker) Snapshot() (locked bool, allowlist []string, locks, unlocks int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.LastLocked, append([]string(nil), b.LastAllowlist...), b.LockCalls, b.UnlockCalls
}

// Options configures a Manager. All fields are optional; the manager
// supplies safe defaults when one is left zero.
type Options struct {
	// StatePath overrides DefaultStatePath. Tests pass a temp dir.
	StatePath string

	// Now lets tests inject a clock. Production passes time.Now.
	Now func() time.Time

	// DeadManThreshold is how long the manager waits without a control-
	// plane heartbeat before dropping the lockdown. Zero = disabled
	// (don't lift the block on heartbeat loss). Production default is
	// 10 minutes; set zero only when you're certain the operator has
	// another access path (console, IPMI).
	DeadManThreshold time.Duration

	// MinTickInterval clamps how often the manager re-evaluates. Even
	// when NextChangeAt is years away, we still tick at least this often
	// to pick up clock skew and to refresh the dead-man timer. Default
	// 30s.
	MinTickInterval time.Duration

	// Logger receives non-fatal warnings (failed Save, blocker errors).
	// Nil-safe — falls back to discard.
	Logger Logger
}

// Logger is the minimal log surface — keeps this package free of any
// specific logger dependency.
type Logger interface {
	Warnf(format string, args ...interface{})
	Infof(format string, args ...interface{})
}

type discardLogger struct{}

func (discardLogger) Warnf(string, ...interface{}) {}
func (discardLogger) Infof(string, ...interface{}) {}

// Manager owns the lockdown state for one host. Methods are safe for
// concurrent use — the WebSocket handler can call SetState while the
// ticker is mid-Evaluate.
type Manager struct {
	opts    Options
	blocker Blocker

	mu        sync.RWMutex
	state     State
	heartbeat time.Time // last time the control plane confirmed it sees us

	// wakeup is signalled by SetState / Heartbeat so the ticker re-runs
	// immediately instead of waiting for the next interval. Buffered
	// 1-deep — coalesces concurrent wakeups.
	wakeup chan struct{}
}

// NewManager builds a Manager backed by blocker. The initial state is
// loaded from disk if Options.StatePath exists; otherwise zero. Call
// Run to start the ticker.
func NewManager(blocker Blocker, opts Options) (*Manager, error) {
	if opts.StatePath == "" {
		opts.StatePath = DefaultStatePath
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.MinTickInterval <= 0 {
		opts.MinTickInterval = 30 * time.Second
	}
	if opts.Logger == nil {
		opts.Logger = discardLogger{}
	}
	if blocker == nil {
		blocker = &NoopBlocker{}
	}

	m := &Manager{
		opts:    opts,
		blocker: blocker,
		wakeup:  make(chan struct{}, 1),
	}

	loaded, err := LoadState(opts.StatePath)
	if err != nil {
		opts.Logger.Warnf("lockdown: failed to load persisted state from %s: %v", opts.StatePath, err)
	}
	m.state = loaded
	// Heartbeat starts fresh — the dead-man timer doesn't fire until the
	// control plane has had a chance to check in.
	m.heartbeat = opts.Now()
	return m, nil
}

// State returns a copy of the current State. Safe to mutate.
func (m *Manager) State() State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneState(m.state)
}

// SetState replaces the entire state. Used by the control plane when
// the UI pushes a full update (schedule edit, allowlist edit, etc.).
// Validates first; rejects rather than persists a bad value.
func (m *Manager) SetState(s State) error {
	if err := s.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	m.state = cloneState(s)
	m.mu.Unlock()

	if err := SaveState(m.opts.StatePath, s); err != nil {
		m.opts.Logger.Warnf("lockdown: SaveState failed: %v", err)
	}
	m.kick()
	return nil
}

// Unlock pushes ReleaseUntil to now+duration (or extends it if the
// existing value is later — extension never shortens an active unlock).
// updatedBy is recorded in the audit field. Returns the timestamp the
// host will re-lock at.
func (m *Manager) Unlock(duration time.Duration, updatedBy string) (time.Time, error) {
	if duration <= 0 {
		return time.Time{}, errors.New("duration must be positive")
	}
	now := m.opts.Now()
	target := now.Add(duration)

	m.mu.Lock()
	if m.state.ReleaseUntil.After(target) {
		// Extension shorter than existing window — keep the existing one.
		target = m.state.ReleaseUntil
	}
	m.state.ReleaseUntil = target
	m.state.UpdatedAt = now
	m.state.UpdatedBy = updatedBy
	snapshot := cloneState(m.state)
	m.mu.Unlock()

	if err := SaveState(m.opts.StatePath, snapshot); err != nil {
		m.opts.Logger.Warnf("lockdown: SaveState failed during Unlock: %v", err)
	}
	m.kick()
	return target, nil
}

// LockNow clears any active unlock so the next tick relocks immediately.
// Schedule-driven unlocks pick up again at the next window start.
func (m *Manager) LockNow(updatedBy string) error {
	m.mu.Lock()
	m.state.ReleaseUntil = time.Time{}
	m.state.UpdatedAt = m.opts.Now()
	m.state.UpdatedBy = updatedBy
	snapshot := cloneState(m.state)
	m.mu.Unlock()

	if err := SaveState(m.opts.StatePath, snapshot); err != nil {
		m.opts.Logger.Warnf("lockdown: SaveState failed during LockNow: %v", err)
	}
	m.kick()
	return nil
}

// Heartbeat records that the control plane is alive. The dead-man timer
// resets to zero on every call. The agent's WebSocket loop calls this
// every time it gets a server-pushed message (any method, not just
// lockdown commands).
func (m *Manager) Heartbeat() {
	m.mu.Lock()
	m.heartbeat = m.opts.Now()
	m.mu.Unlock()
}

// Run is the manager's main loop. Cancel ctx to shut down — Run returns
// after the next blocker call completes and Close() runs.
//
// Each iteration:
//  1. Evaluate the state with current `now`.
//  2. If the dead-man threshold is configured and we've gone past it
//     without a heartbeat, force-unlock (override). This prevents a
//     wedged host: agent loses control plane → can never be unlocked
//     manually → operator has no path back unless dead-man fires.
//  3. Apply the decision to the blocker.
//  4. Sleep until either NextChangeAt or MinTickInterval, whichever is
//     sooner. wakeup channel preempts the sleep when SetState/Unlock/
//     LockNow are called.
func (m *Manager) Run(ctx context.Context) {
	defer func() {
		if err := m.blocker.Close(); err != nil {
			m.opts.Logger.Warnf("lockdown: blocker.Close: %v", err)
		}
	}()

	for {
		// Take a consistent snapshot for this iteration.
		m.mu.RLock()
		state := cloneState(m.state)
		heartbeat := m.heartbeat
		m.mu.RUnlock()

		now := m.opts.Now()
		decision := Evaluate(state, now)

		// Dead-man override: if the threshold has elapsed without a
		// heartbeat, force-unlock so operators can reach the host out-of-
		// band. Note we don't update state.ReleaseUntil — the moment a
		// heartbeat returns, the next eval picks up the original state.
		deadMan := false
		if m.opts.DeadManThreshold > 0 && now.Sub(heartbeat) > m.opts.DeadManThreshold {
			decision = Decision{Locked: false, ReleaseUntil: time.Time{}, NextChangeAt: now.Add(m.opts.MinTickInterval)}
			deadMan = true
		}

		// Apply to the blocker.
		var err error
		if decision.Locked {
			err = m.blocker.Lock(state.AllowedSourceIPs)
		} else {
			err = m.blocker.Unlock(state.AllowedSourceIPs, decision.ReleaseUntil)
		}
		if err != nil {
			m.opts.Logger.Warnf("lockdown: blocker apply failed (locked=%v, dead_man=%v): %v", decision.Locked, deadMan, err)
		}

		// Compute sleep duration.
		sleep := m.opts.MinTickInterval
		if !decision.NextChangeAt.IsZero() {
			until := decision.NextChangeAt.Sub(now)
			if until > 0 && until < sleep {
				sleep = until
			}
		}
		if sleep < time.Second {
			// Don't busy-loop. Floor at 1s — picks up clock-skew misses
			// without burning CPU.
			sleep = time.Second
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(sleep):
		case <-m.wakeup:
		}
	}
}

func (m *Manager) kick() {
	select {
	case m.wakeup <- struct{}{}:
	default:
	}
}

func cloneState(s State) State {
	out := State{
		ReleaseUntil: s.ReleaseUntil,
		UpdatedAt:    s.UpdatedAt,
		UpdatedBy:    s.UpdatedBy,
	}
	if len(s.AllowedSourceIPs) > 0 {
		out.AllowedSourceIPs = append([]string(nil), s.AllowedSourceIPs...)
	}
	if len(s.Schedule) > 0 {
		out.Schedule = append([]ScheduleWindow(nil), s.Schedule...)
		for i, w := range out.Schedule {
			if len(w.DaysOfWeek) > 0 {
				out.Schedule[i].DaysOfWeek = append([]int(nil), w.DaysOfWeek...)
			}
		}
	}
	return out
}

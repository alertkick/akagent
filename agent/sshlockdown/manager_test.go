package sshlockdown

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock lets tests step time deterministically without sleeping.
type fakeClock struct{ now atomic.Value }

func newFakeClock(t time.Time) *fakeClock {
	c := &fakeClock{}
	c.now.Store(t)
	return c
}
func (c *fakeClock) Now() time.Time { return c.now.Load().(time.Time) }
func (c *fakeClock) Set(t time.Time) { c.now.Store(t) }

func TestManager_InitialStateAppliesLock(t *testing.T) {
	b := &NoopBlocker{}
	clk := newFakeClock(mustParse(t, time.RFC3339, "2026-05-29T14:00:00Z"))
	m, err := NewManager(b, Options{
		StatePath: filepath.Join(t.TempDir(), "lockdown.json"),
		Now:       clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	// Wait for the first apply.
	waitFor(t, func() bool { l, _, lc, _ := b.Snapshot(); return l && lc >= 1 })
	locked, _, _, _ := b.Snapshot()
	if !locked {
		t.Fatalf("expected initial Lock call")
	}
}

func TestManager_UnlockAppliesAndRelocks(t *testing.T) {
	b := &NoopBlocker{}
	clk := newFakeClock(mustParse(t, time.RFC3339, "2026-05-29T14:00:00Z"))
	m, _ := NewManager(b, Options{
		StatePath:       filepath.Join(t.TempDir(), "lockdown.json"),
		Now:             clk.Now,
		MinTickInterval: 1 * time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	// Initial lock applied.
	waitFor(t, func() bool { l, _, _, _ := b.Snapshot(); return l })

	// Trigger an unlock — manager should switch state on next tick.
	if _, err := m.Unlock(10*time.Minute, "ssidhu"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { l, _, _, _ := b.Snapshot(); return !l })

	// Advance clock past the unlock; next tick should re-lock.
	clk.Set(mustParse(t, time.RFC3339, "2026-05-29T14:11:00Z"))
	waitFor(t, func() bool { l, _, _, _ := b.Snapshot(); return l })
}

func TestManager_UnlockExtensionNeverShortens(t *testing.T) {
	m, _ := NewManager(&NoopBlocker{}, Options{
		StatePath: filepath.Join(t.TempDir(), "lockdown.json"),
		Now:       newFakeClock(mustParse(t, time.RFC3339, "2026-05-29T14:00:00Z")).Now,
	})
	first, err := m.Unlock(60*time.Minute, "ssidhu")
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.Unlock(10*time.Minute, "ssidhu")
	if err != nil {
		t.Fatal(err)
	}
	if !second.Equal(first) {
		t.Fatalf("second Unlock (10m) should not shorten first (60m). got %v want %v", second, first)
	}
}

func TestManager_LockNowOverridesUnlock(t *testing.T) {
	b := &NoopBlocker{}
	clk := newFakeClock(mustParse(t, time.RFC3339, "2026-05-29T14:00:00Z"))
	m, _ := NewManager(b, Options{
		StatePath: filepath.Join(t.TempDir(), "lockdown.json"),
		Now:       clk.Now,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	_, _ = m.Unlock(30*time.Minute, "ssidhu")
	waitFor(t, func() bool { l, _, _, _ := b.Snapshot(); return !l })

	_ = m.LockNow("ssidhu")
	waitFor(t, func() bool { l, _, _, _ := b.Snapshot(); return l })
}

func TestManager_DeadManSwitchUnlocksAfterHeartbeatLoss(t *testing.T) {
	b := &NoopBlocker{}
	clk := newFakeClock(mustParse(t, time.RFC3339, "2026-05-29T14:00:00Z"))
	m, _ := NewManager(b, Options{
		StatePath:        filepath.Join(t.TempDir(), "lockdown.json"),
		Now:              clk.Now,
		MinTickInterval:  1 * time.Second,
		DeadManThreshold: 5 * time.Minute,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	waitFor(t, func() bool { l, _, _, _ := b.Snapshot(); return l })

	// Advance past dead-man threshold without heartbeat.
	clk.Set(clk.Now().Add(6 * time.Minute))
	waitFor(t, func() bool { l, _, _, _ := b.Snapshot(); return !l })
}

func TestManager_HeartbeatPreventsDeadMan(t *testing.T) {
	b := &NoopBlocker{}
	clk := newFakeClock(mustParse(t, time.RFC3339, "2026-05-29T14:00:00Z"))
	m, _ := NewManager(b, Options{
		StatePath:        filepath.Join(t.TempDir(), "lockdown.json"),
		Now:              clk.Now,
		MinTickInterval:  1 * time.Second,
		DeadManThreshold: 5 * time.Minute,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	waitFor(t, func() bool { l, _, _, _ := b.Snapshot(); return l })

	// Advance 4 min, heartbeat, advance 4 min — total 8 min but never
	// 5 consecutive minutes without heartbeat, so lock should hold.
	clk.Set(clk.Now().Add(4 * time.Minute))
	m.Heartbeat()
	clk.Set(clk.Now().Add(4 * time.Minute))
	// Give the manager a few ticks at the new time.
	time.Sleep(50 * time.Millisecond)
	locked, _, _, _ := b.Snapshot()
	if !locked {
		t.Fatal("dead-man should NOT have fired with intermittent heartbeats")
	}
}

func TestManager_PersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lockdown.json")
	clk := newFakeClock(mustParse(t, time.RFC3339, "2026-05-29T14:00:00Z"))

	// First manager: unlock for 30 min, then "die".
	{
		m, _ := NewManager(&NoopBlocker{}, Options{StatePath: path, Now: clk.Now})
		if _, err := m.Unlock(30*time.Minute, "ssidhu"); err != nil {
			t.Fatal(err)
		}
	}

	// Second manager (simulated restart) at the same time: should load
	// the persisted unlock and report unlocked.
	{
		m, _ := NewManager(&NoopBlocker{}, Options{StatePath: path, Now: clk.Now})
		s := m.State()
		if s.ReleaseUntil.IsZero() {
			t.Fatal("restarted manager should have loaded persisted ReleaseUntil")
		}
		d := Evaluate(s, clk.Now())
		if d.Locked {
			t.Fatal("restarted manager should be unlocked (unlock not yet expired)")
		}
	}
}

func TestManager_SetStateRejectsBadSchedule(t *testing.T) {
	m, _ := NewManager(&NoopBlocker{}, Options{
		StatePath: filepath.Join(t.TempDir(), "lockdown.json"),
	})
	bad := State{Schedule: []ScheduleWindow{{StartTime: "25:00", EndTime: "03:00"}}}
	if err := m.SetState(bad); err == nil {
		t.Fatal("expected SetState to reject schedule with hour > 23")
	}
}

// waitFor polls cond up to 2 seconds. Tests use this instead of time.Sleep
// so they pass quickly when the manager reacts fast and don't flake when
// it's slow.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("waitFor: condition not met within 2s")
}

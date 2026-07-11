//go:build linux

package ebpf

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// Regression tests for the stg-fe-app-eu-1 startup deadlock (2026-07-06 /
// 2026-07-11): StartEventListener holds mu's write lock while Readopt
// classifies re-adopted SSH sessions; classify calls the allowlist closure,
// which used to route through GetNativeConfig() → mu.RLock() → self-deadlock.
// The allowlist must therefore be readable without touching mu.

// runOrDeadlock runs fn in a goroutine and fails the test if it doesn't
// complete quickly — the signature of re-entering mu.
func runOrDeadlock(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s blocked while mu was write-held — reintroduces the SSH-session startup deadlock", what)
	}
}

func TestSSHAllowedSourceIPsLockFree(t *testing.T) {
	a := &NativeEBPFAgent{}
	a.storeSSHAllowlist([]string{"203.0.113.7", "10.0.0.0/8"})

	// Hold the write lock like StartEventListener does around Readopt.
	a.mu.Lock()
	defer a.mu.Unlock()

	runOrDeadlock(t, "SSHAllowedSourceIPs()", func() {
		got := a.SSHAllowedSourceIPs()
		if !reflect.DeepEqual(got, []string{"203.0.113.7", "10.0.0.0/8"}) {
			t.Errorf("unexpected allowlist: %v", got)
		}
	})
}

func TestClassifyUnderWriteLock(t *testing.T) {
	a := &NativeEBPFAgent{sshSessionTracker: NewSSHSessionTracker()}
	a.storeSSHAllowlist([]string{"203.0.113.7"})
	// Wire the allowlist the same way initSSHLockdown does (minus the
	// lockdown manager's own list, which has no mu involvement).
	a.SetSSHAllowlistFunc(func() []string { return a.SSHAllowedSourceIPs() })

	a.mu.Lock()
	defer a.mu.Unlock()

	runOrDeadlock(t, "sshSessionTracker.classify()", func() {
		if got := a.sshSessionTracker.classify("203.0.113.7"); got != sshClassTrusted {
			t.Errorf("classify(allowlisted) = %q, want %q", got, sshClassTrusted)
		}
		if got := a.sshSessionTracker.classify("198.51.100.9"); got != sshClassUntrusted {
			t.Errorf("classify(other) = %q, want %q", got, sshClassUntrusted)
		}
	})
}

// TestUpdateNativeConfigRefreshesAllowlistSnapshot ensures a config push
// updates the lock-free snapshot, so classification tracks ac-007 edits.
func TestUpdateNativeConfigRefreshesAllowlistSnapshot(t *testing.T) {
	cfg := DefaultNativeConfig()
	a := &NativeEBPFAgent{
		config:      cfg,
		configPath:  filepath.Join(t.TempDir(), "native.json"),
		filter:      NewEventFilter(&cfg),
		alertFilter: NewAlertFilterWithLists(&cfg.AlertFilter, &cfg.NativeLists),
		rateLimiter: NewRateLimiter(cfg.RateLimiter),
		enricher:    NewEventEnricherWithTTL(30 * time.Second),
	}
	a.storeSSHAllowlist(cfg.SSHAllowedSourceIPs)

	newCfg := DefaultNativeConfig()
	newCfg.SSHAllowedSourceIPs = []string{"192.0.2.1"}
	if err := a.UpdateNativeConfig(newCfg); err != nil {
		t.Fatalf("UpdateNativeConfig: %v", err)
	}
	if got := a.SSHAllowedSourceIPs(); !reflect.DeepEqual(got, []string{"192.0.2.1"}) {
		t.Errorf("allowlist snapshot after update = %v, want [192.0.2.1]", got)
	}
}

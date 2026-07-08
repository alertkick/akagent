//go:build windows

package winevt

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"akagent/ebpf"
)

// TestSecurityEventPipeline drives the full Windows security-event path on a
// real (elevated) runner: enable audit policy, subscribe to the Security and
// System channels, perform actions that generate known event IDs, and assert
// the collector emits the correctly-mapped SecurityEvents. This is the
// end-to-end proof that EvtSubscribe → EvtRender → parseEventXML → MapEvent
// works against genuine Windows audit events, not synthesized XML.
//
// Requires administrator (audit policy + Security channel subscription).
// GitHub windows runners are elevated; skipped under -short.
func TestSecurityEventPipeline(t *testing.T) {
	if testing.Short() {
		t.Skip("pipeline test mutates audit policy and system state; run in the dedicated CI step")
	}

	// 1. Enable the audit subcategories our events depend on.
	for _, sub := range []string{"User Account Management", "Security Group Management", "Logon", "Process Creation"} {
		run(t, "auditpol", "/set", "/subcategory:"+sub, "/success:enable", "/failure:enable")
	}

	// 2. Collect emitted events by rule.
	var mu sync.Mutex
	byRule := map[string]ebpf.SecurityEvent{}

	c := NewCollector(500)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Subscribe to Security (logons, account mgmt, 4688) and System (7045).
	for _, ch := range []string{"Security", "System"} {
		sub, err := subscribe(ch)
		if err != nil {
			t.Fatalf("subscribe(%s): %v", ch, err)
		}
		defer sub.close()
		go c.readLoop(ctx, sub)
	}
	drainInto(ctx, c, &mu, byRule)

	time.Sleep(1 * time.Second) // let subscriptions arm

	// 3. Generate events.
	suffix := fmt.Sprintf("%d", time.Now().UnixNano()%100000)
	user := "aktest" + suffix
	svcName := "aktestsvc" + suffix

	// 4720 — user account created (and 4732/4728 if added to a group).
	run(t, "net", "user", user, "Akp@ssw0rd!"+suffix, "/add")
	defer exec.Command("net", "user", user, "/delete").Run()

	// 7045 — service installed (System channel, SCM).
	run(t, "sc.exe", "create", svcName, "binPath=", `C:\Windows\System32\cmd.exe /c rem`)
	defer exec.Command("sc.exe", "delete", svcName).Run()

	// 4688 — process creation.
	run(t, "cmd.exe", "/c", "whoami")

	// 4625 — failed logon (bad password against the loopback IPC share).
	// Expected to fail; we only care that it emits the audit event.
	exec.Command("net", "use", `\\127.0.0.1\IPC$`, "/user:"+user, "wrongpassword").Run()

	// 4. Wait for the expected rules to show up.
	want := []string{"User Account Created", "Service Installed", "Process Execution"}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		missing := filterMissing(byRule, want)
		mu.Unlock()
		if len(missing) == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, rule := range want {
		ev, ok := byRule[rule]
		if !ok {
			t.Errorf("expected a %q event, none observed", rule)
			continue
		}
		if !ev.Validate() {
			t.Errorf("%q event failed validation: %+v", rule, ev)
		}
	}
	// The created-user name should appear in the account event's fields.
	if ev, ok := byRule["User Account Created"]; ok {
		if tgt, _ := ev.RawFields["target_user"].(string); !strings.EqualFold(tgt, user) {
			t.Errorf("User Account Created target_user = %q, want %q", tgt, user)
		}
	}
	// 4625 is best-effort (net use behaviour varies); log rather than fail.
	if _, ok := byRule["Windows Logon Failure"]; !ok {
		t.Log("note: no 4625 failed-logon event observed (net use path may not audit on this runner)")
	}
}

// drainInto reads the collector's event channel into a rule-keyed map.
func drainInto(ctx context.Context, c *Collector, mu *sync.Mutex, byRule map[string]ebpf.SecurityEvent) {
	go func() {
		ch := c.EventChannel()
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-ch:
				mu.Lock()
				byRule[ev.Rule] = ev
				mu.Unlock()
			}
		}
	}()
}

func filterMissing(byRule map[string]ebpf.SecurityEvent, want []string) []string {
	var missing []string
	for _, r := range want {
		if _, ok := byRule[r]; !ok {
			missing = append(missing, r)
		}
	}
	return missing
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v (%s)", name, strings.Join(args, " "), err, out)
	}
}

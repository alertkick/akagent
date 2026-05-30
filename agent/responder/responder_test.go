package responder

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// fakeRunner records the commands it was asked to run.
type fakeRunner struct{ cmds []string }

func (f *fakeRunner) run(name string, args ...string) error {
	f.cmds = append(f.cmds, name+" "+strings.Join(args, " "))
	return nil
}

func TestBlockRefusesAllowlistedAndManagement(t *testing.T) {
	r := New(Config{Allowlist: []string{"203.0.113.0/24"}}, nil)
	fr := &fakeRunner{}
	r.run = fr.run

	for _, ip := range []string{"127.0.0.1", "203.0.113.50"} {
		if err := r.BlockIP(ip, 0); err == nil {
			t.Fatalf("expected refusal blocking %s", ip)
		}
	}
	if len(fr.cmds) != 0 {
		t.Fatalf("no iptables commands should run for refused blocks, got %v", fr.cmds)
	}
}

func TestDryRunDoesNotEnforce(t *testing.T) {
	r := New(Config{DryRun: true}, nil)
	fr := &fakeRunner{}
	r.run = fr.run
	if err := r.BlockIP("8.8.8.8", 0); err != nil {
		t.Fatalf("dry-run block should not error: %v", err)
	}
	if len(fr.cmds) != 0 {
		t.Fatalf("dry-run must not touch iptables, got %v", fr.cmds)
	}
}

func TestBlockEnforceIssuesIptables(t *testing.T) {
	r := New(Config{DryRun: false}, nil)
	fr := &fakeRunner{}
	r.run = fr.run
	if err := r.BlockIP("8.8.8.8", 0); err != nil {
		t.Fatalf("block failed: %v", err)
	}
	joined := strings.Join(fr.cmds, "\n")
	for _, want := range []string{
		"iptables -A ALERTKICK_BLOCK -s 8.8.8.8 -j DROP",
		"iptables -A ALERTKICK_BLOCK -d 8.8.8.8 -j DROP",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected command %q in:\n%s", want, joined)
		}
	}
}

func TestKillGuardrails(t *testing.T) {
	r := New(Config{DryRun: false}, nil)
	r.commOf = func(pid int) string {
		if pid == 999 {
			return "sshd"
		}
		return "evil"
	}
	if err := r.KillProcess(1); err == nil {
		t.Fatal("must refuse pid 1")
	}
	if err := r.KillProcess(os.Getpid()); err == nil {
		t.Fatal("must refuse self")
	}
	if err := r.KillProcess(999); err == nil {
		t.Fatal("must refuse protected comm (sshd)")
	}
}

func TestKillDryRun(t *testing.T) {
	r := New(Config{DryRun: true}, nil)
	r.commOf = func(int) string { return "evil" }
	// Use a pid that's almost certainly not us and not protected; dry-run means
	// no signal is actually sent regardless.
	if err := r.KillProcess(2147480000); err != nil {
		t.Fatalf("dry-run kill should not error: %v", err)
	}
}

func TestAuditCalled(t *testing.T) {
	var audits []string
	r := New(Config{DryRun: true}, func(action, target, result string) {
		audits = append(audits, action+" "+target+" "+result)
	})
	_ = r.BlockIP("8.8.8.8", 0)
	if len(audits) != 1 || !strings.Contains(audits[0], "dry-run") {
		t.Fatalf("expected one dry-run audit, got %v", audits)
	}
	_ = strconv.Itoa(0)
}

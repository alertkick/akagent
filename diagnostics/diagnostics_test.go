package diagnostics

import (
	"context"
	"strings"
	"testing"
)

func TestJournalRejectsInvalidUnit(t *testing.T) {
	bad := []string{"foo; rm -rf /", "unit name", "a$b", strings.Repeat("x", 200), "../etc"}
	for _, unit := range bad {
		if _, err := Journal(context.Background(), JournalArgs{Unit: unit}); err == nil {
			t.Errorf("unit %q should be rejected", unit)
		}
	}
	good := []string{"nginx", "docker.service", "user@1000.service", "systemd-journald"}
	for _, unit := range good {
		if !unitNameRe.MatchString(unit) {
			t.Errorf("unit %q should be accepted", unit)
		}
	}
}

func TestProcessesRejectsBadSort(t *testing.T) {
	if _, err := Processes(context.Background(), ProcessesArgs{Sort: "evil"}); err == nil {
		t.Error("sort=evil should be rejected")
	}
}

func TestNewResultCapsOutput(t *testing.T) {
	r := newResult("bundle", strings.Repeat("a", MaxTotalBytes+100))
	if !r.Truncated {
		t.Error("expected truncated flag")
	}
	if len(r.Output) > MaxTotalBytes+len(truncationNotice) {
		t.Errorf("output not capped: %d bytes", len(r.Output))
	}
}

func TestMemorySummaryFilters(t *testing.T) {
	// Runs against the real /proc on Linux CI; just assert it's non-empty
	// and smaller than the raw file would be.
	s := memorySummary()
	if s == "" {
		t.Fatal("memorySummary empty")
	}
	if !strings.Contains(s, "MemTotal") && !strings.Contains(s, "unreadable") {
		t.Errorf("unexpected summary: %.120s", s)
	}
}

func TestTailLines(t *testing.T) {
	in := "a\nb\nc\nd"
	if got := tailLines(in, 2); got != "c\nd" {
		t.Errorf("tailLines = %q", got)
	}
	if got := tailLines(in, 10); got != in {
		t.Errorf("tailLines short input = %q", got)
	}
}

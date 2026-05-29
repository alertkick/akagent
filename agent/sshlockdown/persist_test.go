package sshlockdown

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadState_MissingFileIsZero(t *testing.T) {
	got, err := LoadState(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if !got.ReleaseUntil.IsZero() || len(got.Schedule) != 0 {
		t.Fatalf("expected zero state, got %+v", got)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lockdown.json")
	want := State{
		ReleaseUntil:     mustParse(t, time.RFC3339, "2026-05-29T15:00:00Z"),
		AllowedSourceIPs: []string{"10.0.0.0/24", "192.168.1.5"},
		Schedule: []ScheduleWindow{
			{StartTime: "02:00", EndTime: "03:00", Timezone: "UTC", DaysOfWeek: []int{int(time.Friday)}},
		},
		UpdatedAt: mustParse(t, time.RFC3339, "2026-05-29T14:30:00Z"),
		UpdatedBy: "ssidhu",
	}
	if err := SaveState(path, want); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	got, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if !got.ReleaseUntil.Equal(want.ReleaseUntil) {
		t.Errorf("ReleaseUntil: got %v want %v", got.ReleaseUntil, want.ReleaseUntil)
	}
	if got.UpdatedBy != want.UpdatedBy {
		t.Errorf("UpdatedBy: got %q want %q", got.UpdatedBy, want.UpdatedBy)
	}
	if len(got.AllowedSourceIPs) != 2 || got.AllowedSourceIPs[0] != "10.0.0.0/24" {
		t.Errorf("AllowedSourceIPs round-trip failed: %v", got.AllowedSourceIPs)
	}
	if len(got.Schedule) != 1 || got.Schedule[0].StartTime != "02:00" {
		t.Errorf("Schedule round-trip failed: %+v", got.Schedule)
	}
}

func TestSaveState_AtomicReplace(t *testing.T) {
	// SaveState must replace an existing file without ever leaving the
	// target path partially-written. Verify by writing twice and checking
	// the second write's content is fully present (not interleaved with
	// the first).
	path := filepath.Join(t.TempDir(), "lockdown.json")
	if err := SaveState(path, State{UpdatedBy: "first"}); err != nil {
		t.Fatal(err)
	}
	if err := SaveState(path, State{UpdatedBy: "second"}); err != nil {
		t.Fatal(err)
	}
	got, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.UpdatedBy != "second" {
		t.Fatalf("expected second write to win, got %q", got.UpdatedBy)
	}
}

func TestSaveState_FilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subdir", "lockdown.json")
	if err := SaveState(path, State{UpdatedBy: "x"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("file perms = %o, want 0600", mode)
	}
	dirInfo, _ := os.Stat(filepath.Dir(path))
	if mode := dirInfo.Mode().Perm(); mode != 0o700 {
		t.Errorf("dir perms = %o, want 0700", mode)
	}
}

func TestSaveState_NoTempFileLeftBehind(t *testing.T) {
	// Ensure the atomic-rename machinery removes its temp file even on
	// the happy path, so /var/lib/akagent doesn't accumulate cruft over
	// thousands of writes.
	dir := t.TempDir()
	path := filepath.Join(dir, "lockdown.json")
	for i := 0; i < 5; i++ {
		if err := SaveState(path, State{UpdatedBy: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(path) {
			t.Errorf("unexpected file left behind: %s", e.Name())
		}
	}
}

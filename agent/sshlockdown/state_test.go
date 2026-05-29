package sshlockdown

import (
	"testing"
	"time"
)

// mustParse helps every test build a wall-clock time without TZ noise.
func mustParse(t *testing.T, layout, value string) time.Time {
	t.Helper()
	ts, err := time.Parse(layout, value)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func TestEvaluate_DefaultLocked(t *testing.T) {
	now := mustParse(t, time.RFC3339, "2026-05-29T14:00:00Z")
	d := Evaluate(State{}, now)
	if !d.Locked {
		t.Fatal("zero-state should be locked")
	}
	if !d.ReleaseUntil.IsZero() {
		t.Fatalf("ReleaseUntil should be zero when locked, got %v", d.ReleaseUntil)
	}
	if !d.NextChangeAt.IsZero() {
		t.Fatalf("NextChangeAt should be zero with no schedule, got %v", d.NextChangeAt)
	}
}

func TestEvaluate_AdHocUnlockActive(t *testing.T) {
	now := mustParse(t, time.RFC3339, "2026-05-29T14:00:00Z")
	release := now.Add(30 * time.Minute)
	d := Evaluate(State{ReleaseUntil: release}, now)
	if d.Locked {
		t.Fatal("expected unlocked while inside ReleaseUntil window")
	}
	if !d.ReleaseUntil.Equal(release) {
		t.Fatalf("ReleaseUntil = %v, want %v", d.ReleaseUntil, release)
	}
	if !d.NextChangeAt.Equal(release) {
		t.Fatalf("NextChangeAt should be the unlock expiry, got %v", d.NextChangeAt)
	}
}

func TestEvaluate_ExpiredUnlockRelocks(t *testing.T) {
	now := mustParse(t, time.RFC3339, "2026-05-29T14:00:00Z")
	d := Evaluate(State{ReleaseUntil: now.Add(-1 * time.Minute)}, now)
	if !d.Locked {
		t.Fatal("expected locked once ReleaseUntil is in the past")
	}
}

func TestEvaluate_ScheduledWindowActive(t *testing.T) {
	// Friday 02:30 UTC — inside a Friday 02:00-03:00 UTC window.
	now := mustParse(t, time.RFC3339, "2026-05-29T02:30:00Z")
	state := State{
		Schedule: []ScheduleWindow{{
			DaysOfWeek: []int{int(time.Friday)},
			StartTime:  "02:00",
			EndTime:    "03:00",
			Timezone:   "UTC",
		}},
	}
	d := Evaluate(state, now)
	if d.Locked {
		t.Fatal("expected unlocked inside scheduled window")
	}
	wantEnd := mustParse(t, time.RFC3339, "2026-05-29T03:00:00Z")
	if !d.ReleaseUntil.Equal(wantEnd) {
		t.Fatalf("ReleaseUntil = %v, want %v", d.ReleaseUntil, wantEnd)
	}
}

func TestEvaluate_ScheduledWindowInactive_NextStart(t *testing.T) {
	// Friday 01:30 UTC — 30 minutes before a 02:00-03:00 Friday window.
	now := mustParse(t, time.RFC3339, "2026-05-29T01:30:00Z")
	state := State{
		Schedule: []ScheduleWindow{{
			DaysOfWeek: []int{int(time.Friday)},
			StartTime:  "02:00",
			EndTime:    "03:00",
		}},
	}
	d := Evaluate(state, now)
	if !d.Locked {
		t.Fatal("expected locked before window opens")
	}
	wantNext := mustParse(t, time.RFC3339, "2026-05-29T02:00:00Z")
	if !d.NextChangeAt.Equal(wantNext) {
		t.Fatalf("NextChangeAt = %v, want %v", d.NextChangeAt, wantNext)
	}
}

func TestEvaluate_AdHocBeatsSchedule(t *testing.T) {
	// Even when we're inside a scheduled window that ends at 03:00, an
	// ad-hoc unlock pushing release_until to 04:00 keeps the host open
	// until 04:00 — not the earlier of the two.
	now := mustParse(t, time.RFC3339, "2026-05-29T02:30:00Z")
	state := State{
		ReleaseUntil: mustParse(t, time.RFC3339, "2026-05-29T04:00:00Z"),
		Schedule: []ScheduleWindow{{
			DaysOfWeek: []int{int(time.Friday)},
			StartTime:  "02:00",
			EndTime:    "03:00",
		}},
	}
	d := Evaluate(state, now)
	if d.Locked {
		t.Fatal("expected unlocked due to ad-hoc release")
	}
	wantEnd := mustParse(t, time.RFC3339, "2026-05-29T04:00:00Z")
	if !d.ReleaseUntil.Equal(wantEnd) {
		t.Fatalf("ReleaseUntil should reflect ad-hoc release, got %v", d.ReleaseUntil)
	}
}

func TestEvaluate_CrossMidnightWindow(t *testing.T) {
	// Window 22:00 → 02:00 on Friday, evaluated at Saturday 01:30 UTC.
	// The Friday instance hasn't ended yet; host should be unlocked.
	now := mustParse(t, time.RFC3339, "2026-05-30T01:30:00Z")
	state := State{
		Schedule: []ScheduleWindow{{
			DaysOfWeek: []int{int(time.Friday)},
			StartTime:  "22:00",
			EndTime:    "02:00",
		}},
	}
	d := Evaluate(state, now)
	if d.Locked {
		t.Fatal("expected unlocked inside cross-midnight window from Friday")
	}
	wantEnd := mustParse(t, time.RFC3339, "2026-05-30T02:00:00Z")
	if !d.ReleaseUntil.Equal(wantEnd) {
		t.Fatalf("ReleaseUntil = %v, want %v", d.ReleaseUntil, wantEnd)
	}
}

func TestEvaluate_TimezoneAffectsWindow(t *testing.T) {
	// Window: Friday 02:00-03:00 America/New_York. That's 06:00-07:00
	// UTC. Evaluated at 06:30 UTC — should be unlocked because it's
	// inside the NY-local Friday morning maintenance slot.
	now := mustParse(t, time.RFC3339, "2026-05-29T06:30:00Z")
	state := State{
		Schedule: []ScheduleWindow{{
			DaysOfWeek: []int{int(time.Friday)},
			StartTime:  "02:00",
			EndTime:    "03:00",
			Timezone:   "America/New_York",
		}},
	}
	d := Evaluate(state, now)
	if d.Locked {
		t.Fatal("expected unlocked inside NY-local window")
	}
}

func TestEvaluate_DaysOfWeekRespected(t *testing.T) {
	// Window scheduled Mon/Tue/Wed only. Evaluated at Friday 02:30 UTC —
	// should be locked even though the time matches.
	now := mustParse(t, time.RFC3339, "2026-05-29T02:30:00Z") // Friday
	state := State{
		Schedule: []ScheduleWindow{{
			DaysOfWeek: []int{int(time.Monday), int(time.Tuesday), int(time.Wednesday)},
			StartTime:  "02:00",
			EndTime:    "03:00",
		}},
	}
	d := Evaluate(state, now)
	if !d.Locked {
		t.Fatal("expected locked outside Mon/Tue/Wed days")
	}
}

func TestEvaluate_EmptyDaysOfWeekMeansDaily(t *testing.T) {
	// No DaysOfWeek specified → window applies every day.
	now := mustParse(t, time.RFC3339, "2026-05-29T02:30:00Z") // Friday
	state := State{
		Schedule: []ScheduleWindow{{
			StartTime: "02:00",
			EndTime:   "03:00",
		}},
	}
	d := Evaluate(state, now)
	if d.Locked {
		t.Fatal("expected unlocked when DaysOfWeek is empty (daily window)")
	}
}

func TestValidate_GoodSchedule(t *testing.T) {
	s := State{
		Schedule: []ScheduleWindow{
			{StartTime: "00:00", EndTime: "23:59"},
			{StartTime: "02:00", EndTime: "03:00", Timezone: "UTC", DaysOfWeek: []int{0, 6}},
			{StartTime: "22:00", EndTime: "02:00", Timezone: "America/Los_Angeles"},
		},
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestValidate_BadTime(t *testing.T) {
	s := State{Schedule: []ScheduleWindow{{StartTime: "25:00", EndTime: "03:00"}}}
	if err := s.Validate(); err == nil {
		t.Fatal("expected validation error for hour > 23")
	}
}

func TestValidate_BadTimezone(t *testing.T) {
	s := State{Schedule: []ScheduleWindow{{StartTime: "02:00", EndTime: "03:00", Timezone: "Not/A_Real_Zone"}}}
	if err := s.Validate(); err == nil {
		t.Fatal("expected validation error for unknown timezone")
	}
}

func TestValidate_BadDayOfWeek(t *testing.T) {
	s := State{Schedule: []ScheduleWindow{{StartTime: "02:00", EndTime: "03:00", DaysOfWeek: []int{7}}}}
	if err := s.Validate(); err == nil {
		t.Fatal("expected validation error for day_of_week=7")
	}
}

// Package sshlockdown implements the SSH lockdown / maintenance window
// state machine that backs the "Lockdown" tab on the server detail page.
//
// Design (see fleet/docs/features/ssh-lockdown.md):
//
//   - Default posture of a host is UNLOCKED. Locking is opt-in: the
//     operator toggles lock_enabled=true, and only then does enforcement
//     apply — inbound sshd accept() returns -EPERM from the LSM hook (or
//     TC drop on older kernels) outside an active unlock.
//   - While locked, an "unlock" is a timestamp: lockdown.release_until.
//     When now >= release_until the host is locked again; otherwise
//     unlocked. There is no separate "is_unlocked" boolean for the timed
//     path — the timestamp IS the truth, so the LSM hot path can decide
//     with one read of one BPF map cell.
//   - Unlocks come from two sources:
//        1. Ad-hoc UI button → API writes release_until = now + duration.
//        2. Scheduled maintenance windows → the agent computes the next
//           window-end at every tick and sets release_until to it.
//     Both paths share the same field; latest write wins.
//
// This file deliberately holds only pure logic (no clock, no FS, no BPF).
// Tests can drive every transition with a fake `now`. The manager that
// owns persistence, the blocker, and the ticker lives in manager.go.
package sshlockdown

import (
	"errors"
	"sort"
	"time"
)

// State is the single source of truth for whether SSH is currently
// allowed on a host. It's serialised verbatim into:
//   - /var/lib/akagent/lockdown.json (crash persistence)
//   - the alertkick-api security_settings.ssh_lockdown subdocument
//   - the control-plane PUT payload from the UI
//
// A zero-value State means "unlocked, lock posture off" — SSH is open
// until an operator explicitly enables the lock. (Before v2.1 the zero
// value meant locked; the posture flip was a deliberate product change —
// see the API's SSHLockdown model doc.)
type State struct {
	// LockEnabled is the persistent lock posture. False (the default) =
	// SSH is always allowed and the fields below are dormant. True = the
	// host is locked outside an active ad-hoc unlock or scheduled window.
	LockEnabled bool `json:"lock_enabled,omitempty"`

	// ReleaseUntil is the wall-clock instant after which SSH is allowed.
	// Zero = locked (while LockEnabled). Compared against time.Now(), not
	// monotonic time — the agent and the LSM map both need the same
	// answer after a reboot.
	ReleaseUntil time.Time `json:"release_until,omitempty"`

	// AllowedSourceIPs is the permanent bastion allowlist. Entries in
	// this list bypass the block even when ReleaseUntil is zero — those
	// CIDRs are baked into the BPF map's allowlist side, never denied.
	// Reuses AlertPolicy.AllowedSourceIPs from ac-007 so an operator
	// curates one list, not two.
	AllowedSourceIPs []string `json:"allowed_source_ips,omitempty"`

	// Schedule is the optional list of recurring maintenance windows.
	// All entries must have IsAllowed=true (see [Validate]); they're
	// unlock windows, not lock windows. Outside every window the host
	// is locked.
	Schedule []ScheduleWindow `json:"schedule,omitempty"`

	// UpdatedAt is the wall-clock instant this state was last written by
	// the control plane. Used as a tie-break when the agent has a local
	// state from a restart and the API pushes an update — the larger
	// UpdatedAt wins. Also surfaced in the UI audit log.
	UpdatedAt time.Time `json:"updated_at,omitempty"`

	// UpdatedBy is the user who triggered the last change (set by the API
	// from the authenticated request). Plain audit field — never read by
	// the agent's decision logic. Empty for schedule-driven transitions
	// computed locally.
	UpdatedBy string `json:"updated_by,omitempty"`
}

// ScheduleWindow is one recurring slot during which SSH is allowed. The
// shape mirrors models.TimeWindow on the API side so an operator can
// move policies between schedules and SSH lockdown without re-learning
// the field names. IsAllowed is implicit (always true) for lockdown
// schedules; we keep the same struct shape for cross-feature
// consistency but document the constraint here.
type ScheduleWindow struct {
	// DaysOfWeek follows time.Weekday's encoding: 0=Sunday..6=Saturday.
	// Empty = every day.
	DaysOfWeek []int `json:"days_of_week,omitempty"`

	// StartTime / EndTime are wall-clock HH:MM in 24-hour format,
	// interpreted in Timezone. A window crossing midnight (e.g. 22:00
	// → 02:00) is supported — the evaluator treats EndTime < StartTime
	// as "this window wraps to the next day".
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time"`

	// Timezone is an IANA name (e.g. "America/New_York"). Empty defaults
	// to UTC, not the agent's local zone — local zone would silently
	// change behaviour when an operator timezone-hops their laptop while
	// the UI is open.
	Timezone string `json:"timezone,omitempty"`
}

// Decision is the answer the state machine returns. The manager applies
// this to the blocker and persists it; tests read it.
type Decision struct {
	// Locked reports whether SSH is currently denied. Inverse of "is
	// there an active unlock right now".
	Locked bool

	// ReleaseUntil is the timestamp the state machine wants persisted —
	// either copied from input State, or computed from the schedule when
	// the host has just entered a maintenance window. Zero means "no
	// active unlock; the manager should clear the BPF map's unlock cell."
	ReleaseUntil time.Time

	// NextChangeAt is when the manager should re-evaluate. Either the
	// active unlock expiry, or the next schedule transition (start/end),
	// whichever is sooner. Used to pick the ticker interval — the
	// manager wakes up at this exact time instead of polling every
	// second.
	NextChangeAt time.Time
}

// Validate enforces the invariants every State must satisfy before
// being persisted. Returns a joined error so the API can echo every
// problem at once (the UI surfaces them next to the relevant field).
func (s State) Validate() error {
	var errs []error
	for i, w := range s.Schedule {
		if err := w.validate(); err != nil {
			errs = append(errs, &windowError{Index: i, Err: err})
		}
	}
	return joinErrors(errs)
}

// windowError tags a validation error with the schedule index so the
// UI can highlight the offending row.
type windowError struct {
	Index int
	Err   error
}

func (e *windowError) Error() string {
	return "window[" + itoa(e.Index) + "]: " + e.Err.Error()
}
func (e *windowError) Unwrap() error { return e.Err }

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	const digits = "0123456789"
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = digits[i%10]
		i /= 10
	}
	return string(b[pos:])
}

func joinErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	if len(errs) == 1 {
		return errs[0]
	}
	return errors.Join(errs...)
}

func (w ScheduleWindow) validate() error {
	if _, err := parseHHMM(w.StartTime); err != nil {
		return errors.New("invalid start_time " + w.StartTime + " (want HH:MM)")
	}
	if _, err := parseHHMM(w.EndTime); err != nil {
		return errors.New("invalid end_time " + w.EndTime + " (want HH:MM)")
	}
	if w.Timezone != "" {
		if _, err := time.LoadLocation(w.Timezone); err != nil {
			return errors.New("unknown timezone " + w.Timezone)
		}
	}
	for _, d := range w.DaysOfWeek {
		if d < 0 || d > 6 {
			return errors.New("day_of_week out of range; want 0 (Sunday) to 6 (Saturday)")
		}
	}
	return nil
}

// Evaluate runs the state machine for a given moment and returns the
// concrete Decision. The manager calls this on every tick and on every
// command-pushed update. Pure function — no I/O, no clock side effects.
//
// Precedence:
//  0. Lock posture off (the default) → unlocked, nothing else considered.
//  1. An ad-hoc unlock (state.ReleaseUntil) that hasn't expired wins.
//     If the operator clicks "Unlock 30 min" at 14:00, the host stays
//     unlocked until 14:30 regardless of what the schedule says.
//  2. Otherwise, if `now` falls inside any scheduled window, the host
//     is unlocked through that window's end.
//  3. Otherwise locked. NextChangeAt points at the soonest of (unlock
//     expiry, next window start, current window end).
func Evaluate(state State, now time.Time) Decision {
	// 0. Lock posture off → permanently unlocked. Zero ReleaseUntil makes
	// the blocker use its far-future sentinel; zero NextChangeAt lets the
	// ticker idle at MinTickInterval.
	if !state.LockEnabled {
		return Decision{Locked: false, ReleaseUntil: time.Time{}, NextChangeAt: time.Time{}}
	}

	// 1. Ad-hoc unlock active?
	if !state.ReleaseUntil.IsZero() && state.ReleaseUntil.After(now) {
		next := state.ReleaseUntil
		// If a scheduled window starts before the ad-hoc unlock expires,
		// that window doesn't change the lock status — already unlocked —
		// but it might EXTEND past ReleaseUntil and become the next
		// transition. We don't pre-extend here; the ticker picks it up
		// when the ad-hoc unlock expires and re-evaluates.
		return Decision{Locked: false, ReleaseUntil: state.ReleaseUntil, NextChangeAt: next}
	}

	// 2. Scheduled window active?
	if end, ok := activeWindowEnd(state.Schedule, now); ok {
		return Decision{Locked: false, ReleaseUntil: end, NextChangeAt: end}
	}

	// 3. Locked. NextChangeAt = next window start (or zero if none).
	return Decision{Locked: true, ReleaseUntil: time.Time{}, NextChangeAt: nextWindowStart(state.Schedule, now)}
}

// activeWindowEnd returns the end timestamp of the schedule window that
// contains `now`, or (zero, false) when no window contains it.
func activeWindowEnd(schedule []ScheduleWindow, now time.Time) (time.Time, bool) {
	for _, w := range schedule {
		start, end, ok := windowInstanceCovering(w, now)
		if ok {
			return end, true
		}
		_ = start
	}
	return time.Time{}, false
}

// nextWindowStart returns the earliest start instant strictly after
// `now` across every window. Zero when no window is scheduled or every
// window's next instance is unbounded (never expected in practice; the
// generator iterates forward by day for up to 8 days, covering wrap).
func nextWindowStart(schedule []ScheduleWindow, now time.Time) time.Time {
	type cand struct{ t time.Time }
	var candidates []cand
	for _, w := range schedule {
		if s, ok := nextStartAfter(w, now); ok {
			candidates = append(candidates, cand{t: s})
		}
	}
	if len(candidates) == 0 {
		return time.Time{}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].t.Before(candidates[j].t) })
	return candidates[0].t
}

// windowInstanceCovering checks whether the window has an instance
// containing `now`. Cross-midnight windows are handled by also checking
// yesterday's instance: a 22:00→02:00 Tuesday window covers Wednesday
// 01:30 because the Tuesday instance hasn't ended yet.
func windowInstanceCovering(w ScheduleWindow, now time.Time) (time.Time, time.Time, bool) {
	loc := windowLocation(w)
	startMin, _ := parseHHMM(w.StartTime)
	endMin, _ := parseHHMM(w.EndTime)
	wraps := endMin <= startMin

	// Try today and yesterday in the window's timezone.
	nowInTZ := now.In(loc)
	for _, dayOffset := range []int{0, -1} {
		day := nowInTZ.AddDate(0, 0, dayOffset)
		if !dayMatches(w, day.Weekday()) {
			continue
		}
		start := time.Date(day.Year(), day.Month(), day.Day(), startMin/60, startMin%60, 0, 0, loc)
		var end time.Time
		if wraps {
			end = start.Add(time.Duration(24*60-startMin+endMin) * time.Minute)
		} else {
			end = time.Date(day.Year(), day.Month(), day.Day(), endMin/60, endMin%60, 0, 0, loc)
		}
		if (now.Equal(start) || now.After(start)) && now.Before(end) {
			return start, end, true
		}
	}
	return time.Time{}, time.Time{}, false
}

// nextStartAfter walks up to 8 days ahead (covers any weekly recurrence
// plus the wrap case) looking for the first start instant after `now`.
func nextStartAfter(w ScheduleWindow, now time.Time) (time.Time, bool) {
	loc := windowLocation(w)
	startMin, _ := parseHHMM(w.StartTime)
	nowInTZ := now.In(loc)
	for dayOffset := 0; dayOffset < 8; dayOffset++ {
		day := nowInTZ.AddDate(0, 0, dayOffset)
		if !dayMatches(w, day.Weekday()) {
			continue
		}
		start := time.Date(day.Year(), day.Month(), day.Day(), startMin/60, startMin%60, 0, 0, loc)
		if start.After(now) {
			return start, true
		}
	}
	return time.Time{}, false
}

func dayMatches(w ScheduleWindow, day time.Weekday) bool {
	if len(w.DaysOfWeek) == 0 {
		return true
	}
	for _, d := range w.DaysOfWeek {
		if time.Weekday(d) == day {
			return true
		}
	}
	return false
}

func windowLocation(w ScheduleWindow) *time.Location {
	if w.Timezone == "" {
		return time.UTC
	}
	loc, err := time.LoadLocation(w.Timezone)
	if err != nil {
		return time.UTC
	}
	return loc
}

// parseHHMM parses "HH:MM" into total minutes since midnight. Returns
// an error on malformed input — caller decides whether to skip the
// window or surface to the UI.
func parseHHMM(s string) (int, error) {
	if len(s) != 5 || s[2] != ':' {
		return 0, errors.New("not HH:MM")
	}
	h := int(s[0]-'0')*10 + int(s[1]-'0')
	m := int(s[3]-'0')*10 + int(s[4]-'0')
	if h < 0 || h > 23 {
		return 0, errors.New("hour out of range")
	}
	if m < 0 || m > 59 {
		return 0, errors.New("minute out of range")
	}
	return h*60 + m, nil
}

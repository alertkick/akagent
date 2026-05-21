package ebpf

import "testing"

// TestNoiseFilter_DisabledPassesAll — when Enabled is false the filter
// must be a pure passthrough regardless of comm or path.
func TestNoiseFilter_DisabledPassesAll(t *testing.T) {
	f := NewAlertFilter(&AlertFilterConfig{Enabled: false})
	event := &SecurityEvent{
		Process: ProcessInfo{Name: "ls"}, // would normally be excluded
	}
	if !f.ShouldAlert(event) {
		t.Fatal("disabled filter must let all events through")
	}
}

// TestNoiseFilter_DropsExcludedComm — a process name in the configured
// exclusion set should be filtered out at the source.
func TestNoiseFilter_DropsExcludedComm(t *testing.T) {
	lists := DefaultNativeListConfig()
	lists.ExcludeCoreutilsBinaries = true
	f := NewAlertFilterWithLists(&AlertFilterConfig{Enabled: true}, &lists)

	event := &SecurityEvent{Process: ProcessInfo{Name: "ls"}}
	if f.ShouldAlert(event) {
		t.Fatal("coreutils binary should be dropped as noise")
	}
}

// TestNoiseFilter_PassesNonExcludedComm — a process name outside any
// configured exclusion set should pass through to the endpoint.
func TestNoiseFilter_PassesNonExcludedComm(t *testing.T) {
	lists := DefaultNativeListConfig()
	f := NewAlertFilterWithLists(&AlertFilterConfig{Enabled: true}, &lists)

	event := &SecurityEvent{Process: ProcessInfo{Name: "unknown-binary"}}
	if !f.ShouldAlert(event) {
		t.Fatal("unknown binary should not be dropped as noise")
	}
}

// TestNoiseFilter_DropsExcludedPath — a file path under a configured
// safe-prefix should be dropped at the source.
func TestNoiseFilter_DropsExcludedPath(t *testing.T) {
	lists := DefaultNativeListConfig()
	lists.ExcludeSafeEtcDirs = true
	f := NewAlertFilterWithLists(&AlertFilterConfig{Enabled: true}, &lists)

	event := &SecurityEvent{File: FileInfo{Path: "/etc/ssl/certs/ca-bundle.crt"}}
	if f.ShouldAlert(event) {
		t.Fatal("file under SafeEtcDirs prefix should be dropped as noise")
	}
}

// TestNoiseFilter_StatsTracksAllowsAndDrops verifies the statistics
// counters reflect filter decisions.
func TestNoiseFilter_StatsTracksAllowsAndDrops(t *testing.T) {
	lists := DefaultNativeListConfig()
	lists.ExcludeCoreutilsBinaries = true
	f := NewAlertFilterWithLists(&AlertFilterConfig{Enabled: true}, &lists)

	f.ShouldAlert(&SecurityEvent{Process: ProcessInfo{Name: "ls"}})            // drop
	f.ShouldAlert(&SecurityEvent{Process: ProcessInfo{Name: "interesting"}})   // allow
	f.ShouldAlert(&SecurityEvent{Process: ProcessInfo{Name: "also-allowed"}})  // allow

	stats := f.Stats()
	if stats.TotalEvents != 3 {
		t.Fatalf("expected TotalEvents=3, got %d", stats.TotalEvents)
	}
	if stats.DroppedEvents != 1 {
		t.Fatalf("expected DroppedEvents=1, got %d", stats.DroppedEvents)
	}
	if stats.AlertedEvents != 2 {
		t.Fatalf("expected AlertedEvents=2, got %d", stats.AlertedEvents)
	}
}

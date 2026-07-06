//go:build windows

package services

import (
	"strings"
	"testing"
)

// TestGetRunningServicesWindows verifies the SCM enumeration returns real
// services with mapped states. EventLog is always present on Windows.
func TestGetRunningServicesWindows(t *testing.T) {
	svcs, err := GetRunningServices()
	if err != nil {
		t.Fatalf("GetRunningServices: %v", err)
	}
	if len(svcs) == 0 {
		t.Fatal("expected at least one service")
	}

	var foundEventLog, foundActive bool
	for _, s := range svcs {
		if strings.EqualFold(s.Name, "EventLog") {
			foundEventLog = true
		}
		if s.ActiveState == "active" && s.SubState == "running" {
			foundActive = true
		}
		// State mapping must never be empty.
		if s.ActiveState == "" {
			t.Errorf("service %q has empty active_state", s.Name)
		}
	}
	if !foundEventLog {
		t.Error("EventLog service not found in enumeration")
	}
	if !foundActive {
		t.Error("no active/running service found (SCM state mapping suspect)")
	}
}

package bpftc

import (
	"errors"
	"strings"
	"testing"
)

func TestTCCapability_Supported(t *testing.T) {
	if !(Capability{HasSchedCLS: true}).Supported() {
		t.Fatal("expected Supported when SchedCLS true and no error")
	}
}

func TestTCCapability_NotSupportedOnError(t *testing.T) {
	if (Capability{HasSchedCLS: true, Error: errors.New("x")}).Supported() {
		t.Fatal("error should override capability")
	}
}

func TestTCCapability_NotSupportedWhenSchedCLSMissing(t *testing.T) {
	if (Capability{HasSchedCLS: false}).Supported() {
		t.Fatal("SchedCLS missing should not be supported")
	}
}

func TestTCCapability_ReasonNamesMissing(t *testing.T) {
	r := (Capability{HasSchedCLS: false}).Reason()
	if !strings.Contains(strings.ToLower(r), "sched_cls") {
		t.Errorf("Reason() = %q, want substring 'sched_cls'", r)
	}
}

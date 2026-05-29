package bpflsm

import (
	"errors"
	"strings"
	"testing"
)

func TestCapability_Supported_TrueOnlyWhenAllChecksPass(t *testing.T) {
	cap := Capability{HasLSMProgType: true, HasBPFLSMModule: true, LSMList: "lockdown,yama,bpf"}
	if !cap.Supported() {
		t.Fatal("expected Supported when both flags true and no error")
	}
}

func TestCapability_Supported_FalseOnMissingProgType(t *testing.T) {
	cap := Capability{HasLSMProgType: false, HasBPFLSMModule: true}
	if cap.Supported() {
		t.Fatal("expected NOT supported when LSM prog type missing")
	}
}

func TestCapability_Supported_FalseOnMissingBPFLSM(t *testing.T) {
	cap := Capability{HasLSMProgType: true, HasBPFLSMModule: false, LSMList: "lockdown,yama"}
	if cap.Supported() {
		t.Fatal("expected NOT supported when lsm cmdline missing 'bpf'")
	}
}

func TestCapability_Supported_FalseOnError(t *testing.T) {
	cap := Capability{HasLSMProgType: true, HasBPFLSMModule: true, Error: errors.New("probe failed")}
	if cap.Supported() {
		t.Fatal("expected NOT supported when Error is set")
	}
}

func TestCapability_Reason_NamesMissingComponent(t *testing.T) {
	cases := []struct {
		name     string
		cap      Capability
		wantSubs []string
	}{
		{
			name:     "missing prog type",
			cap:      Capability{HasLSMProgType: false, HasBPFLSMModule: true},
			wantSubs: []string{"BPF_PROG_TYPE_LSM", "CONFIG_BPF_LSM"},
		},
		{
			name:     "missing bpf in lsm cmdline",
			cap:      Capability{HasLSMProgType: true, HasBPFLSMModule: false, LSMList: "lockdown,yama"},
			wantSubs: []string{"lsm=", "bpf", "lockdown,yama"},
		},
		{
			name:     "supported",
			cap:      Capability{HasLSMProgType: true, HasBPFLSMModule: true},
			wantSubs: []string{"supported"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.cap.Reason()
			for _, sub := range c.wantSubs {
				if !strings.Contains(strings.ToLower(got), strings.ToLower(sub)) {
					t.Errorf("Reason() = %q, want substring %q", got, sub)
				}
			}
		})
	}
}

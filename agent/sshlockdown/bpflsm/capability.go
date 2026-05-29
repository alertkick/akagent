// Package bpflsm contains the LSM-based SSH lockdown Blocker. Lives in
// its own subpackage so the sshlockdown core stays kernel-free (testable
// without root) and the build doesn't pull in the cilium/ebpf library on
// platforms that won't use it.
package bpflsm

import (
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
)

// Capability is the result of probing the host for LSM-BPF support.
// Three pieces have to line up for an LSM Blocker to load:
//
//  1. Kernel was built with CONFIG_BPF_LSM=y.
//  2. The kernel cmdline includes "bpf" in the lsm= list (so the LSM
//     framework actually exposes BPF as an LSM module).
//  3. The agent has permissions to load BPF programs (CAP_BPF / root).
//
// We expose each piece separately so the operator-facing error message
// can be precise — "kernel has BPF_LSM but lsm=bpf is missing from
// cmdline" is actionable; "LSM not supported" is not.
type Capability struct {
	HasLSMProgType bool   // features.HaveProgramType(LSM) succeeded
	HasBPFLSMModule bool  // /sys/kernel/security/lsm contains "bpf"
	LSMList         string // raw contents of /sys/kernel/security/lsm
	Error           error  // populated when any check fails or the probe
	                       // itself can't run (e.g. /sys not mounted)
}

// Supported reports whether the LSM Blocker can be loaded. Both
// HasLSMProgType and HasBPFLSMModule must be true; Error must be nil.
func (c Capability) Supported() bool {
	return c.Error == nil && c.HasLSMProgType && c.HasBPFLSMModule
}

// Reason returns a human-readable diagnostic for why the LSM Blocker
// is unavailable. Used in the agent status surface and in the API
// response so the UI can tell the operator which fallback is active.
func (c Capability) Reason() string {
	if c.Supported() {
		return "LSM-BPF supported"
	}
	if c.Error != nil {
		return "LSM probe failed: " + c.Error.Error()
	}
	if !c.HasLSMProgType {
		return "kernel does not support BPF_PROG_TYPE_LSM (need CONFIG_BPF_LSM=y, kernel 5.7+)"
	}
	if !c.HasBPFLSMModule {
		return "kernel cmdline does not include lsm=...,bpf (current: " + c.LSMList + ")"
	}
	return "LSM-BPF unsupported"
}

// DetectCapability runs the probe. Cheap — three sysfs reads and a
// feature probe — fine to call once at agent start and again after a
// kernel update notification.
func DetectCapability() Capability {
	var cap Capability

	// (1) Does the kernel know about BPF_PROG_TYPE_LSM at all? This is
	// the cheapest distinguisher; older kernels (< 5.7) return ENOSYS
	// immediately. cilium/ebpf wraps this as a HaveProgramType call.
	if err := features.HaveProgramType(ebpf.LSM); err == nil {
		cap.HasLSMProgType = true
	} else {
		cap.Error = err
		// Don't short-circuit — still read /sys/kernel/security/lsm so
		// the Reason() string is informative.
	}

	// (2) Is BPF actually wired into the LSM stack on this boot? Even
	// a kernel with CONFIG_BPF_LSM=y won't expose LSM hooks unless the
	// cmdline opted in. /sys/kernel/security/lsm is the comma-separated
	// list of active LSM modules; we look for "bpf".
	lsmList, readErr := os.ReadFile("/sys/kernel/security/lsm")
	if readErr == nil {
		cap.LSMList = strings.TrimSpace(string(lsmList))
		for _, mod := range strings.Split(cap.LSMList, ",") {
			if strings.TrimSpace(mod) == "bpf" {
				cap.HasBPFLSMModule = true
				break
			}
		}
	} else if cap.Error == nil {
		// Don't mask an earlier program-type error with the sysfs error.
		cap.Error = readErr
	}

	return cap
}

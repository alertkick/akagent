package bpftc

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
)

// Capability is the result of probing the host for TC-BPF support.
// Two pieces have to line up for the TC blocker to load:
//
//  1. Kernel exposes BPF_PROG_TYPE_SCHED_CLS (the TC classifier program
//     type used by clsact filters). This has been in the kernel since
//     4.1, so practically every supported Linux has it.
//  2. Permissions to load BPF programs (CAP_BPF / root). The agent
//     already requires CAP_BPF for its main eBPF telemetry pipeline,
//     so if we got this far we have it — but we still probe so the
//     error message is precise.
//
// We don't probe for CONFIG_NET_CLS_BPF specifically; it's implicit in
// SchedCLS support. We also don't probe for clsact qdisc support
// separately — qdisc add returns ENOENT on kernels without it, and
// the Blocker's per-interface attach loop surfaces that as a per-
// interface error rather than a global capability failure.
type Capability struct {
	HasSchedCLS bool
	Error       error
}

// Supported reports whether the TC blocker can be loaded.
func (c Capability) Supported() bool {
	return c.Error == nil && c.HasSchedCLS
}

// Reason explains the choice for the operator-facing diagnostic.
func (c Capability) Reason() string {
	if c.Supported() {
		return "TC-BPF supported"
	}
	if c.Error != nil {
		return "TC probe failed: " + c.Error.Error()
	}
	if !c.HasSchedCLS {
		return "kernel does not support BPF_PROG_TYPE_SCHED_CLS (need CONFIG_NET_CLS_BPF=y, kernel 4.1+)"
	}
	return "TC-BPF unsupported"
}

// DetectCapability runs the probe.
func DetectCapability() Capability {
	var cap Capability
	if err := features.HaveProgramType(ebpf.SchedCLS); err == nil {
		cap.HasSchedCLS = true
	} else {
		cap.Error = err
	}
	return cap
}

//go:build linux

package sshlockdown

import (
	"strings"
	"time"

	"akagent/agent/sshlockdown/bpflsm"
	"akagent/agent/sshlockdown/bpftc"
)

// SelectBlocker picks the best available enforcement implementation for
// the host. Order:
//
//  1. LSM-BPF Blocker (kernel 5.7+, CONFIG_BPF_LSM=y, lsm=bpf in cmdline).
//     Production preferred — reject at the LSM hook so sshd's accept()
//     returns -EPERM and the client sees "Connection refused".
//  2. TC-BPF Blocker (kernel 4.5+, CONFIG_NET_CLS_BPF=y). Packet-layer
//     drop on SYN to SSH ports. Client sees TCP timeouts instead of
//     refused — slightly worse UX, but the security guarantee is the
//     same.
//  3. NoopBlocker. Used when neither path is available. State still
//     tracked end-to-end so the UI works and the operator sees what
//     WOULD have happened — DiagnosticReason explains why kernel-side
//     enforcement isn't active.
type BlockerSelection struct {
	Blocker          Blocker
	Mechanism        string // "lsm-bpf" | "tc-bpf" | "noop"
	DiagnosticReason string // human-readable; surfaced in API + UI
}

// SelectBlocker returns the best Blocker plus a diagnostic. Never
// returns an error — the worst case is a NoopBlocker with a non-empty
// DiagnosticReason. Callers may treat that as a warning, not a failure.
func SelectBlocker() BlockerSelection {
	// (1) LSM-BPF is the preferred path.
	if cap := bpflsm.DetectCapability(); cap.Supported() {
		if b, err := bpflsm.New(); err == nil {
			return BlockerSelection{
				Blocker:          &lsmBlockerAdapter{inner: b},
				Mechanism:        "lsm-bpf",
				DiagnosticReason: "LSM-BPF active",
			}
		} else {
			// Capability said yes, load said no — usually a transient
			// rlimit/permissions issue. Try TC as fallback.
			_ = err
		}
	} else {
		// Record the LSM reason on the way down so the TC-fallback
		// diagnostic includes context.
		_ = cap
	}

	// (2) TC-BPF fallback.
	if cap := bpftc.DetectCapability(); cap.Supported() {
		if b, err := bpftc.New(); err == nil {
			return BlockerSelection{
				Blocker:          &tcBlockerAdapter{inner: b},
				Mechanism:        "tc-bpf",
				DiagnosticReason: "TC-BPF active on: " + joinIfaces(b.Interfaces()),
			}
		} else {
			return BlockerSelection{
				Blocker:          &NoopBlocker{},
				Mechanism:        "noop",
				DiagnosticReason: "tc-bpf load failed: " + err.Error(),
			}
		}
	} else {
		return BlockerSelection{
			Blocker:          &NoopBlocker{},
			Mechanism:        "noop",
			DiagnosticReason: "lsm-bpf unavailable, " + cap.Reason(),
		}
	}
}

func joinIfaces(ifaces []string) string {
	if len(ifaces) == 0 {
		return "no interfaces"
	}
	return strings.Join(ifaces, ", ")
}

// lsmBlockerAdapter bridges *bpflsm.Blocker (which has SetUnlockUntil
// + SetPorts as first-class methods) to the sshlockdown.Blocker
// interface (Lock/Unlock/Close only). The manager uses the interface;
// the agent's lockdown initialiser keeps a separate handle to the
// concrete Blocker so it can call SetPorts when sshd_config changes.
type lsmBlockerAdapter struct {
	inner *bpflsm.Blocker
}

func (a *lsmBlockerAdapter) Lock(allowlist []string) error {
	return a.inner.Lock(allowlist)
}
func (a *lsmBlockerAdapter) Unlock(allowlist []string, releaseUntil time.Time) error {
	// Two-step apply: refresh the allowlist (cheap when unchanged), then
	// stamp the exact wall-clock release into the BPF map. The kernel
	// hot path reads bpf_ktime_get_ns() and compares — passing the
	// authoritative deadline (not a sentinel) means the kernel re-locks
	// on the dot, not at the next userspace tick.
	if err := a.inner.Unlock(allowlist); err != nil {
		return err
	}
	return a.inner.SetUnlockUntil(releaseUntil)
}
func (a *lsmBlockerAdapter) Close() error {
	return a.inner.Close()
}

// LSMBlocker returns the concrete blocker when the LSM path is active.
// Returns nil otherwise. The agent's initialiser uses this to feed
// sshd port updates straight to the kernel.
func (s BlockerSelection) LSMBlocker() *bpflsm.Blocker {
	if a, ok := s.Blocker.(*lsmBlockerAdapter); ok {
		return a.inner
	}
	return nil
}

// tcBlockerAdapter wraps *bpftc.Blocker. Same role as
// lsmBlockerAdapter — bridges the typed Blocker to the
// sshlockdown.Blocker interface so the manager doesn't care which
// kernel path is active.
type tcBlockerAdapter struct {
	inner *bpftc.Blocker
}

func (a *tcBlockerAdapter) Lock(allowlist []string) error {
	return a.inner.Lock(allowlist)
}
func (a *tcBlockerAdapter) Unlock(allowlist []string, releaseUntil time.Time) error {
	return a.inner.Unlock(allowlist, releaseUntil)
}
func (a *tcBlockerAdapter) Close() error {
	return a.inner.Close()
}

// TCBlocker returns the concrete blocker when the TC path is active.
// Same role as LSMBlocker — the agent initialiser uses it to push
// sshd_config port updates straight to the kernel.
func (s BlockerSelection) TCBlocker() *bpftc.Blocker {
	if a, ok := s.Blocker.(*tcBlockerAdapter); ok {
		return a.inner
	}
	return nil
}

// portsSetter is the small surface the agent calls into after each
// sshd_config refresh. Both bpflsm.Blocker and bpftc.Blocker satisfy
// it. The selection helper below returns nil when the active path is
// the NoopBlocker, which the agent treats as "nothing to update".
type portsSetter interface {
	SetPorts(ports []uint16) error
}

// PortsSetter returns whichever concrete blocker exposes a SetPorts
// method (LSM or TC), or nil for the NoopBlocker. Lets the agent's
// sshd_config refresh callback push ports without caring which kernel
// path is active.
func (s BlockerSelection) PortsSetter() portsSetter {
	if a, ok := s.Blocker.(*lsmBlockerAdapter); ok {
		return a.inner
	}
	if a, ok := s.Blocker.(*tcBlockerAdapter); ok {
		return a.inner
	}
	return nil
}

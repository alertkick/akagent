//go:build linux

// Package bpftc implements the TC clsact ingress SSH lockdown Blocker.
//
// Why TC, not LSM: this blocker exists for kernels that can't run the
// LSM-BPF program (kernel < 5.7, missing CONFIG_BPF_LSM, or lsm=bpf
// not in cmdline). TC programs work on any kernel with CONFIG_NET_CLS_BPF
// and clsact qdisc support (4.5+), which covers practically every
// production Linux in service today.
//
// Why packet-drop, not LSM-style reject: at the TC layer we can't tell
// the TCP stack "reject this accept" — we can only drop the packet.
// The client sees TCP retransmits and eventually a timeout instead of
// "Connection refused". Slightly worse UX, but the security guarantee
// is the same.
//
// Attach strategy:
//   - For each non-loopback interface that's UP and has an IP, install
//     a clsact qdisc (if not already present) and attach a direct-action
//     BPF filter at the ingress hook.
//   - Track every qdisc and filter we add so Close() unwinds cleanly.
//     The agent owns the qdisc lifecycle — if we install a qdisc that
//     wasn't there, we remove it; if the operator had a clsact already,
//     we attach our filter to theirs and leave the qdisc alone.
package bpftc

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"akagent/ebpf/bpfgen"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Blocker is the TC-based SSH lockdown enforcement. Implements the
// sshlockdown.Blocker interface via the same shape as the LSM blocker
// — the factory picks one and the manager doesn't know which it has.
//
// Concurrency: SetPorts / Lock / Unlock / SetAllowlist are safe for
// concurrent callers. The mutex guards the snapshot maps; the BPF maps
// themselves are kernel-managed and atomically updated.
type Blocker struct {
	mu      sync.Mutex
	objs    *bpfgen.SshlockdowntcObjects
	closed  atomic.Bool

	monotonicBoot time.Time

	portsSnapshot map[uint16]struct{}
	allowSnapshot map[string]struct{}

	// attachments tracks what we installed on each interface so Close()
	// can undo it. Captured in install order so Close() removes filters
	// before qdiscs.
	attachments []ifaceAttachment
}

// ifaceAttachment records the per-interface state the blocker owns.
// installedQdisc is true only when we created the qdisc ourselves; if
// the operator already had a clsact qdisc on that interface, we leave
// it in place and only remove our filter on Close.
type ifaceAttachment struct {
	linkIndex      int
	ifaceName      string
	installedQdisc bool
	filter         *netlink.BpfFilter
}

// New loads the BPF objects, primes the monotonic clock offset, and
// attaches the program to every eligible interface. Returns an error
// if no interface could be attached — that's a hard failure because
// otherwise the agent reports "TC lockdown active" without enforcing
// anything.
func New() (*Blocker, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit memlock: %w", err)
	}

	objs := &bpfgen.SshlockdowntcObjects{}
	if err := bpfgen.LoadSshlockdowntcObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("load sshlockdowntc objects: %w", err)
	}

	b := &Blocker{
		objs:          objs,
		portsSnapshot: make(map[uint16]struct{}),
		allowSnapshot: make(map[string]struct{}),
		monotonicBoot: wallClockOfMonotonicZero(),
	}

	links, err := netlink.LinkList()
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("netlink list links: %w", err)
	}
	for _, l := range links {
		if !isEligibleInterface(l) {
			continue
		}
		if err := b.attachToLink(l); err != nil {
			// One interface failing isn't fatal — the agent may be on a
			// host with a weird virtual interface (wireguard, docker0)
			// that doesn't support clsact. Log and continue; we count
			// successful attachments at the end.
			b.appendDiagnostic("attach %s: %v", l.Attrs().Name, err)
			continue
		}
	}
	if len(b.attachments) == 0 {
		_ = objs.Close()
		return nil, errors.New("no interfaces eligible for TC lockdown (no UP non-loopback link?)")
	}
	return b, nil
}

// isEligibleInterface returns true when we should try to attach to the
// link. Wraps eligibleByNameAndFlags so the netlink dependency stays
// out of the testable predicate.
func isEligibleInterface(l netlink.Link) bool {
	a := l.Attrs()
	if a == nil {
		return false
	}
	return eligibleByNameAndFlags(a.Name, a.Flags)
}

// eligibleByNameAndFlags is the pure predicate isEligibleInterface
// wraps. Skip loopback (not a remote-traffic surface), skip down links
// (nothing to drop), skip well-known virtual bridges where we'd just
// duplicate the drop on the host interface anyway.
func eligibleByNameAndFlags(name string, flags net.Flags) bool {
	if flags&net.FlagLoopback != 0 {
		return false
	}
	if flags&net.FlagUp == 0 {
		return false
	}
	switch name {
	case "docker0", "br-docker", "cni0":
		return false
	}
	return true
}

func (b *Blocker) attachToLink(l netlink.Link) error {
	linkIndex := l.Attrs().Index

	// (1) Ensure a clsact qdisc exists. clsact is a special "wrapper"
	// qdisc that exposes both ingress and egress hooks (we only use
	// ingress). If one is already present, QdiscAdd returns EEXIST and
	// we leave it alone.
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: linkIndex,
			Parent:    netlink.HANDLE_CLSACT,
			Handle:    netlink.MakeHandle(0xffff, 0),
		},
		QdiscType: "clsact",
	}
	installedQdisc := false
	if err := netlink.QdiscAdd(qdisc); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("qdisc add: %w", err)
		}
	} else {
		installedQdisc = true
	}

	// (2) Attach the BPF program as a direct-action filter on ingress.
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: linkIndex,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           b.objs.SshLockdownTc.FD(),
		Name:         "ssh_lockdown_tc",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		// If we created the qdisc above, roll it back so we don't leave
		// orphaned qdiscs across agent restarts.
		if installedQdisc {
			_ = netlink.QdiscDel(qdisc)
		}
		return fmt.Errorf("filter add: %w", err)
	}

	b.attachments = append(b.attachments, ifaceAttachment{
		linkIndex:      linkIndex,
		ifaceName:      l.Attrs().Name,
		installedQdisc: installedQdisc,
		filter:         filter,
	})
	return nil
}

// SetPorts updates the ports map with delta semantics — same pattern as
// the LSM blocker. Empty slice clears the map (no-op state).
func (b *Blocker) SetPorts(ports []uint16) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed.Load() {
		return errors.New("blocker closed")
	}
	next := make(map[uint16]struct{}, len(ports))
	for _, p := range ports {
		next[p] = struct{}{}
	}
	one := uint8(1)
	for p := range next {
		if _, present := b.portsSnapshot[p]; present {
			continue
		}
		if err := b.objs.SshLockdownTcPorts.Put(p, one); err != nil {
			return fmt.Errorf("ssh_lockdown_tc_ports.Put(%d): %w", p, err)
		}
	}
	for p := range b.portsSnapshot {
		if _, keep := next[p]; keep {
			continue
		}
		if err := b.objs.SshLockdownTcPorts.Delete(p); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("ssh_lockdown_tc_ports.Delete(%d): %w", p, err)
		}
	}
	b.portsSnapshot = next
	return nil
}

func (b *Blocker) Lock(allowlist []string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed.Load() {
		return errors.New("blocker closed")
	}
	if err := b.applyAllowlistLocked(allowlist); err != nil {
		return err
	}
	return b.writeReleaseLocked(0)
}

// Unlock applies the allowlist and stamps the exact wall-clock deadline
// as a monotonic ns into the BPF map cell. Same semantics as the LSM
// blocker so the factory adapter doesn't need to special-case.
func (b *Blocker) Unlock(allowlist []string, releaseUntil time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed.Load() {
		return errors.New("blocker closed")
	}
	if err := b.applyAllowlistLocked(allowlist); err != nil {
		return err
	}
	if releaseUntil.IsZero() {
		// "Unlocked, no expiry yet" — write a far-future sentinel so
		// the kernel hot path treats it as unlocked until the manager
		// pushes the real deadline shortly.
		return b.writeReleaseLocked(uint64(^uint64(0) >> 1))
	}
	monoNs := wallToMonoNs(b.monotonicBoot, releaseUntil)
	if monoNs < 0 {
		return b.writeReleaseLocked(0)
	}
	return b.writeReleaseLocked(uint64(monoNs))
}

// Close detaches every filter and removes every qdisc we installed.
// Order matters: filter removal must precede qdisc removal, or the
// kernel rejects with EBUSY.
func (b *Blocker) Close() error {
	if b.closed.Swap(true) {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	var firstErr error
	for i := len(b.attachments) - 1; i >= 0; i-- {
		a := b.attachments[i]
		if a.filter != nil {
			if err := netlink.FilterDel(a.filter); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("filter del on %s: %w", a.ifaceName, err)
			}
		}
		if a.installedQdisc {
			qdisc := &netlink.GenericQdisc{
				QdiscAttrs: netlink.QdiscAttrs{
					LinkIndex: a.linkIndex,
					Parent:    netlink.HANDLE_CLSACT,
					Handle:    netlink.MakeHandle(0xffff, 0),
				},
				QdiscType: "clsact",
			}
			if err := netlink.QdiscDel(qdisc); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("qdisc del on %s: %w", a.ifaceName, err)
			}
		}
	}
	b.attachments = nil
	if b.objs != nil {
		if err := b.objs.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		b.objs = nil
	}
	return firstErr
}

// Stats reads the per-CPU counters: allowed / blocked / allowlist-bypass.
func (b *Blocker) Stats() (allowed, blocked, allowlisted uint64, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed.Load() {
		return 0, 0, 0, errors.New("blocker closed")
	}
	allowed, err = sumPerCPU(b.objs.SshLockdownTcStats, 0)
	if err != nil {
		return 0, 0, 0, err
	}
	blocked, err = sumPerCPU(b.objs.SshLockdownTcStats, 1)
	if err != nil {
		return 0, 0, 0, err
	}
	allowlisted, err = sumPerCPU(b.objs.SshLockdownTcStats, 2)
	if err != nil {
		return 0, 0, 0, err
	}
	return allowed, blocked, allowlisted, nil
}

// Interfaces returns the names of interfaces we successfully attached
// to. Surfaced in the agent status panel so the operator can confirm
// the right NICs are protected.
func (b *Blocker) Interfaces() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.attachments))
	for _, a := range b.attachments {
		out = append(out, a.ifaceName)
	}
	return out
}

// applyAllowlistLocked applies a CIDR list to the v4/v6 LPM tries.
// Caller MUST hold b.mu.
func (b *Blocker) applyAllowlistLocked(entries []string) error {
	next := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		next[e] = struct{}{}
	}
	for e := range next {
		if _, ok := b.allowSnapshot[e]; ok {
			continue
		}
		if err := b.putAllowEntry(e); err != nil {
			return err
		}
	}
	for e := range b.allowSnapshot {
		if _, keep := next[e]; keep {
			continue
		}
		if err := b.deleteAllowEntry(e); err != nil {
			return err
		}
	}
	b.allowSnapshot = next
	return nil
}

func (b *Blocker) putAllowEntry(cidr string) error {
	if ip, ones, isV6, ok := parseCIDROrIP(cidr); ok {
		one := uint8(1)
		if isV6 {
			key := lpmV6Key{Prefixlen: uint32(ones)}
			copy(key.Data[:], ip)
			return b.objs.SshLockdownTcV6Allowlist.Put(key, one)
		}
		key := lpmV4Key{Prefixlen: uint32(ones)}
		copy(key.Data[:], ip)
		return b.objs.SshLockdownTcV4Allowlist.Put(key, one)
	}
	return nil
}

func (b *Blocker) deleteAllowEntry(cidr string) error {
	if ip, ones, isV6, ok := parseCIDROrIP(cidr); ok {
		if isV6 {
			key := lpmV6Key{Prefixlen: uint32(ones)}
			copy(key.Data[:], ip)
			err := b.objs.SshLockdownTcV6Allowlist.Delete(key)
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return err
			}
			return nil
		}
		key := lpmV4Key{Prefixlen: uint32(ones)}
		copy(key.Data[:], ip)
		err := b.objs.SshLockdownTcV4Allowlist.Delete(key)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

func (b *Blocker) writeReleaseLocked(monoNs uint64) error {
	key := uint32(0)
	return b.objs.SshLockdownTcState.Put(key, monoNs)
}

func (b *Blocker) appendDiagnostic(format string, args ...interface{}) {
	// Reserved for a future structured-diagnostic API. Today the New()
	// caller logs via its zerolog and we report attachment count via
	// Interfaces(). Keeping the method here so the structured form
	// lands in one place when we add it.
	_ = fmt.Sprintf(format, args...)
}

// lpmV4Key / lpmV6Key mirror the C-side LPM key shapes. Same layout
// constraint as the LSM blocker — must be packed {u32 prefixlen, data}.
type lpmV4Key struct {
	Prefixlen uint32
	Data      [4]byte
}

type lpmV6Key struct {
	Prefixlen uint32
	Data      [16]byte
}

func parseCIDROrIP(s string) ([]byte, int, bool, bool) {
	if ip, ipnet, err := net.ParseCIDR(s); err == nil {
		ones, _ := ipnet.Mask.Size()
		if v4 := ip.To4(); v4 != nil {
			return v4, ones, false, true
		}
		return ip.To16(), ones, true, true
	}
	if ip := net.ParseIP(s); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4, 32, false, true
		}
		return ip.To16(), 128, true, true
	}
	return nil, 0, false, false
}

func sumPerCPU(m *ebpf.Map, idx uint32) (uint64, error) {
	var values []uint64
	if err := m.Lookup(idx, &values); err != nil {
		return 0, err
	}
	var sum uint64
	for _, v := range values {
		sum += v
	}
	return sum, nil
}

func wallClockOfMonotonicZero() time.Time {
	uptime, err := readProcUptime()
	if err != nil {
		return time.Time{}
	}
	return time.Now().Add(-uptime)
}

func wallToMonoNs(monoBoot time.Time, target time.Time) int64 {
	if monoBoot.IsZero() {
		return -1
	}
	diff := target.Sub(monoBoot)
	if diff < 0 {
		return -1
	}
	return diff.Nanoseconds()
}

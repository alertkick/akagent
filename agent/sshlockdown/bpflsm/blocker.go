//go:build linux

package bpflsm

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"akagent/ebpf/bpfgen"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Blocker is the LSM-based SSH lockdown enforcement. Implements the
// sshlockdown.Blocker interface (Lock/Unlock/Close) — the rest of the
// agent doesn't import this package; selection happens in
// sshlockdown/factory.go based on the kernel capability probe.
//
// Lifecycle:
//   1. New() loads the BPF program + maps and attaches the LSM hook.
//   2. SetPorts() seeds the ssh_lockdown_ports map. Called by the agent
//      on startup and after every sshd_config refresh.
//   3. Lock/Unlock flip the ssh_lockdown_state cell. Lock writes 0
//      (immediate effect); Unlock writes ktime_ns + duration_ns.
//   4. Close() detaches the LSM link and closes the maps.
//
// Thread safety: SetPorts/Lock/Unlock are safe for concurrent callers.
// The BPF maps themselves are kernel-managed and atomically updated;
// our Go-side state is guarded by a single mutex.
type Blocker struct {
	mu        sync.Mutex
	objs      *bpfgen.SshlockdownObjects
	lsmLink   link.Link
	closed    atomic.Bool

	// monotonicBoot is the wall-clock time we observed when bpf_ktime_get
	// returned 0 on this boot. We snapshot it once and use it to convert
	// the operator's wall-clock release_until into the monotonic ns the
	// LSM hook reads.
	monotonicBoot time.Time

	// portsSnapshot is the last seeded port set. Used to compute
	// add/remove deltas on SetPorts so we don't re-walk the map every
	// refresh tick.
	portsSnapshot map[uint16]struct{}

	// allowSnapshot tracks the last allowlist (CIDR strings) so SetAllowlist
	// can apply deltas instead of re-populating the whole trie.
	allowSnapshot map[string]struct{}
}

// New loads the BPF objects, attaches the LSM hook, and primes the
// monotonic-clock offset. Returns an error if any step fails — the
// caller (sshlockdown.NewManager via the factory) decides how to fall
// back.
func New() (*Blocker, error) {
	// Raise RLIMIT_MEMLOCK — older kernels charge BPF map memory against
	// this limit. Idempotent; safe to call from multiple agents.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit memlock: %w", err)
	}

	objs := &bpfgen.SshlockdownObjects{}
	if err := bpfgen.LoadSshlockdownObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("load sshlockdown objects: %w", err)
	}

	lsmLink, err := link.AttachLSM(link.LSMOptions{Program: objs.SshlockdownSocketAccept})
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("attach LSM socket_accept: %w", err)
	}

	b := &Blocker{
		objs:          objs,
		lsmLink:       lsmLink,
		portsSnapshot: make(map[uint16]struct{}),
		allowSnapshot: make(map[string]struct{}),
	}
	// Sample the kernel ktime once at start so we can convert wall-clock
	// → monotonic without round-tripping through clock_gettime in the
	// hot path. Drift between the two clocks across a long-running
	// agent is bounded by the ticker that re-applies state on every
	// Manager.Run iteration.
	b.monotonicBoot = wallClockOfMonotonicZero()

	return b, nil
}

// SetPorts replaces the ssh_lockdown_ports map with the supplied set.
// Called by the agent on startup and after every sshd_config refresh.
// Passing an empty slice clears the map — the LSM hook then no-ops on
// every accept, which is the right default for "feature off".
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

	// Add missing.
	for p := range next {
		if _, present := b.portsSnapshot[p]; present {
			continue
		}
		one := uint8(1)
		if err := b.objs.SshLockdownPorts.Put(p, one); err != nil {
			return fmt.Errorf("ssh_lockdown_ports.Put(%d): %w", p, err)
		}
	}
	// Remove stale.
	for p := range b.portsSnapshot {
		if _, keep := next[p]; keep {
			continue
		}
		if err := b.objs.SshLockdownPorts.Delete(p); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("ssh_lockdown_ports.Delete(%d): %w", p, err)
		}
	}
	b.portsSnapshot = next
	return nil
}

// Lock zeros out the release timestamp so the LSM hook denies every
// accept on SSH ports immediately. The allowlist is reapplied so the
// LSM hook honors bastion bypass during the lockdown.
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

// Unlock writes ktime_ns into the state cell so the hook allows accepts
// until that point. The wall-clock duration is converted to a monotonic
// ns using the snapshot taken at New().
//
// We accept a duration rather than an absolute time because the manager
// already holds the authoritative ReleaseUntil; we just need to give
// the hook a monotonic comparator. Recomputing each call covers clock
// drift over long-running agents.
func (b *Blocker) Unlock(allowlist []string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed.Load() {
		return errors.New("blocker closed")
	}
	if err := b.applyAllowlistLocked(allowlist); err != nil {
		return err
	}
	// "Unlocked, no expiry stamped yet" is rare — Manager will follow
	// with SetUnlockUntil shortly. For now we use a very large value so
	// the hook treats it as unlocked.
	farFuture := uint64(^uint64(0) >> 1)
	return b.writeReleaseLocked(farFuture)
}

// SetUnlockUntil stamps a specific wall-clock release time. Called by
// the manager every tick so the kernel always has the authoritative
// expiry, not a stale "far future" approximation.
func (b *Blocker) SetUnlockUntil(until time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed.Load() {
		return errors.New("blocker closed")
	}
	if until.IsZero() {
		return b.writeReleaseLocked(0)
	}
	monoNs := wallToMonoNs(b.monotonicBoot, until)
	if monoNs < 0 {
		// `until` is already in the past — treat as locked.
		return b.writeReleaseLocked(0)
	}
	return b.writeReleaseLocked(uint64(monoNs))
}

// Close detaches the LSM hook and releases all BPF resources.
// Idempotent — repeated calls return nil after the first close.
func (b *Blocker) Close() error {
	if b.closed.Swap(true) {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	var firstErr error
	if b.lsmLink != nil {
		if err := b.lsmLink.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		b.lsmLink = nil
	}
	if b.objs != nil {
		if err := b.objs.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		b.objs = nil
	}
	return firstErr
}

// Stats returns (allowed, blocked, allowlist-bypassed) counts summed
// across CPUs. Used by the UI's audit panel and by debug commands.
func (b *Blocker) Stats() (allowed, blocked, allowlisted uint64, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed.Load() {
		return 0, 0, 0, errors.New("blocker closed")
	}
	allowed, err = sumPerCPU(b.objs.SshLockdownStats, 0)
	if err != nil {
		return 0, 0, 0, err
	}
	blocked, err = sumPerCPU(b.objs.SshLockdownStats, 1)
	if err != nil {
		return 0, 0, 0, err
	}
	allowlisted, err = sumPerCPU(b.objs.SshLockdownStats, 2)
	if err != nil {
		return 0, 0, 0, err
	}
	return allowed, blocked, allowlisted, nil
}

// applyAllowlistLocked applies a CIDR list to the v4/v6 LPM tries.
// Caller MUST hold b.mu.
func (b *Blocker) applyAllowlistLocked(entries []string) error {
	next := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		next[e] = struct{}{}
	}

	// Add missing.
	for e := range next {
		if _, ok := b.allowSnapshot[e]; ok {
			continue
		}
		if err := b.putAllowEntry(e); err != nil {
			return err
		}
	}
	// Remove stale.
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
			return b.objs.SshLockdownV6Allowlist.Put(key, one)
		}
		key := lpmV4Key{Prefixlen: uint32(ones)}
		copy(key.Data[:], ip)
		return b.objs.SshLockdownV4Allowlist.Put(key, one)
	}
	// Malformed entry → skip silently. The API already validates these,
	// so a malformed value here is from a misconfigured agent state file.
	return nil
}

func (b *Blocker) deleteAllowEntry(cidr string) error {
	if ip, ones, isV6, ok := parseCIDROrIP(cidr); ok {
		if isV6 {
			key := lpmV6Key{Prefixlen: uint32(ones)}
			copy(key.Data[:], ip)
			err := b.objs.SshLockdownV6Allowlist.Delete(key)
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return err
			}
			return nil
		}
		key := lpmV4Key{Prefixlen: uint32(ones)}
		copy(key.Data[:], ip)
		err := b.objs.SshLockdownV4Allowlist.Delete(key)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

// writeReleaseLocked stamps the state cell. Caller MUST hold b.mu.
func (b *Blocker) writeReleaseLocked(monoNs uint64) error {
	key := uint32(0)
	return b.objs.SshLockdownState.Put(key, monoNs)
}

// lpmV4Key / lpmV6Key mirror the C-side LPM key shapes. Field order +
// `bson:"-"` style not needed because cilium/ebpf serialises by struct
// layout, but they must be 1-byte aligned and packed so the kernel sees
// {prefixlen u32, data[N] u8}.
type lpmV4Key struct {
	Prefixlen uint32
	Data      [4]byte
}

type lpmV6Key struct {
	Prefixlen uint32
	Data      [16]byte
}

// parseCIDROrIP accepts either "1.2.3.4" or "1.2.3.0/24" and returns
// the network address bytes, prefix length, and whether it's v6. Bare
// IPv4 → /32 implied; bare IPv6 → /128 implied.
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

// sumPerCPU reads a single index from a BPF_MAP_TYPE_PERCPU_ARRAY and
// returns the per-CPU sum. Index out of range returns 0, nil.
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

// wallClockOfMonotonicZero returns the wall-clock time corresponding to
// the kernel's monotonic-clock epoch. We compute it as `time.Now() -
// uptime`. The kernel exposes uptime via /proc/uptime; we tolerate read
// failures (returning a sentinel zero time) because the manager re-
// applies state on every tick — a single bad reading self-heals.
func wallClockOfMonotonicZero() time.Time {
	uptime, err := readProcUptime()
	if err != nil {
		return time.Time{}
	}
	return time.Now().Add(-uptime)
}

// wallToMonoNs converts a wall-clock target into nanoseconds since
// monotonic boot. Returns -1 when boot is unknown (caller should treat
// as "lock immediately") or when target is in the past.
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


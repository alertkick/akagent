// SPDX-License-Identifier: GPL-2.0 OR MIT
// ssh_lockdown.bpf.c - BPF LSM blocker for SSH lockdown / maintenance window.
//
// Hook:
//   lsm/socket_accept(struct socket *sock, struct socket *newsock, int ret)
//
// When sshd calls accept(), the kernel walks the LSM chain. We return -EPERM
// to make accept() fail; sshd surfaces "Connection refused" to the client.
// The TCP handshake has already completed at this point, but rejecting at
// accept() time keeps the agent's behaviour deterministic: existing
// established sessions are unaffected (they live on already-accepted
// sockets), only new logins fail.
//
// Decision logic:
//   1. If newsock's local port is not in ssh_ports → allow (not SSH).
//   2. If lockdown_state[0] is in the future (now < release_until) → allow.
//   3. If peer IP is in v4_allowlist → allow (bypass for bastion IPs).
//   4. Otherwise deny with -EPERM.
//
// We deliberately reject in this exact order so the cheap port check
// short-circuits the expensive map lookups for the 99% case of non-SSH
// accepts. Without the port gate, every accept on the host would walk
// at least one map.
//
// Build: `make bpf/generate` triggers bpf2go on this file.
// Kernel: requires CONFIG_BPF_LSM=y AND `lsm=...,bpf` in cmdline. The
// userspace loader probes /sys/kernel/security/lsm before attaching;
// kernels without LSM-BPF fall back to the TC packet-drop blocker.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// The project's minimal vmlinux.h doesn't carry the bpf_map_flags enum;
// LPM tries refuse to load without this flag (uapi value 1U << 0).
#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC (1U << 0)
#endif

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Local kernel struct declarations. The project's vmlinux.h is minimal
// and doesn't carry the socket types we need. We declare just the
// fields we touch and rely on BPF CO-RE (the preserve_access_index
// pragma) to relocate them at load time against the host's real BTF.
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)

struct sock_common {
    union {
        struct {
            __be32 skc_daddr;       // peer (remote) IP, network byte order
            __be32 skc_rcv_saddr;   // local (bound) IP, network byte order
        };
    };
    union {
        struct {
            __be16 skc_dport;       // peer port, network byte order
            __u16  skc_num;         // local port, HOST byte order
        };
    };
    unsigned short skc_family;      // AF_INET / AF_INET6
};

struct sock {
    struct sock_common __sk_common;
};

struct socket {
    struct sock *sk;
};

#pragma clang attribute pop

#define AF_INET  2
#define AF_INET6 10

// Lockdown state map. Single-cell array carrying the kernel-monotonic
// nanosecond timestamp `release_until_ns`. The userspace agent writes
// `bpf_ktime_get_ns() + duration_ns` here whenever the operator unlocks
// or a scheduled window opens.
//
// Why monotonic ktime, not wall-clock: BPF programs read ktime cheaply
// (one helper call), wall-clock requires a CO-RE read of the kernel's
// timekeeper which is more expensive. The agent does the wall-clock →
// monotonic conversion once at write time.
//
// Value semantics:
//   0                  → locked (default; same as zero-init)
//   <= now()           → locked (release window expired)
//   >  now()           → unlocked through release_until_ns
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ssh_lockdown_state SEC(".maps");

// SSH ports the host's sshd is listening on, populated from sshd_config
// at agent startup and refreshed on its 5-minute ticker. Hash with
// host-byte-order port as key. Empty map = no SSH ports configured =
// program is a no-op (matches the agent's "if sshdConfig empty, fall
// back to port 22" semantics — userspace inserts 22 in that case).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u16);
    __type(value, __u8);
} ssh_lockdown_ports SEC(".maps");

// IPv4 allowlist. LPM trie so CIDRs (10.0.0.0/24, 192.168.1.5/32, etc.)
// work directly — no per-/32 expansion on the agent side. Key shape is
// the canonical bpf LPM key: {prefixlen, data[4]}.
struct lpm_v4_key {
    __u32 prefixlen;
    __u8  data[4]; // big-endian
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct lpm_v4_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ssh_lockdown_v4_allowlist SEC(".maps");

// IPv6 allowlist — separate trie because LPM tries are size-typed.
// Most operator bastions are v4 in practice; this is here so a v6-only
// bastion isn't silently blocked.
struct lpm_v6_key {
    __u32 prefixlen;
    __u8  data[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct lpm_v6_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ssh_lockdown_v6_allowlist SEC(".maps");

// Per-CPU stats. Lets the agent surface "blocked accepts: 42, allowed:
// 1,103" without pulling per-event tracepoint data. Indices:
//   0 = allowed (not SSH or unlocked or allowlisted)
//   1 = blocked
//   2 = allowed via allowlist (subset of allowed, useful audit signal)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} ssh_lockdown_stats SEC(".maps");

static __always_inline void bump_stat(__u32 idx) {
    __u64 *cnt = bpf_map_lookup_elem(&ssh_lockdown_stats, &idx);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}

// is_unlocked returns 1 when the lockdown is currently lifted, 0 when
// the host is locked. Centralised so a future change (e.g. dead-man
// auto-unlock from the kernel side) lives in one place.
static __always_inline int is_unlocked(void) {
    __u32 k = 0;
    __u64 *release_until_ns = bpf_map_lookup_elem(&ssh_lockdown_state, &k);
    if (!release_until_ns)
        return 0;
    __u64 until = *release_until_ns;
    if (until == 0)
        return 0;
    __u64 now = bpf_ktime_get_ns();
    return now < until;
}

// is_port_ssh returns 1 when the host-byte-order port matches an entry
// in ssh_lockdown_ports. Empty map → 0 → program no-ops (agent ensures
// 22 is present whenever the feature is active).
static __always_inline int is_port_ssh(__u16 port_host) {
    __u8 *v = bpf_map_lookup_elem(&ssh_lockdown_ports, &port_host);
    return v != NULL;
}

// is_v4_allowlisted does an LPM lookup for the given peer address.
// Returns 1 on hit, 0 on miss.
static __always_inline int is_v4_allowlisted(__be32 peer) {
    struct lpm_v4_key key = {};
    key.prefixlen = 32;
    __builtin_memcpy(key.data, &peer, 4);
    __u8 *v = bpf_map_lookup_elem(&ssh_lockdown_v4_allowlist, &key);
    return v != NULL;
}

// Unused until the v6 peer-extraction path lands (see the socket_accept
// comment below); kept so the v6 trie stays exercised by the verifier.
static __always_inline __attribute__((unused)) int is_v6_allowlisted(const __u8 *peer16) {
    struct lpm_v6_key key = {};
    key.prefixlen = 128;
    __builtin_memcpy(key.data, peer16, 16);
    __u8 *v = bpf_map_lookup_elem(&ssh_lockdown_v6_allowlist, &key);
    return v != NULL;
}

// Approximate IPv6 peer extraction. struct sock has skc_v6_daddr as an
// in6_addr, but vmlinux.h doesn't carry it — for v1 we punt on v6 here
// and decide based on family + skc_daddr (always-zero for v6 sockets,
// so v6 traffic currently always blocks if locked & v6 allowlist empty).
// Tracked as a known limitation; see sshlockdown design doc.
SEC("lsm/socket_accept")
int BPF_PROG(sshlockdown_socket_accept,
             struct socket *sock, struct socket *newsock, int ret) {
    // Honor previous LSM denials in the chain.
    if (ret)
        return ret;
    if (!newsock)
        return 0;

    struct sock *sk = BPF_CORE_READ(newsock, sk);
    if (!sk)
        return 0;

    __u16 local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    if (!is_port_ssh(local_port)) {
        bump_stat(0);
        return 0;
    }

    if (is_unlocked()) {
        bump_stat(0);
        return 0;
    }

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family == AF_INET) {
        __be32 peer = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        if (is_v4_allowlisted(peer)) {
            bump_stat(2);
            return 0;
        }
    } else if (family == AF_INET6) {
        // Best-effort v6 — see comment above. Without the v6 peer
        // available via the minimal vmlinux.h, we skip the allowlist
        // check and block. Operators with v6 bastions can shim by
        // running sshd on a v4-only listener until the v6 path lands.
    }

    bump_stat(1);
    return -1; // -EPERM
}

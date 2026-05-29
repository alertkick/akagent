// SPDX-License-Identifier: GPL-2.0 OR MIT
// ssh_lockdown_tc.bpf.c - TC ingress fallback for SSH lockdown.
//
// When the host can't run the LSM blocker (kernel < 5.7, CONFIG_BPF_LSM
// missing, or `lsm=` cmdline doesn't include "bpf"), the agent loads
// this program as a TC clsact ingress filter on each non-loopback
// interface. Decision is identical to the LSM hook, but enforcement is
// at the network layer:
//
//   * LSM rejects with -EPERM → client sees "Connection refused"
//     immediately.
//   * TC drops the SYN → client sees TCP retransmits then a timeout.
//
// Slightly worse UX, but works on any kernel with CONFIG_NET_CLS_BPF
// and clsact qdisc support (4.5+).
//
// Only SYN packets get dropped. The lockdown is for *new logins*; an
// existing SSH session has its packets routed via the established TCP
// flow (no SYN), so we never disturb a live session. The kernel doesn't
// give us an established-connection flag to check, but TCP's SYN flag
// is the canonical "new connection" signal — checking it is both
// necessary and sufficient.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define IPPROTO_TCP 6

// Mirror the LSM blocker's map shapes so the userspace Blocker
// interface can swap implementations without rewriting the map ops.
// These are SEPARATE maps from the LSM ones — TC and LSM programs can
// be loaded together (e.g. testing the fallback while LSM is active)
// without their state stomping on each other.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ssh_lockdown_tc_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u16);
    __type(value, __u8);
} ssh_lockdown_tc_ports SEC(".maps");

struct lpm_v4_key {
    __u32 prefixlen;
    __u8  data[4];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct lpm_v4_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ssh_lockdown_tc_v4_allowlist SEC(".maps");

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
} ssh_lockdown_tc_v6_allowlist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} ssh_lockdown_tc_stats SEC(".maps");

static __always_inline void bump(__u32 idx) {
    __u64 *cnt = bpf_map_lookup_elem(&ssh_lockdown_tc_stats, &idx);
    if (cnt) __sync_fetch_and_add(cnt, 1);
}

// Local Ethernet / IP / TCP headers. vmlinux.h doesn't carry them and
// we don't want to drag in <linux/if_ether.h> for a few bytes of
// layout.
struct ethhdr {
    __u8  h_dest[6];
    __u8  h_source[6];
    __be16 h_proto;
} __attribute__((packed));

struct iphdr_local {
    __u8  ihl_version;     // ihl:4, version:4
    __u8  tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8  ttl;
    __u8  protocol;
    __be16 check;
    __be32 saddr;
    __be32 daddr;
} __attribute__((packed));

struct ipv6hdr_local {
    __u8  ver_class_flow[4];
    __be16 payload_len;
    __u8  nexthdr;
    __u8  hop_limit;
    __u8  saddr[16];
    __u8  daddr[16];
} __attribute__((packed));

struct tcphdr_local {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    // Bytes 12..13 carry data offset (high 4 bits), reserved, and flags.
    // We read the flags byte (offset 13) directly.
    __u8  doff_reserved;
    __u8  flags;
    __be16 window;
    __be16 check;
    __be16 urg_ptr;
} __attribute__((packed));

#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_ACK 0x10

static __always_inline int is_unlocked(void) {
    __u32 k = 0;
    __u64 *until = bpf_map_lookup_elem(&ssh_lockdown_tc_state, &k);
    if (!until || *until == 0) return 0;
    return bpf_ktime_get_ns() < *until;
}

static __always_inline int is_port_ssh(__u16 port_host) {
    __u8 *v = bpf_map_lookup_elem(&ssh_lockdown_tc_ports, &port_host);
    return v != NULL;
}

static __always_inline int is_v4_allow(__be32 src) {
    struct lpm_v4_key key = { .prefixlen = 32 };
    __builtin_memcpy(key.data, &src, 4);
    __u8 *v = bpf_map_lookup_elem(&ssh_lockdown_tc_v4_allowlist, &key);
    return v != NULL;
}

static __always_inline int is_v6_allow(const __u8 *src16) {
    struct lpm_v6_key key = { .prefixlen = 128 };
    __builtin_memcpy(key.data, src16, 16);
    __u8 *v = bpf_map_lookup_elem(&ssh_lockdown_tc_v6_allowlist, &key);
    return v != NULL;
}

// decide returns TC_ACT_OK for an allowed packet, TC_ACT_SHOT to drop.
// Defensive bounds checks at every header read — the verifier rejects
// any program that touches packet bytes without proving they're
// in-bounds.
static __always_inline int decide(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *end  = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end) return TC_ACT_OK;

    __be16 proto = eth->h_proto;
    __u16 proto_h = bpf_ntohs(proto);

    __u16 dport_h = 0;
    __be32 v4_src = 0;
    __u8 v6_src[16];
    int is_v6 = 0;
    __u8 tcp_flags = 0;

    if (proto_h == ETH_P_IP) {
        struct iphdr_local *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > end) return TC_ACT_OK;
        if (iph->protocol != IPPROTO_TCP) return TC_ACT_OK;

        // IHL is in 4-byte words; minimum 5 (20 bytes). Skip option bytes
        // by advancing data pointer the right amount.
        __u8 ihl = iph->ihl_version & 0x0F;
        if (ihl < 5) return TC_ACT_OK;
        __u32 iph_bytes = ihl * 4;

        void *tcp_off = (void *)iph + iph_bytes;
        struct tcphdr_local *tcp = tcp_off;
        if ((void *)(tcp + 1) > end) return TC_ACT_OK;

        dport_h = bpf_ntohs(tcp->dest);
        v4_src = iph->saddr;
        tcp_flags = tcp->flags;
    } else if (proto_h == ETH_P_IPV6) {
        struct ipv6hdr_local *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > end) return TC_ACT_OK;
        if (ip6->nexthdr != IPPROTO_TCP) return TC_ACT_OK;

        struct tcphdr_local *tcp = (void *)(ip6 + 1);
        if ((void *)(tcp + 1) > end) return TC_ACT_OK;

        dport_h = bpf_ntohs(tcp->dest);
        __builtin_memcpy(v6_src, ip6->saddr, 16);
        is_v6 = 1;
        tcp_flags = tcp->flags;
    } else {
        return TC_ACT_OK;
    }

    // Only act on SYN-without-ACK. SYN+ACK is the response to our own
    // outbound connect — never block; pure SYN is "new inbound", which
    // is exactly what the lockdown is meant to stop.
    if ((tcp_flags & TCP_FLAG_SYN) == 0 || (tcp_flags & TCP_FLAG_ACK) != 0) {
        bump(0);
        return TC_ACT_OK;
    }

    if (!is_port_ssh(dport_h)) {
        bump(0);
        return TC_ACT_OK;
    }
    if (is_unlocked()) {
        bump(0);
        return TC_ACT_OK;
    }
    if (is_v6) {
        if (is_v6_allow(v6_src)) {
            bump(2);
            return TC_ACT_OK;
        }
    } else {
        if (is_v4_allow(v4_src)) {
            bump(2);
            return TC_ACT_OK;
        }
    }

    bump(1);
    return TC_ACT_SHOT;
}

// classifier/ingress lets vishvananda/netlink attach this as a clsact
// ingress BPF filter. The section name doesn't matter for direct-action
// attaches, but the convention helps when someone inspects the program
// via `bpftool prog show`.
SEC("classifier/ssh_lockdown_tc")
int ssh_lockdown_tc(struct __sk_buff *skb) {
    return decide(skb);
}

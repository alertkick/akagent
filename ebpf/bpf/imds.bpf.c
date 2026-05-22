// SPDX-License-Identifier: GPL-2.0 OR MIT
// imds.bpf.c - BPF program for detecting cloud IMDS access
// Security: Detects connections to cloud Instance Metadata Service (169.254.169.254)
// Covers AWS, GCP, and Azure IMDS endpoints
//
// IMDS access from compromised processes can lead to:
// - Cloud credential theft (SSRF attacks)
// - Lateral movement via stolen IAM roles
// - Cloud infrastructure reconnaissance

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"
#include "discarders.h"
#include "output.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Force BTF export
struct imds_event *unused_imds_event __attribute__((unused));

DECLARE_EVENT_OUTPUT(imds_events, struct imds_event, 64 * 1024);

// Address family constants
#define AF_INET  2
#define AF_INET6 10

// sockaddr structures
struct imds_sockaddr_in {
    __u16 sin_family;
    __u16 sin_port;
    __u32 sin_addr;
    __u8 pad[8];
};

struct imds_sockaddr_in6 {
    __u16 sin6_family;
    __u16 sin6_port;
    __u32 sin6_flowinfo;
    __u8 sin6_addr[16];
    __u32 sin6_scope_id;
};

// Check if an IPv4 address is the IMDS endpoint (169.254.169.254).
// sin_addr is stored in network byte order (big-endian): bytes a9 fe a9 fe.
static __always_inline int is_imds_ipv4(__u32 sin_addr) {
    __u8 *ip = (__u8 *)&sin_addr;
    return (ip[0] == 169 && ip[1] == 254 && ip[2] == 169 && ip[3] == 254);
}

// Helper to fill common fields
static __always_inline void fill_common_imds(struct imds_event *event) {
    struct task_struct *task;
    u64 pid_tgid, uid_gid;

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_IMDS_ACCESS;

    pid_tgid = bpf_get_current_pid_tgid();
    event->pid = (u32)(pid_tgid >> 32);

    uid_gid = bpf_get_current_uid_gid();
    event->uid = (u32)uid_gid;
    event->gid = (u32)(uid_gid >> 32);

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = NULL;
        bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
        if (parent) {
            bpf_probe_read_kernel(&event->ppid, sizeof(event->ppid), &parent->tgid);
        }
    }
}

// =============================================================================
// Tracepoint: sys_enter_connect
// =============================================================================
// connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
// args: [0]=sockfd, [1]=addr, [2]=addrlen
//
// Detects connections to 169.254.169.254 (the IMDS endpoint used by AWS, GCP,
// and Azure for instance metadata and temporary credential distribution).
//
// Note: This tracepoint fires alongside the network.bpf.c connect hook.
// The kernel supports multiple BPF programs per tracepoint. The IMDS event
// provides a high-priority, dedicated alert separate from general network events.

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    const void *addr = (const void *)ctx->args[1];
    if (!addr)
        return 0;

    // Fast path: read address family first (2 bytes)
    __u16 family = 0;
    if (bpf_probe_read_user(&family, sizeof(family), addr) < 0)
        return 0;

    // Only check IPv4 (IMDS is always on 169.254.169.254 link-local)
    if (family != AF_INET)
        return 0;

    // Read full IPv4 sockaddr
    struct imds_sockaddr_in sa = {};
    if (bpf_probe_read_user(&sa, sizeof(sa), addr) < 0)
        return 0;

    // Check if destination is the IMDS IP
    if (!is_imds_ipv4(sa.sin_addr))
        return 0;

    // This is an IMDS connection - always important
    // Apply discarder check AFTER IMDS IP match (we only want to filter
    // by PID/comm, not by category disable - but we use the standard mechanism)
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_NETWORK, tgid, comm))
        return 0;

    struct imds_event *event = EVENT_OUTPUT_BEGIN(imds_events, struct imds_event);
    if (!event)
        return 0;

    fill_common_imds(event);

    event->family = family;
    event->dport = __builtin_bswap16(sa.sin_port);
    __builtin_memcpy(event->daddr, &sa.sin_addr, 4);

    EVENT_OUTPUT_END(imds_events, event, struct imds_event, ctx);
    return 0;
}

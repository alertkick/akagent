// SPDX-License-Identifier: GPL-2.0 OR MIT
// network.bpf.c - BPF program for tracing network operations
//
// Compiled in two modes:
//   Default:         Standard event output (struct network_event via ring buffer/perf)
//   -DUSE_ENRICHED:  Enriched event output (struct enriched_event with process lineage)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

#ifdef USE_ENRICHED
#include "enriched_helpers.h"
#else
#include "discarders.h"
#include "output.h"
#include "syscall_context.h"
#endif

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Address family constants
#define AF_INET  2
#define AF_INET6 10

// bind() also fires for AF_NETLINK/AF_UNIX control sockets (iptables,
// systemd, ...) and for port 0 (kernel-assigned ephemeral port). Neither
// can be a real listening port, so drop them before touching the ring
// buffer. sin_port/sin6_port both sit right after the 2-byte family field.
static __always_inline int bind_is_inet_service(const void *addr) {
    __u16 family = 0;
    __u16 port = 0;

    if (!addr)
        return 0;
    bpf_probe_read_user(&family, sizeof(family), addr);
    if (family != AF_INET && family != AF_INET6)
        return 0;
    bpf_probe_read_user(&port, sizeof(port), (const char *)addr + 2);
    return port != 0;
}

#ifdef USE_ENRICHED

// sockaddr structures for parsing (enriched-local names to avoid conflicts)
struct sockaddr_in_local {
    __u16 sin_family;
    __u16 sin_port;
    __u32 sin_addr;
    __u8 pad[8];
};

struct sockaddr_in6_local {
    __u16 sin6_family;
    __u16 sin6_port;
    __u32 sin6_flowinfo;
    __u8 sin6_addr[16];
    __u32 sin6_scope_id;
};

// Ring buffer for enriched network events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} network_events_enriched SEC(".maps");

// Force BTF export
struct enriched_event *unused_enriched_network_event __attribute__((unused));

// Initialize enriched event fields for network events
static __always_inline void init_enriched_network_event(struct enriched_event *event) {
    init_enriched_event(event);
    event->network.family = 0;
    event->network.sport = 0;
    event->network.dport = 0;
    event->network.protocol = 0;
    __builtin_memset(event->network.saddr, 0, sizeof(event->network.saddr));
    __builtin_memset(event->network.daddr, 0, sizeof(event->network.daddr));
}

// Helper to parse sockaddr and fill event network fields
static __always_inline void parse_sockaddr_enriched(struct enriched_event *event, const void *addr) {
    __u16 family = 0;

    if (!addr)
        return;

    bpf_probe_read_user(&family, sizeof(family), addr);
    event->network.family = family;

    if (family == AF_INET) {
        struct sockaddr_in_local sa = {};
        bpf_probe_read_user(&sa, sizeof(sa), addr);
        event->network.dport = __builtin_bswap16(sa.sin_port);
        __builtin_memcpy(event->network.daddr, &sa.sin_addr, 4);
    } else if (family == AF_INET6) {
        struct sockaddr_in6_local sa6 = {};
        bpf_probe_read_user(&sa6, sizeof(sa6), addr);
        event->network.dport = __builtin_bswap16(sa6.sin6_port);
        __builtin_memcpy(event->network.daddr, sa6.sin6_addr, 16);
    }
}

#else /* !USE_ENRICHED */

// Force BTF export
struct network_event *unused_network_event __attribute__((unused));

DECLARE_EVENT_OUTPUT(network_events, struct network_event, 256 * 1024);

// Saved context for connect enter/exit correlation
struct connect_ctx {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    __u16 family;
    __u16 dport;
    __u8 daddr[16];
};
DECLARE_SYSCALL_CONTEXT(connect_context, struct connect_ctx, 4096);

// Helper to fill common fields
static __always_inline void fill_common_net(struct network_event *event, __u32 event_type) {
    struct task_struct *task;
    u64 pid_tgid, uid_gid;

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = event_type;

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

// sockaddr structures for parsing
struct sockaddr_in {
    __u16 sin_family;
    __u16 sin_port;
    __u32 sin_addr;
    __u8 pad[8];
};

struct sockaddr_in6 {
    __u16 sin6_family;
    __u16 sin6_port;
    __u32 sin6_flowinfo;
    __u8 sin6_addr[16];
    __u32 sin6_scope_id;
};

// Helper to parse sockaddr and fill event
static __always_inline void parse_sockaddr(struct network_event *event, const void *addr) {
    __u16 family = 0;

    if (!addr)
        return;

    bpf_probe_read_user(&family, sizeof(family), addr);
    event->family = family;

    if (family == AF_INET) {
        struct sockaddr_in sa = {};
        bpf_probe_read_user(&sa, sizeof(sa), addr);
        event->dport = __builtin_bswap16(sa.sin_port);
        __builtin_memcpy(event->daddr, &sa.sin_addr, 4);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 sa6 = {};
        bpf_probe_read_user(&sa6, sizeof(sa6), addr);
        event->dport = __builtin_bswap16(sa6.sin6_port);
        __builtin_memcpy(event->daddr, sa6.sin6_addr, 16);
    }
}

#endif /* USE_ENRICHED */

// =============================================================================
// Tracepoint: sys_enter_connect
// =============================================================================
SEC("tracepoint/syscalls/sys_enter_connect")
#ifdef USE_ENRICHED
int tracepoint__syscalls__sys_enter_connect_enriched(struct trace_event_raw_sys_enter *ctx) {
#else
int tracepoint__syscalls__sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
#endif
    // In-kernel discard check
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);

#ifdef USE_ENRICHED
    struct enriched_event *event = bpf_ringbuf_reserve(&network_events_enriched, sizeof(*event), 0);
    if (!event)
        return 0;

    init_enriched_network_event(event);

    __u64 uid_gid = bpf_get_current_uid_gid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_CONNECT;
    event->pid = tgid;
    event->uid = (__u32)uid_gid;
    event->gid = (__u32)(uid_gid >> 32);

    // args[1] = sockaddr, args[2] = addrlen
    const void *addr = (const void *)ctx->args[1];
    parse_sockaddr_enriched(event, addr);

    fill_process_context(event, tgid);

    bpf_ringbuf_submit(event, 0);
#else
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_NETWORK, tgid, comm))
        return 0;

    // Save context for exit correlation
    struct connect_ctx *saved = SYSCALL_CTX_SAVE(connect_context, struct connect_ctx);
    if (saved) {
        saved->pid = tgid;
        __builtin_memcpy(saved->comm, comm, TASK_COMM_LEN);
        u64 uid_gid = bpf_get_current_uid_gid();
        saved->uid = (u32)uid_gid;
        saved->gid = (u32)(uid_gid >> 32);

        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        if (task) {
            struct task_struct *parent = NULL;
            bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
            if (parent)
                bpf_probe_read_kernel(&saved->ppid, sizeof(saved->ppid), &parent->tgid);
        }
    }

    struct network_event *event = EVENT_OUTPUT_BEGIN(network_events, struct network_event);
    if (!event)
        return 0;

    fill_common_net(event, EVENT_TYPE_CONNECT);

    // args[1] = sockaddr, args[2] = addrlen
    const void *addr = (const void *)ctx->args[1];
    parse_sockaddr(event, addr);

    // Also save parsed addr in context for exit re-emission
    if (saved) {
        saved->family = event->family;
        saved->dport = event->dport;
        __builtin_memcpy(saved->daddr, event->daddr, 16);
    }

    EVENT_OUTPUT_END(network_events, event, struct network_event, ctx);
#endif
    return 0;
}

// =============================================================================
// Tracepoint: sys_exit_connect (standard-only)
// =============================================================================
#ifndef USE_ENRICHED
// sys_exit_connect - capture success vs ECONNREFUSED/ETIMEDOUT
SEC("tracepoint/syscalls/sys_exit_connect")
int tracepoint__syscalls__sys_exit_connect(struct trace_event_raw_sys_exit *ctx) {
    struct connect_ctx *saved = SYSCALL_CTX_LOAD(connect_context, struct connect_ctx);
    if (!saved)
        return 0;

    long ret = ctx->ret;

    // Only emit on error (ECONNREFUSED, ETIMEDOUT, etc.)
    // Successful connects (ret=0) and EINPROGRESS (ret=-115) are normal
    if (ret == 0 || ret == -115)
        return 0;

    struct network_event *event = EVENT_OUTPUT_BEGIN(network_events, struct network_event);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_CONNECT;
    event->pid = saved->pid;
    event->ppid = saved->ppid;
    event->uid = saved->uid;
    event->gid = saved->gid;
    __builtin_memcpy(event->comm, saved->comm, TASK_COMM_LEN);
    event->family = saved->family;
    event->dport = saved->dport;
    __builtin_memcpy(event->daddr, saved->daddr, 16);
    event->ret_code = (__s32)ret;

    EVENT_OUTPUT_END(network_events, event, struct network_event, ctx);
    return 0;
}
#endif /* !USE_ENRICHED */

// =============================================================================
// Tracepoint: sys_enter_accept4
// =============================================================================
SEC("tracepoint/syscalls/sys_enter_accept4")
#ifdef USE_ENRICHED
int tracepoint__syscalls__sys_enter_accept4_enriched(struct trace_event_raw_sys_enter *ctx) {
#else
int tracepoint__syscalls__sys_enter_accept4(struct trace_event_raw_sys_enter *ctx) {
#endif
    // In-kernel discard check
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);

#ifdef USE_ENRICHED
    struct enriched_event *event = bpf_ringbuf_reserve(&network_events_enriched, sizeof(*event), 0);
    if (!event)
        return 0;

    init_enriched_network_event(event);

    __u64 uid_gid = bpf_get_current_uid_gid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_ACCEPT;
    event->pid = tgid;
    event->uid = (__u32)uid_gid;
    event->gid = (__u32)(uid_gid >> 32);

    fill_process_context(event, tgid);

    bpf_ringbuf_submit(event, 0);
#else
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_NETWORK, tgid, comm))
        return 0;

    struct network_event *event = EVENT_OUTPUT_BEGIN(network_events, struct network_event);
    if (!event)
        return 0;

    fill_common_net(event, EVENT_TYPE_ACCEPT);
    // Accept addresses are filled on exit, we just track the attempt here

    EVENT_OUTPUT_END(network_events, event, struct network_event, ctx);
#endif
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_bind
// =============================================================================
SEC("tracepoint/syscalls/sys_enter_bind")
#ifdef USE_ENRICHED
int tracepoint__syscalls__sys_enter_bind_enriched(struct trace_event_raw_sys_enter *ctx) {
#else
int tracepoint__syscalls__sys_enter_bind(struct trace_event_raw_sys_enter *ctx) {
#endif
    // In-kernel discard check
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);

    // args[1] = sockaddr
    const void *addr = (const void *)ctx->args[1];
    if (!bind_is_inet_service(addr))
        return 0;

#ifdef USE_ENRICHED
    struct enriched_event *event = bpf_ringbuf_reserve(&network_events_enriched, sizeof(*event), 0);
    if (!event)
        return 0;

    init_enriched_network_event(event);

    __u64 uid_gid = bpf_get_current_uid_gid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_BIND;
    event->pid = tgid;
    event->uid = (__u32)uid_gid;
    event->gid = (__u32)(uid_gid >> 32);

    parse_sockaddr_enriched(event, addr);

    fill_process_context(event, tgid);

    bpf_ringbuf_submit(event, 0);
#else
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_NETWORK, tgid, comm))
        return 0;

    struct network_event *event = EVENT_OUTPUT_BEGIN(network_events, struct network_event);
    if (!event)
        return 0;

    fill_common_net(event, EVENT_TYPE_BIND);

    parse_sockaddr(event, addr);

    EVENT_OUTPUT_END(network_events, event, struct network_event, ctx);
#endif
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_socket
// =============================================================================
SEC("tracepoint/syscalls/sys_enter_socket")
#ifdef USE_ENRICHED
int tracepoint__syscalls__sys_enter_socket_enriched(struct trace_event_raw_sys_enter *ctx) {
#else
int tracepoint__syscalls__sys_enter_socket(struct trace_event_raw_sys_enter *ctx) {
#endif
    // In-kernel discard check
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);

#ifdef USE_ENRICHED
    struct enriched_event *event = bpf_ringbuf_reserve(&network_events_enriched, sizeof(*event), 0);
    if (!event)
        return 0;

    init_enriched_network_event(event);

    __u64 uid_gid = bpf_get_current_uid_gid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_SOCKET;
    event->pid = tgid;
    event->uid = (__u32)uid_gid;
    event->gid = (__u32)(uid_gid >> 32);

    // args[0] = family, args[1] = type, args[2] = protocol
    event->network.family = (__u16)ctx->args[0];
    event->network.protocol = (__u16)ctx->args[2];

    fill_process_context(event, tgid);

    bpf_ringbuf_submit(event, 0);
#else
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_NETWORK, tgid, comm))
        return 0;

    struct network_event *event = EVENT_OUTPUT_BEGIN(network_events, struct network_event);
    if (!event)
        return 0;

    fill_common_net(event, EVENT_TYPE_SOCKET);

    // args[0] = family, args[1] = type, args[2] = protocol
    event->family = (__u16)ctx->args[0];
    event->protocol = (__u16)ctx->args[2];

    EVENT_OUTPUT_END(network_events, event, struct network_event, ctx);
#endif
    return 0;
}

// SPDX-License-Identifier: GPL-2.0 OR MIT
// network.bpf.c - BPF program for tracing network operations

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Force BTF export
struct network_event *unused_network_event __attribute__((unused));

// Address family constants
#define AF_INET  2
#define AF_INET6 10

// Ring buffer for network events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} network_events SEC(".maps");

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

// Tracepoint for sys_enter_connect
SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    struct network_event *event;
    const void *addr;

    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event)
        return 0;

    fill_common_net(event, EVENT_TYPE_CONNECT);

    // args[1] = sockaddr, args[2] = addrlen
    addr = (const void *)ctx->args[1];
    parse_sockaddr(event, addr);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint for sys_enter_accept4
SEC("tracepoint/syscalls/sys_enter_accept4")
int tracepoint__syscalls__sys_enter_accept4(struct trace_event_raw_sys_enter *ctx) {
    struct network_event *event;

    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event)
        return 0;

    fill_common_net(event, EVENT_TYPE_ACCEPT);
    // Accept addresses are filled on exit, we just track the attempt here

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint for sys_enter_bind
SEC("tracepoint/syscalls/sys_enter_bind")
int tracepoint__syscalls__sys_enter_bind(struct trace_event_raw_sys_enter *ctx) {
    struct network_event *event;
    const void *addr;

    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event)
        return 0;

    fill_common_net(event, EVENT_TYPE_BIND);

    // args[1] = sockaddr
    addr = (const void *)ctx->args[1];
    parse_sockaddr(event, addr);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint for sys_enter_socket
SEC("tracepoint/syscalls/sys_enter_socket")
int tracepoint__syscalls__sys_enter_socket(struct trace_event_raw_sys_enter *ctx) {
    struct network_event *event;

    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event)
        return 0;

    fill_common_net(event, EVENT_TYPE_SOCKET);

    // args[0] = family, args[1] = type, args[2] = protocol
    event->family = (__u16)ctx->args[0];
    event->protocol = (__u16)ctx->args[2];

    bpf_ringbuf_submit(event, 0);
    return 0;
}

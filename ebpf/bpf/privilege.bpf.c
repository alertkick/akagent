// SPDX-License-Identifier: GPL-2.0 OR MIT
// privilege.bpf.c - BPF program for tracing privilege escalation operations
// SOX/PCI Compliance: Tracks setuid, setgid, setreuid, setregid syscalls

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Force BTF export
struct privilege_event *unused_privilege_event __attribute__((unused));

// Ring buffer for privilege events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} privilege_events SEC(".maps");

// Helper to fill common fields
static __always_inline void fill_common_priv(struct privilege_event *event, __u32 event_type) {
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

// Tracepoint for sys_enter_setuid
SEC("tracepoint/syscalls/sys_enter_setuid")
int tracepoint__syscalls__sys_enter_setuid(struct trace_event_raw_sys_enter *ctx) {
    struct privilege_event *event;

    event = bpf_ringbuf_reserve(&privilege_events, sizeof(*event), 0);
    if (!event)
        return 0;

    fill_common_priv(event, EVENT_TYPE_SETUID);

    // args[0] = uid
    event->new_uid = (__u32)ctx->args[0];

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint for sys_enter_setgid
SEC("tracepoint/syscalls/sys_enter_setgid")
int tracepoint__syscalls__sys_enter_setgid(struct trace_event_raw_sys_enter *ctx) {
    struct privilege_event *event;

    event = bpf_ringbuf_reserve(&privilege_events, sizeof(*event), 0);
    if (!event)
        return 0;

    fill_common_priv(event, EVENT_TYPE_SETGID);

    // args[0] = gid
    event->new_gid = (__u32)ctx->args[0];

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint for sys_enter_setreuid
SEC("tracepoint/syscalls/sys_enter_setreuid")
int tracepoint__syscalls__sys_enter_setreuid(struct trace_event_raw_sys_enter *ctx) {
    struct privilege_event *event;

    event = bpf_ringbuf_reserve(&privilege_events, sizeof(*event), 0);
    if (!event)
        return 0;

    fill_common_priv(event, EVENT_TYPE_SETREUID);

    // args[0] = ruid, args[1] = euid
    event->new_uid = (__u32)ctx->args[0];
    event->new_euid = (__u32)ctx->args[1];

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint for sys_enter_setregid
SEC("tracepoint/syscalls/sys_enter_setregid")
int tracepoint__syscalls__sys_enter_setregid(struct trace_event_raw_sys_enter *ctx) {
    struct privilege_event *event;

    event = bpf_ringbuf_reserve(&privilege_events, sizeof(*event), 0);
    if (!event)
        return 0;

    fill_common_priv(event, EVENT_TYPE_SETREGID);

    // args[0] = rgid, args[1] = egid
    event->new_gid = (__u32)ctx->args[0];
    event->new_egid = (__u32)ctx->args[1];

    bpf_ringbuf_submit(event, 0);
    return 0;
}

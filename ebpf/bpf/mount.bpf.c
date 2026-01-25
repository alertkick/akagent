// SPDX-License-Identifier: GPL-2.0 OR MIT
// mount.bpf.c - BPF program for tracing mount operations
// SOX/PCI Compliance: Tracks mount and umount syscalls

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Force BTF export
struct mount_event *unused_mount_event __attribute__((unused));

// Ring buffer for mount events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} mount_events SEC(".maps");

// Helper to fill common fields
static __always_inline void fill_common_mount(struct mount_event *event, __u32 event_type) {
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

// Tracepoint for sys_enter_mount
SEC("tracepoint/syscalls/sys_enter_mount")
int tracepoint__syscalls__sys_enter_mount(struct trace_event_raw_sys_enter *ctx) {
    struct mount_event *event;
    const char *source;
    const char *target;
    const char *fstype;

    event = bpf_ringbuf_reserve(&mount_events, sizeof(*event), 0);
    if (!event)
        return 0;

    fill_common_mount(event, EVENT_TYPE_MOUNT);

    // args[0] = source, args[1] = target, args[2] = filesystemtype, args[3] = mountflags
    source = (const char *)ctx->args[0];
    target = (const char *)ctx->args[1];
    fstype = (const char *)ctx->args[2];

    if (source) {
        bpf_probe_read_user_str(event->source, sizeof(event->source), source);
    }
    if (target) {
        bpf_probe_read_user_str(event->target, sizeof(event->target), target);
    }
    if (fstype) {
        bpf_probe_read_user_str(event->fstype, sizeof(event->fstype), fstype);
    }
    event->flags = ctx->args[3];

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint for sys_enter_umount
SEC("tracepoint/syscalls/sys_enter_umount")
int tracepoint__syscalls__sys_enter_umount(struct trace_event_raw_sys_enter *ctx) {
    struct mount_event *event;
    const char *target;

    event = bpf_ringbuf_reserve(&mount_events, sizeof(*event), 0);
    if (!event)
        return 0;

    fill_common_mount(event, EVENT_TYPE_UMOUNT);

    // args[0] = target, args[1] = flags
    target = (const char *)ctx->args[0];

    if (target) {
        bpf_probe_read_user_str(event->target, sizeof(event->target), target);
    }
    event->flags = ctx->args[1];

    bpf_ringbuf_submit(event, 0);
    return 0;
}

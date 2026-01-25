// SPDX-License-Identifier: GPL-2.0 OR MIT
// fileops.bpf.c - BPF program for tracing file operations

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Force BTF export
struct file_event *unused_file_event __attribute__((unused));

// Ring buffer for file events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} file_events SEC(".maps");

// Helper to fill common fields
static __always_inline void fill_common(struct file_event *event, __u32 event_type) {
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

// Tracepoint for sys_enter_openat
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;
    const char *filename;

    event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_OPEN);

    // args[1] = filename, args[2] = flags
    filename = (const char *)ctx->args[1];
    if (filename) {
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
    }
    event->flags = (s32)ctx->args[2];

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint for sys_enter_unlinkat
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tracepoint__syscalls__sys_enter_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;
    const char *filename;

    event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_UNLINK);

    // args[1] = filename
    filename = (const char *)ctx->args[1];
    if (filename) {
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
    }
    event->flags = (s32)ctx->args[2];

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint for sys_enter_renameat2
SEC("tracepoint/syscalls/sys_enter_renameat2")
int tracepoint__syscalls__sys_enter_renameat2(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;
    const char *oldname;
    const char *newname;

    event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_RENAME);

    // args[1] = oldname, args[3] = newname
    oldname = (const char *)ctx->args[1];
    newname = (const char *)ctx->args[3];

    if (oldname) {
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), oldname);
    }
    if (newname) {
        bpf_probe_read_user_str(event->filename2, sizeof(event->filename2), newname);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint for sys_enter_fchmodat
SEC("tracepoint/syscalls/sys_enter_fchmodat")
int tracepoint__syscalls__sys_enter_fchmodat(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;
    const char *filename;

    event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_CHMOD);

    // args[1] = filename, args[2] = mode
    filename = (const char *)ctx->args[1];
    if (filename) {
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
    }
    event->flags = (s32)ctx->args[2]; // mode

    bpf_ringbuf_submit(event, 0);
    return 0;
}

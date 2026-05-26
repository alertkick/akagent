// SPDX-License-Identifier: GPL-2.0 OR MIT
// dirops.bpf.c - BPF program for directory operation monitoring
// Tracks chdir, fchdir, chroot, and pivot_root syscalls.
// These are security-relevant because they can change the process's
// view of the filesystem, enabling container escapes and sandbox evasion.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"
#include "discarders.h"
#include "output.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Force BTF export
struct dirops_event *unused_dirops_event __attribute__((unused));

DECLARE_EVENT_OUTPUT(dirops_events, struct dirops_event, 128 * 1024);

// Helper to fill common fields
static __always_inline void fill_common_dirops(struct dirops_event *event, __u32 event_type) {
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

// chdir(const char *path)
SEC("tracepoint/syscalls/sys_enter_chdir")
int tracepoint__syscalls__sys_enter_chdir(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    struct dirops_event *event = EVENT_OUTPUT_BEGIN(dirops_events, struct dirops_event);
    if (!event)
        return 0;

    fill_common_dirops(event, EVENT_TYPE_CHDIR);

    const char *path = (const char *)ctx->args[0];
    if (path) {
        bpf_probe_read_user_str(event->path, sizeof(event->path), path);
    }

    EVENT_OUTPUT_END(dirops_events, event, struct dirops_event, ctx);
    return 0;
}

// fchdir(int fd)
SEC("tracepoint/syscalls/sys_enter_fchdir")
int tracepoint__syscalls__sys_enter_fchdir(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    struct dirops_event *event = EVENT_OUTPUT_BEGIN(dirops_events, struct dirops_event);
    if (!event)
        return 0;

    fill_common_dirops(event, EVENT_TYPE_FCHDIR);
    event->fd = (__s32)ctx->args[0];

    EVENT_OUTPUT_END(dirops_events, event, struct dirops_event, ctx);
    return 0;
}

// chroot(const char *path)
SEC("tracepoint/syscalls/sys_enter_chroot")
int tracepoint__syscalls__sys_enter_chroot(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    struct dirops_event *event = EVENT_OUTPUT_BEGIN(dirops_events, struct dirops_event);
    if (!event)
        return 0;

    fill_common_dirops(event, EVENT_TYPE_CHROOT);

    const char *path = (const char *)ctx->args[0];
    if (path) {
        bpf_probe_read_user_str(event->path, sizeof(event->path), path);
    }

    EVENT_OUTPUT_END(dirops_events, event, struct dirops_event, ctx);
    return 0;
}

// pivot_root(const char *new_root, const char *put_old)
SEC("tracepoint/syscalls/sys_enter_pivot_root")
int tracepoint__syscalls__sys_enter_pivot_root(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILESYSTEM, tgid, comm))
        return 0;

    struct dirops_event *event = EVENT_OUTPUT_BEGIN(dirops_events, struct dirops_event);
    if (!event)
        return 0;

    fill_common_dirops(event, EVENT_TYPE_PIVOT_ROOT);

    const char *new_root = (const char *)ctx->args[0];
    const char *put_old = (const char *)ctx->args[1];
    if (new_root) {
        bpf_probe_read_user_str(event->path, sizeof(event->path), new_root);
    }
    if (put_old) {
        bpf_probe_read_user_str(event->path2, sizeof(event->path2), put_old);
    }

    EVENT_OUTPUT_END(dirops_events, event, struct dirops_event, ctx);
    return 0;
}

// SPDX-License-Identifier: GPL-2.0 OR MIT
// mount.bpf.c - BPF program for tracing mount operations
// SOX/PCI Compliance: Tracks mount and umount syscalls
//
// Compiled in two modes:
//   Default:         Standard event output (struct mount_event via ring buffer/perf)
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

#ifdef USE_ENRICHED

// Ring buffer for enriched mount events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} mount_events_enriched SEC(".maps");

// Force BTF export
struct enriched_event *unused_enriched_mount_event __attribute__((unused));

// Initialize enriched event fields for mount events
static __always_inline void init_enriched_mount_event(struct enriched_event *event) {
    init_enriched_event(event);
    event->mount.source[0] = '\0';
    event->mount.target[0] = '\0';
    event->mount.fstype[0] = '\0';
    event->mount.mount_flags = 0;
}

#else /* !USE_ENRICHED */

// Force BTF export
struct mount_event *unused_mount_event __attribute__((unused));

DECLARE_EVENT_OUTPUT(mount_events, struct mount_event, 256 * 1024);

// Saved context for mount enter/exit correlation
struct mount_ctx {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    char source[MAX_FILENAME_LEN];
    char target[MAX_FILENAME_LEN];
    char fstype[32];
    __u64 flags;
};
DECLARE_SYSCALL_CONTEXT(mount_context, struct mount_ctx, 1024);

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

#endif /* USE_ENRICHED */

// =============================================================================
// Tracepoint: sys_enter_mount
// =============================================================================
SEC("tracepoint/syscalls/sys_enter_mount")
#ifdef USE_ENRICHED
int tracepoint__syscalls__sys_enter_mount_enriched(struct trace_event_raw_sys_enter *ctx) {
#else
int tracepoint__syscalls__sys_enter_mount(struct trace_event_raw_sys_enter *ctx) {
#endif
    // In-kernel discard check
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);

#ifdef USE_ENRICHED
    struct enriched_event *event = bpf_ringbuf_reserve(&mount_events_enriched, sizeof(*event), 0);
    if (!event)
        return 0;

    init_enriched_mount_event(event);

    __u64 uid_gid = bpf_get_current_uid_gid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_MOUNT;
    event->pid = tgid;
    event->uid = (__u32)uid_gid;
    event->gid = (__u32)(uid_gid >> 32);

    // args[0] = source, args[1] = target, args[2] = filesystemtype, args[3] = mountflags
    const char *source = (const char *)ctx->args[0];
    const char *target = (const char *)ctx->args[1];
    const char *fstype = (const char *)ctx->args[2];

    if (source)
        bpf_probe_read_user_str(event->mount.source, sizeof(event->mount.source), source);
    if (target)
        bpf_probe_read_user_str(event->mount.target, sizeof(event->mount.target), target);
    if (fstype)
        bpf_probe_read_user_str(event->mount.fstype, sizeof(event->mount.fstype), fstype);
    event->mount.mount_flags = ctx->args[3];

    fill_process_context(event, tgid);

    bpf_ringbuf_submit(event, 0);
#else
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILESYSTEM, tgid, comm))
        return 0;

    struct mount_event *event = EVENT_OUTPUT_BEGIN(mount_events, struct mount_event);
    if (!event)
        return 0;

    fill_common_mount(event, EVENT_TYPE_MOUNT);

    // args[0] = source, args[1] = target, args[2] = filesystemtype, args[3] = mountflags
    const char *source = (const char *)ctx->args[0];
    const char *target = (const char *)ctx->args[1];
    const char *fstype = (const char *)ctx->args[2];

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

    EVENT_OUTPUT_END(mount_events, event, struct mount_event, ctx);
#endif
    return 0;
}

// =============================================================================
// Tracepoint: sys_exit_mount (standard-only)
// =============================================================================
#ifndef USE_ENRICHED
// sys_exit_mount - capture return value
SEC("tracepoint/syscalls/sys_exit_mount")
int tracepoint__syscalls__sys_exit_mount(struct trace_event_raw_sys_exit *ctx) {
    long ret = ctx->ret;
    if (ret == 0)
        return 0;

    // On mount failure, emit event with error code
    struct mount_event *event = EVENT_OUTPUT_BEGIN(mount_events, struct mount_event);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_MOUNT;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = (u32)(pid_tgid >> 32);
    u64 uid_gid = bpf_get_current_uid_gid();
    event->uid = (u32)uid_gid;
    event->gid = (u32)(uid_gid >> 32);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->ret_code = (__s32)ret;

    EVENT_OUTPUT_END(mount_events, event, struct mount_event, ctx);
    return 0;
}
#endif /* !USE_ENRICHED */

// =============================================================================
// Tracepoint: sys_enter_umount
// =============================================================================
SEC("tracepoint/syscalls/sys_enter_umount")
#ifdef USE_ENRICHED
int tracepoint__syscalls__sys_enter_umount_enriched(struct trace_event_raw_sys_enter *ctx) {
#else
int tracepoint__syscalls__sys_enter_umount(struct trace_event_raw_sys_enter *ctx) {
#endif
    // In-kernel discard check
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);

#ifdef USE_ENRICHED
    struct enriched_event *event = bpf_ringbuf_reserve(&mount_events_enriched, sizeof(*event), 0);
    if (!event)
        return 0;

    init_enriched_mount_event(event);

    __u64 uid_gid = bpf_get_current_uid_gid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_UMOUNT;
    event->pid = tgid;
    event->uid = (__u32)uid_gid;
    event->gid = (__u32)(uid_gid >> 32);

    // args[0] = target, args[1] = flags
    const char *target = (const char *)ctx->args[0];
    if (target)
        bpf_probe_read_user_str(event->mount.target, sizeof(event->mount.target), target);
    event->mount.mount_flags = ctx->args[1];

    fill_process_context(event, tgid);

    bpf_ringbuf_submit(event, 0);
#else
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILESYSTEM, tgid, comm))
        return 0;

    struct mount_event *event = EVENT_OUTPUT_BEGIN(mount_events, struct mount_event);
    if (!event)
        return 0;

    fill_common_mount(event, EVENT_TYPE_UMOUNT);

    // args[0] = target, args[1] = flags
    const char *target = (const char *)ctx->args[0];

    if (target) {
        bpf_probe_read_user_str(event->target, sizeof(event->target), target);
    }
    event->flags = ctx->args[1];

    EVENT_OUTPUT_END(mount_events, event, struct mount_event, ctx);
#endif
    return 0;
}

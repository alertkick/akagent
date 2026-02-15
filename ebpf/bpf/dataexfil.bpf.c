// SPDX-License-Identifier: GPL-2.0 OR MIT
// dataexfil.bpf.c - BPF program for data exfiltration detection
// Monitors splice, sendfile, copy_file_range, and tee syscalls
// which can move large amounts of data between fds without userspace copies.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"
#include "discarders.h"
#include "output.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Force BTF export
struct dataexfil_event *unused_dataexfil_event __attribute__((unused));

DECLARE_EVENT_OUTPUT(dataexfil_events, struct dataexfil_event, 128 * 1024);

// Helper to fill common fields
static __always_inline void fill_common_exfil(struct dataexfil_event *event, __u32 event_type) {
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

// splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags)
SEC("tracepoint/syscalls/sys_enter_splice")
int tracepoint__syscalls__sys_enter_splice(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    struct dataexfil_event *event = EVENT_OUTPUT_BEGIN(dataexfil_events, struct dataexfil_event);
    if (!event)
        return 0;

    fill_common_exfil(event, EVENT_TYPE_SPLICE);
    event->fd_in = (__s32)ctx->args[0];
    event->fd_out = (__s32)ctx->args[2];
    event->len = (__u64)ctx->args[4];
    event->flags = (__u32)ctx->args[5];

    EVENT_OUTPUT_END(dataexfil_events, event, struct dataexfil_event, ctx);
    return 0;
}

// sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
SEC("tracepoint/syscalls/sys_enter_sendfile64")
int tracepoint__syscalls__sys_enter_sendfile64(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    struct dataexfil_event *event = EVENT_OUTPUT_BEGIN(dataexfil_events, struct dataexfil_event);
    if (!event)
        return 0;

    fill_common_exfil(event, EVENT_TYPE_SENDFILE);
    event->fd_out = (__s32)ctx->args[0];
    event->fd_in = (__s32)ctx->args[1];
    event->len = (__u64)ctx->args[3];

    EVENT_OUTPUT_END(dataexfil_events, event, struct dataexfil_event, ctx);
    return 0;
}

// copy_file_range(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags)
SEC("tracepoint/syscalls/sys_enter_copy_file_range")
int tracepoint__syscalls__sys_enter_copy_file_range(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    struct dataexfil_event *event = EVENT_OUTPUT_BEGIN(dataexfil_events, struct dataexfil_event);
    if (!event)
        return 0;

    fill_common_exfil(event, EVENT_TYPE_COPY_FILE_RANGE);
    event->fd_in = (__s32)ctx->args[0];
    event->fd_out = (__s32)ctx->args[2];
    event->len = (__u64)ctx->args[4];
    event->flags = (__u32)ctx->args[5];

    EVENT_OUTPUT_END(dataexfil_events, event, struct dataexfil_event, ctx);
    return 0;
}

// tee(int fd_in, int fd_out, size_t len, unsigned int flags)
SEC("tracepoint/syscalls/sys_enter_tee")
int tracepoint__syscalls__sys_enter_tee(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    struct dataexfil_event *event = EVENT_OUTPUT_BEGIN(dataexfil_events, struct dataexfil_event);
    if (!event)
        return 0;

    fill_common_exfil(event, EVENT_TYPE_TEE);
    event->fd_in = (__s32)ctx->args[0];
    event->fd_out = (__s32)ctx->args[1];
    event->len = (__u64)ctx->args[2];
    event->flags = (__u32)ctx->args[3];

    EVENT_OUTPUT_END(dataexfil_events, event, struct dataexfil_event, ctx);
    return 0;
}

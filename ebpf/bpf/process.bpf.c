// SPDX-License-Identifier: GPL-2.0 OR MIT
// process.bpf.c - BPF program for tracing process operations

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"
#include "discarders.h"
#include "output.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Force BTF export
struct process_event *unused_process_event __attribute__((unused));

DECLARE_EVENT_OUTPUT(process_events, struct process_event, 256 * 1024);

// Helper to fill common fields
static __always_inline void fill_common_proc(struct process_event *event, __u32 event_type) {
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

// Tracepoint for sys_enter_clone
SEC("tracepoint/syscalls/sys_enter_clone")
int tracepoint__syscalls__sys_enter_clone(struct trace_event_raw_sys_enter *ctx) {
    struct process_event *event;

    // In-kernel discard check
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_PROCESS, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(process_events, struct process_event);
    if (!event)
        return 0;

    fill_common_proc(event, EVENT_TYPE_CLONE);

    // args[0] = clone_flags
    event->clone_flags = ctx->args[0];

    EVENT_OUTPUT_END(process_events, event, struct process_event, ctx);
    return 0;
}

// Tracepoint for sys_enter_kill
SEC("tracepoint/syscalls/sys_enter_kill")
int tracepoint__syscalls__sys_enter_kill(struct trace_event_raw_sys_enter *ctx) {
    struct process_event *event;

    // In-kernel discard check
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_PROCESS, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(process_events, struct process_event);
    if (!event)
        return 0;

    fill_common_proc(event, EVENT_TYPE_KILL);

    // args[0] = pid, args[1] = sig
    event->target_pid = (__u32)ctx->args[0];
    event->sig = (__s32)ctx->args[1];

    EVENT_OUTPUT_END(process_events, event, struct process_event, ctx);
    return 0;
}

// Tracepoint for sys_enter_ptrace
SEC("tracepoint/syscalls/sys_enter_ptrace")
int tracepoint__syscalls__sys_enter_ptrace(struct trace_event_raw_sys_enter *ctx) {
    struct process_event *event;

    // In-kernel discard check
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_PROCESS, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(process_events, struct process_event);
    if (!event)
        return 0;

    fill_common_proc(event, EVENT_TYPE_PTRACE);

    // args[0] = request, args[1] = pid
    event->ptrace_request = (__s32)ctx->args[0];
    event->target_pid = (__u32)ctx->args[1];

    EVENT_OUTPUT_END(process_events, event, struct process_event, ctx);
    return 0;
}

// Tracepoint for sys_enter_tgkill
// tgkill(int tgid, int tid, int sig) - thread-group directed signal
SEC("tracepoint/syscalls/sys_enter_tgkill")
int tracepoint__syscalls__sys_enter_tgkill(struct trace_event_raw_sys_enter *ctx) {
    struct process_event *event;

    // In-kernel discard check
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_PROCESS, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(process_events, struct process_event);
    if (!event)
        return 0;

    fill_common_proc(event, EVENT_TYPE_TGKILL);

    // args[0] = tgid, args[1] = tid, args[2] = sig
    event->target_pid = (__u32)ctx->args[0];
    event->sig = (__s32)ctx->args[2];

    EVENT_OUTPUT_END(process_events, event, struct process_event, ctx);
    return 0;
}

// Tracepoint for sys_enter_tkill
// tkill(int tid, int sig) - thread-directed signal
SEC("tracepoint/syscalls/sys_enter_tkill")
int tracepoint__syscalls__sys_enter_tkill(struct trace_event_raw_sys_enter *ctx) {
    struct process_event *event;

    // In-kernel discard check
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_PROCESS, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(process_events, struct process_event);
    if (!event)
        return 0;

    fill_common_proc(event, EVENT_TYPE_TKILL);

    // args[0] = tid, args[1] = sig
    event->target_pid = (__u32)ctx->args[0];
    event->sig = (__s32)ctx->args[1];

    EVENT_OUTPUT_END(process_events, event, struct process_event, ctx);
    return 0;
}

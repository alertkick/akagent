// SPDX-License-Identifier: GPL-2.0 OR MIT
// execve.bpf.c - BPF program for tracing process execution (execve syscall)
//
// This program attaches to the sys_enter_execve tracepoint to capture
// process execution events and sends them to userspace via a ring buffer.
//
// Requires: Linux kernel 5.8+ (for ring buffer support)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"
#include "discarders.h"
#include "output.h"
#include "syscall_context.h"

// License declaration required for BPF programs
char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Force BTF export of execve_event struct for bpf2go
struct execve_event *unused_event __attribute__((unused));

DECLARE_EVENT_OUTPUT(events, struct execve_event, 256 * 1024);

// Saved context for execve enter/exit correlation
struct execve_ctx {
    __u8 active;  // 1 if entry was captured
};
DECLARE_SYSCALL_CONTEXT(execve_context, struct execve_ctx, 4096);

// Tracepoint for sys_enter_execve
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    struct execve_event *event;
    struct task_struct *task;
    const char *filename;
    u64 pid_tgid;
    u32 tgid;

    // Get PID and comm early for discard check
    pid_tgid = bpf_get_current_pid_tgid();
    tgid = (u32)(pid_tgid >> 32);

    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    // In-kernel discard check - avoid ring buffer allocation for excluded events
    if (should_discard(DISCARD_CAT_PROCESS, tgid, comm))
        return 0;

    // Reserve space in the ring buffer
    event = EVENT_OUTPUT_BEGIN(events, struct execve_event);
    if (!event) {
        return 0;
    }

    // Initialize the event structure
    __builtin_memset(event, 0, sizeof(*event));

    // Get current timestamp
    event->timestamp_ns = bpf_ktime_get_ns();

    // Use already-obtained PID and comm
    event->pid = tgid;
    __builtin_memcpy(event->comm, comm, TASK_COMM_LEN);

    // Get UID/GID
    u64 uid_gid = bpf_get_current_uid_gid();
    event->uid = (u32)uid_gid;
    event->gid = (u32)(uid_gid >> 32);

    // Get parent PID from task_struct
    task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = NULL;
        bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
        if (parent) {
            bpf_probe_read_kernel(&event->ppid, sizeof(event->ppid), &parent->tgid);
        }
    }

    // Read filename (first argument to execve)
    filename = (const char *)ctx->args[0];
    if (filename) {
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
    }

    // Read first argument (argv[0]) into args field
    // Keep it simple - just read the first arg to avoid verifier complexity
    const char *const *argv = (const char *const *)ctx->args[1];
    if (argv) {
        const char *arg0 = NULL;
        bpf_probe_read_user(&arg0, sizeof(arg0), &argv[0]);
        if (arg0) {
            bpf_probe_read_user_str(event->args, sizeof(event->args), arg0);
            event->args_count = 1;
        }
    }

    event->ret_code = 0;

    // Mark entry for exit correlation
    struct execve_ctx *saved = SYSCALL_CTX_SAVE(execve_context, struct execve_ctx);
    if (saved)
        saved->active = 1;

    // Submit the event to the ring buffer
    EVENT_OUTPUT_END(events, event, struct execve_event, ctx);

    return 0;
}

// sys_exit_execve - emit only on failure (successful execve replaces process)
SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct trace_event_raw_sys_exit *ctx) {
    struct execve_ctx *saved = SYSCALL_CTX_LOAD(execve_context, struct execve_ctx);
    if (!saved || !saved->active)
        return 0;

    long ret = ctx->ret;

    // Only emit on failure - successful execve never reaches sys_exit
    // (the process image is replaced)
    if (ret == 0)
        return 0;

    struct execve_event *event = EVENT_OUTPUT_BEGIN(events, struct execve_event);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();

    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = (u32)(pid_tgid >> 32);

    u64 uid_gid = bpf_get_current_uid_gid();
    event->uid = (u32)uid_gid;
    event->gid = (u32)(uid_gid >> 32);

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->ret_code = (__u32)ret;

    EVENT_OUTPUT_END(events, event, struct execve_event, ctx);
    return 0;
}

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

// License declaration required for BPF programs
char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Force BTF export of execve_event struct for bpf2go
struct execve_event *unused_event __attribute__((unused));

// Ring buffer map for sending events to userspace
// Ring buffers are more efficient than perf buffers for high-throughput scenarios
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB ring buffer
} events SEC(".maps");

// Tracepoint for sys_enter_execve
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    struct execve_event *event;
    struct task_struct *task;
    const char *filename;
    u64 pid_tgid;
    u32 tgid;

    // Reserve space in the ring buffer
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    // Initialize the event structure
    __builtin_memset(event, 0, sizeof(*event));

    // Get current timestamp
    event->timestamp_ns = bpf_ktime_get_ns();

    // Get process IDs
    pid_tgid = bpf_get_current_pid_tgid();
    tgid = (u32)(pid_tgid >> 32);  // Process ID (thread group ID)
    event->pid = tgid;

    // Get UID/GID
    u64 uid_gid = bpf_get_current_uid_gid();
    event->uid = (u32)uid_gid;
    event->gid = (u32)(uid_gid >> 32);

    // Get command name
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

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

    // Submit the event to the ring buffer
    bpf_ringbuf_submit(event, 0);

    return 0;
}

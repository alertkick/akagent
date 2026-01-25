// SPDX-License-Identifier: GPL-2.0 OR MIT
// memory.bpf.c - BPF program for tracing memory protection changes
// Security: Tracks mprotect syscalls, especially PROT_EXEC additions

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Force BTF export
struct memory_event *unused_memory_event __attribute__((unused));

// Protection flags (from mman.h)
#define PROT_EXEC 0x4

// Ring buffer for memory events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} memory_events SEC(".maps");

// Helper to fill common fields
static __always_inline void fill_common_memory(struct memory_event *event, __u32 event_type) {
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

// Tracepoint for sys_enter_mprotect
// Only capture events that add PROT_EXEC to reduce noise
SEC("tracepoint/syscalls/sys_enter_mprotect")
int tracepoint__syscalls__sys_enter_mprotect(struct trace_event_raw_sys_enter *ctx) {
    struct memory_event *event;
    __u32 prot;

    // args[0] = addr, args[1] = len, args[2] = prot
    prot = (__u32)ctx->args[2];

    // Only capture if PROT_EXEC is being added (potential code injection)
    if (!(prot & PROT_EXEC))
        return 0;

    event = bpf_ringbuf_reserve(&memory_events, sizeof(*event), 0);
    if (!event)
        return 0;

    fill_common_memory(event, EVENT_TYPE_MPROTECT);

    event->addr = ctx->args[0];
    event->len = ctx->args[1];
    event->prot = prot;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

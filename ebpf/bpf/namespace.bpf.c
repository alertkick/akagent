// SPDX-License-Identifier: GPL-2.0 OR MIT
// namespace.bpf.c - BPF program for tracing namespace operations
// Security: Tracks setns and unshare syscalls for container breakout detection
//
// setns(fd, nstype) - Switch to an existing namespace (container escape vector)
// unshare(flags)    - Create new namespace (privilege boundary manipulation)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"
#include "discarders.h"
#include "output.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Force BTF export
struct namespace_event *unused_namespace_event __attribute__((unused));

// CLONE_NEW* flags (from linux/sched.h)
#define CLONE_NEWNS     0x00020000  // New mount namespace
#define CLONE_NEWCGROUP 0x02000000  // New cgroup namespace
#define CLONE_NEWUTS    0x04000000  // New UTS namespace (hostname)
#define CLONE_NEWIPC    0x08000000  // New IPC namespace
#define CLONE_NEWUSER   0x10000000  // New user namespace
#define CLONE_NEWPID    0x20000000  // New PID namespace
#define CLONE_NEWNET    0x40000000  // New network namespace
#define CLONE_NEWTIME   0x00000080  // New time namespace

// Bitmask of all CLONE_NEW* flags we care about
#define CLONE_NEW_ANY (CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | \
                       CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWTIME)

DECLARE_EVENT_OUTPUT(namespace_events, struct namespace_event, 256 * 1024);

// Helper to fill common fields
static __always_inline void fill_common_ns(struct namespace_event *event, __u32 event_type) {
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

// =============================================================================
// Tracepoint: sys_enter_setns
// =============================================================================
// setns(int fd, int nstype)
// args: [0]=fd, [1]=nstype
//
// Switching namespaces is a key container escape vector. An attacker who gains
// access to a host namespace fd can use setns() to break out of a container.

SEC("tracepoint/syscalls/sys_enter_setns")
int tracepoint__syscalls__sys_enter_setns(struct trace_event_raw_sys_enter *ctx) {
    struct namespace_event *event;

    // In-kernel discard check
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_NAMESPACE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(namespace_events, struct namespace_event);
    if (!event)
        return 0;

    fill_common_ns(event, EVENT_TYPE_SETNS);

    // args[0] = fd, args[1] = nstype
    event->fd = (__s32)ctx->args[0];
    event->nstype = (__u32)ctx->args[1];

    EVENT_OUTPUT_END(namespace_events, event, struct namespace_event, ctx);
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_unshare
// =============================================================================
// unshare(int flags)
// args: [0]=flags
//
// Only captures unshare calls with CLONE_NEW* flags (namespace creation).
// Plain unshare(CLONE_FILES) etc. are filtered out in-kernel to reduce noise.

SEC("tracepoint/syscalls/sys_enter_unshare")
int tracepoint__syscalls__sys_enter_unshare(struct trace_event_raw_sys_enter *ctx) {
    struct namespace_event *event;
    __u64 flags;

    // args[0] = flags
    flags = ctx->args[0];

    // Only capture if any CLONE_NEW* flag is set (namespace creation)
    if (!(flags & CLONE_NEW_ANY))
        return 0;

    // In-kernel discard check (after flag filter to avoid map lookups for non-namespace unshares)
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_NAMESPACE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(namespace_events, struct namespace_event);
    if (!event)
        return 0;

    fill_common_ns(event, EVENT_TYPE_UNSHARE);

    event->flags = flags;

    EVENT_OUTPUT_END(namespace_events, event, struct namespace_event, ctx);
    return 0;
}

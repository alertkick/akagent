// SPDX-License-Identifier: GPL-2.0 OR MIT
// iouring.bpf.c - BPF program for io_uring monitoring
// Security: Detects io_uring usage which can bypass seccomp filters.
//
// io_uring operations execute in kernel context (not via syscalls), meaning
// seccomp BPF filters that restrict syscalls can be completely bypassed.
// Supported operations include: openat, connect, socket, sendmsg, unlinkat,
// renameat, mkdirat, linkat, bind, and more.
//
// This is a container escape and privilege escalation vector.
// Any io_uring creation on a production server is worth investigating.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"
#include "discarders.h"
#include "output.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Force BTF export
struct iouring_event *unused_iouring_event __attribute__((unused));

DECLARE_EVENT_OUTPUT(iouring_events, struct iouring_event, 64 * 1024);

// io_uring_setup flags (from include/uapi/linux/io_uring.h)
// These are the flags passed in io_uring_params.flags
#define IORING_SETUP_IOPOLL     (1U << 0)   // I/O polling mode
#define IORING_SETUP_SQPOLL     (1U << 1)   // Kernel SQ polling thread (stealthy)
#define IORING_SETUP_SQ_AFF     (1U << 2)   // SQ thread CPU affinity
#define IORING_SETUP_CQSIZE     (1U << 3)   // Custom CQ size
#define IORING_SETUP_CLAMP      (1U << 4)   // Clamp SQ/CQ size
#define IORING_SETUP_ATTACH_WQ  (1U << 5)   // Attach to existing workqueue

// io_uring_params layout:
//   __u32 sq_entries;       offset 0
//   __u32 cq_entries;       offset 4
//   __u32 flags;            offset 8
#define IOURING_PARAMS_FLAGS_OFF 8

// Helper to fill common fields
static __always_inline void fill_common_iouring(struct iouring_event *event) {
    struct task_struct *task;
    u64 pid_tgid, uid_gid;

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp_ns = bpf_ktime_get_ns();

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
// Tracepoint: sys_enter_io_uring_setup
// =============================================================================
// io_uring_setup(unsigned entries, struct io_uring_params *p)
// args: [0]=entries, [1]=params
//
// Detects io_uring instance creation. On most production servers, io_uring
// usage is unusual and warrants investigation. SQPOLL mode is particularly
// suspicious as it creates a kernel polling thread that can execute
// operations without any further syscalls from the process.

SEC("tracepoint/syscalls/sys_enter_io_uring_setup")
int tracepoint__syscalls__sys_enter_io_uring_setup(struct trace_event_raw_sys_enter *ctx) {
    // Apply discarder filtering
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_KERNEL, tgid, comm))
        return 0;

    struct iouring_event *event = EVENT_OUTPUT_BEGIN(iouring_events, struct iouring_event);
    if (!event)
        return 0;

    fill_common_iouring(event);
    event->event_type = EVENT_TYPE_IO_URING_SETUP;

    // Read entries count
    event->sq_entries = (__u32)ctx->args[0];

    // Read flags from io_uring_params struct (user pointer)
    const void *params = (const void *)ctx->args[1];
    if (params) {
        bpf_probe_read_user(&event->setup_flags, sizeof(event->setup_flags),
                            params + IOURING_PARAMS_FLAGS_OFF);
    }

    event->fd = -1;  // Not yet assigned

    EVENT_OUTPUT_END(iouring_events, event, struct iouring_event, ctx);
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_io_uring_register
// =============================================================================
// io_uring_register(unsigned int fd, unsigned int opcode,
//                   void *arg, unsigned int nr_args)
// args: [0]=fd, [1]=opcode, [2]=arg, [3]=nr_args
//
// Detects resource registration with io_uring. Key opcodes include:
// - IORING_REGISTER_FILES (2): Register fixed file descriptors
// - IORING_REGISTER_BUFFERS (0): Register fixed buffers
// - IORING_REGISTER_EVENTFD (4): Register eventfd for notifications
// - IORING_REGISTER_PROBE (8): Probe supported operations

SEC("tracepoint/syscalls/sys_enter_io_uring_register")
int tracepoint__syscalls__sys_enter_io_uring_register(struct trace_event_raw_sys_enter *ctx) {
    // Apply discarder filtering
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_KERNEL, tgid, comm))
        return 0;

    struct iouring_event *event = EVENT_OUTPUT_BEGIN(iouring_events, struct iouring_event);
    if (!event)
        return 0;

    fill_common_iouring(event);
    event->event_type = EVENT_TYPE_IO_URING_REGISTER;

    event->fd = (__s32)ctx->args[0];
    event->opcode = (__u32)ctx->args[1];
    event->nr_args = (__u32)ctx->args[3];

    EVENT_OUTPUT_END(iouring_events, event, struct iouring_event, ctx);
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_io_uring_enter
// =============================================================================
// io_uring_enter(unsigned int fd, unsigned int to_submit,
//                unsigned int min_complete, unsigned int flags,
//                const void *argp, size_t argsz)
// args: [0]=fd, [1]=to_submit, [2]=min_complete, [3]=flags

SEC("tracepoint/syscalls/sys_enter_io_uring_enter")
int tracepoint__syscalls__sys_enter_io_uring_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_KERNEL, tgid, comm))
        return 0;

    struct iouring_event *event = EVENT_OUTPUT_BEGIN(iouring_events, struct iouring_event);
    if (!event)
        return 0;

    fill_common_iouring(event);
    event->event_type = EVENT_TYPE_IO_URING_ENTER;

    event->fd = (__s32)ctx->args[0];
    event->sq_entries = (__u32)ctx->args[1];  // to_submit
    event->setup_flags = (__u32)ctx->args[3]; // flags

    EVENT_OUTPUT_END(iouring_events, event, struct iouring_event, ctx);
    return 0;
}

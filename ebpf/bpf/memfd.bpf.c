// SPDX-License-Identifier: GPL-2.0 OR MIT
// memfd.bpf.c - BPF program for fileless malware execution detection
// Security: Detects memfd_create (memory-backed anonymous files) and
// execveat (execute from fd) which are the primary fileless malware vectors.
//
// Attack chain:
//   1. memfd_create("", MFD_CLOEXEC) → creates anonymous in-memory file
//   2. write(fd, payload, ...) → writes executable to memory
//   3. execveat(fd, "", ..., AT_EMPTY_PATH) → executes from memory
// No file ever touches disk, bypassing file-based detection.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"
#include "discarders.h"
#include "output.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Force BTF export
struct memfd_event *unused_memfd_event __attribute__((unused));

DECLARE_EVENT_OUTPUT(memfd_events, struct memfd_event, 64 * 1024);

// memfd_create flags (from include/uapi/linux/memfd.h)
#define MFD_CLOEXEC         0x0001U
#define MFD_ALLOW_SEALING   0x0002U
#define MFD_HUGETLB         0x0004U
#define MFD_NOEXEC_SEAL     0x0008U
#define MFD_EXEC            0x0010U

// execveat flags
#define AT_EMPTY_PATH       0x1000

// Helper to fill common fields
static __always_inline void fill_common_memfd(struct memfd_event *event) {
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
// Tracepoint: sys_enter_memfd_create
// =============================================================================
// memfd_create(const char *name, unsigned int flags)
// args: [0]=name, [1]=flags
//
// memfd_create creates an anonymous memory-backed file. While legitimate uses
// exist (JIT compilation, shared memory), it's the primary setup for fileless
// malware execution. All calls are captured since memfd_create is uncommon
// in normal workloads.

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int tracepoint__syscalls__sys_enter_memfd_create(struct trace_event_raw_sys_enter *ctx) {
    // Apply discarder filtering
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_PROCESS, tgid, comm))
        return 0;

    struct memfd_event *event = EVENT_OUTPUT_BEGIN(memfd_events, struct memfd_event);
    if (!event)
        return 0;

    fill_common_memfd(event);
    event->event_type = EVENT_TYPE_MEMFD_CREATE;
    event->fd = -1;  // Not yet assigned (returned on syscall exit)

    // Read flags
    event->flags = (__u32)ctx->args[1];

    // Read the name argument (user pointer)
    const char *name_ptr = (const char *)ctx->args[0];
    if (name_ptr) {
        bpf_probe_read_user_str(event->name, sizeof(event->name), name_ptr);
    }

    EVENT_OUTPUT_END(memfd_events, event, struct memfd_event, ctx);
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_execveat
// =============================================================================
// execveat(int dirfd, const char *pathname, const char *const argv[],
//          const char *const envp[], int flags)
// args: [0]=dirfd, [1]=pathname, [2]=argv, [3]=envp, [4]=flags
//
// execveat with AT_EMPTY_PATH flag executes the file referenced by the fd
// directly, without needing a filesystem path. Combined with memfd_create,
// this enables completely fileless execution where no binary touches disk.
//
// AT_EMPTY_PATH + dirfd pointing to memfd = fileless malware execution.
// Even without AT_EMPTY_PATH, execveat from unusual fds is suspicious.

SEC("tracepoint/syscalls/sys_enter_execveat")
int tracepoint__syscalls__sys_enter_execveat(struct trace_event_raw_sys_enter *ctx) {
    // Apply discarder filtering
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_PROCESS, tgid, comm))
        return 0;

    struct memfd_event *event = EVENT_OUTPUT_BEGIN(memfd_events, struct memfd_event);
    if (!event)
        return 0;

    fill_common_memfd(event);
    event->event_type = EVENT_TYPE_EXECVEAT;

    // Read dirfd
    event->fd = (__s32)ctx->args[0];

    // Read flags
    event->flags = (__u32)ctx->args[4];

    // Read pathname (user pointer) - may be empty for AT_EMPTY_PATH
    const char *pathname_ptr = (const char *)ctx->args[1];
    if (pathname_ptr) {
        bpf_probe_read_user_str(event->name, sizeof(event->name), pathname_ptr);
    }

    EVENT_OUTPUT_END(memfd_events, event, struct memfd_event, ctx);
    return 0;
}

// sys_exit_memfd_create - capture returned fd
SEC("tracepoint/syscalls/sys_exit_memfd_create")
int tracepoint__syscalls__sys_exit_memfd_create(struct trace_event_raw_sys_exit *ctx) {
    long ret = ctx->ret;
    // Only emit on failure
    if (ret >= 0)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_PROCESS, tgid, comm))
        return 0;

    struct memfd_event *event = EVENT_OUTPUT_BEGIN(memfd_events, struct memfd_event);
    if (!event)
        return 0;

    fill_common_memfd(event);
    event->event_type = EVENT_TYPE_MEMFD_CREATE;
    event->fd = (__s32)ret;

    EVENT_OUTPUT_END(memfd_events, event, struct memfd_event, ctx);
    return 0;
}

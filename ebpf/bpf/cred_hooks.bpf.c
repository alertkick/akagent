// SPDX-License-Identifier: GPL-2.0 OR MIT
// cred_hooks.bpf.c - BPF kprobe programs for credential and process lifecycle monitoring
//
// Hooks:
//   - commit_creds: All credential changes (setuid, setgid, setgroups, capabilities)
//     go through this single kernel function. This is more comprehensive than
//     tracing individual set*id syscalls because it catches credential changes
//     from any source (syscalls, kernel-internal, namespaces).
//
//   - do_exit: Process exit with exit code. Useful for detecting:
//     - Crash signals (SIGSEGV=11, SIGABRT=6, SIGKILL=9)
//     - Abnormal exit codes
//     - Correlating process lifetime with other events

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"
#include "discarders.h"
#include "output.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Force BTF export
struct cred_event *unused_cred_event __attribute__((unused));

DECLARE_EVENT_OUTPUT(cred_events, struct cred_event, 128 * 1024);

// Helper to fill common fields
static __always_inline void fill_common_cred(struct cred_event *event, __u32 event_type) {
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
// kprobe: commit_creds
// =============================================================================
// int commit_creds(struct cred *new)
//
// Called when a process applies new credentials. The 'new' argument contains
// the credentials about to be installed. We compare with current creds
// to detect privilege changes.

SEC("kprobe/commit_creds")
int BPF_KPROBE(kprobe_commit_creds, struct cred *new_cred) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_PRIVILEGE, tgid, comm))
        return 0;

    if (!new_cred)
        return 0;

    // Read the new credentials being applied
    __u32 new_uid = BPF_CORE_READ(new_cred, uid);
    __u32 new_euid = BPF_CORE_READ(new_cred, euid);
    __u32 new_gid = BPF_CORE_READ(new_cred, gid);
    __u32 new_egid = BPF_CORE_READ(new_cred, egid);

    // Read current credentials for comparison
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    const struct cred *old_cred = BPF_CORE_READ(task, real_cred);
    if (!old_cred)
        return 0;

    __u32 old_uid = BPF_CORE_READ(old_cred, uid);
    __u32 old_euid = BPF_CORE_READ(old_cred, euid);
    __u32 old_gid = BPF_CORE_READ(old_cred, gid);
    __u32 old_egid = BPF_CORE_READ(old_cred, egid);

    // Only emit event if credentials actually changed
    if (new_uid == old_uid && new_euid == old_euid &&
        new_gid == old_gid && new_egid == old_egid)
        return 0;

    struct cred_event *event = EVENT_OUTPUT_BEGIN(cred_events, struct cred_event);
    if (!event)
        return 0;

    fill_common_cred(event, EVENT_TYPE_COMMIT_CREDS);

    event->new_uid = new_uid;
    event->new_euid = new_euid;
    event->new_gid = new_gid;
    event->new_egid = new_egid;

    EVENT_OUTPUT_END(cred_events, event, struct cred_event, ctx);
    return 0;
}

// =============================================================================
// kprobe: do_exit
// =============================================================================
// void __noreturn do_exit(long code)
//
// Called when a process is exiting. The code parameter contains the exit
// status: bits 0-7 are the signal number (if killed by signal), bits 8-15
// are the exit code (if exited normally via exit() or return from main).

SEC("kprobe/do_exit")
int BPF_KPROBE(kprobe_do_exit, long code) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_PROCESS, tgid, comm))
        return 0;

    // Only emit for thread group leaders (avoid noise from thread exits)
    u32 tid = (u32)pid_tgid;
    if (tid != tgid)
        return 0;

    struct cred_event *event = EVENT_OUTPUT_BEGIN(cred_events, struct cred_event);
    if (!event)
        return 0;

    fill_common_cred(event, EVENT_TYPE_PROCESS_EXIT);
    event->exit_code = (__s32)code;

    EVENT_OUTPUT_END(cred_events, event, struct cred_event, ctx);
    return 0;
}

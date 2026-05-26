// SPDX-License-Identifier: GPL-2.0 OR MIT
// caps.bpf.c - BPF program for tracing capability changes
// Security: Tracks capset syscalls for capability elevation detection
//
// capset(cap_user_header_t hdrp, cap_user_data_t datap)
// Detects processes attempting to modify their capability sets,
// especially gaining dangerous capabilities like CAP_SYS_ADMIN.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"
#include "discarders.h"
#include "output.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Force BTF export
struct capset_event *unused_capset_event __attribute__((unused));

// Capability header structure (matches __user_cap_header_struct)
struct user_cap_header {
    __u32 version;
    int pid;
};

// Capability data structure (matches __user_cap_data_struct)
// Modern kernels (version >= 0x20080522) use two of these for 64-bit caps
struct user_cap_data {
    __u32 effective;
    __u32 permitted;
    __u32 inheritable;
};

DECLARE_EVENT_OUTPUT(capset_events, struct capset_event, 256 * 1024);

// Helper to fill common fields
static __always_inline void fill_common_caps(struct capset_event *event, __u32 event_type) {
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
// Tracepoint: sys_enter_capset
// =============================================================================
// capset(cap_user_header_t hdrp, cap_user_data_t datap)
// args: [0]=hdrp (userspace pointer), [1]=datap (userspace pointer)
//
// Captures all capset calls. Even though most will fail (EPERM), the attempt
// itself is security-relevant. Successful capset calls to gain CAP_SYS_ADMIN,
// CAP_NET_RAW, CAP_DAC_OVERRIDE etc. are high-severity events.

SEC("tracepoint/syscalls/sys_enter_capset")
int tracepoint__syscalls__sys_enter_capset(struct trace_event_raw_sys_enter *ctx) {
    struct capset_event *event;
    struct user_cap_header hdr = {};
    struct user_cap_data data[2] = {};
    void *hdr_ptr, *data_ptr;

    // In-kernel discard check
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_CAPS, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(capset_events, struct capset_event);
    if (!event)
        return 0;

    fill_common_caps(event, EVENT_TYPE_CAPSET);

    // Read capability header from userspace
    hdr_ptr = (void *)ctx->args[0];
    if (hdr_ptr) {
        bpf_probe_read_user(&hdr, sizeof(hdr), hdr_ptr);
        event->target_pid = (__u32)hdr.pid;
        event->cap_version = hdr.version;
    }

    // Read capability data from userspace
    // Modern kernels use two __user_cap_data_struct entries for 64-bit caps
    data_ptr = (void *)ctx->args[1];
    if (data_ptr) {
        bpf_probe_read_user(&data, sizeof(data), data_ptr);
        // Combine lo + hi 32-bit halves into 64-bit capability sets
        event->cap_effective = ((__u64)data[1].effective << 32) | data[0].effective;
        event->cap_permitted = ((__u64)data[1].permitted << 32) | data[0].permitted;
        event->cap_inheritable = ((__u64)data[1].inheritable << 32) | data[0].inheritable;
    }

    EVENT_OUTPUT_END(capset_events, event, struct capset_event, ctx);
    return 0;
}

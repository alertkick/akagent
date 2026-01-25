// SPDX-License-Identifier: GPL-2.0 OR MIT
// module.bpf.c - BPF program for tracing kernel module operations
// SOX/PCI Compliance: Tracks init_module, finit_module, delete_module syscalls

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Force BTF export
struct module_event *unused_module_event __attribute__((unused));

// Ring buffer for module events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} module_events SEC(".maps");

// Helper to fill common fields
static __always_inline void fill_common_module(struct module_event *event, __u32 event_type) {
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

// Tracepoint for sys_enter_init_module
SEC("tracepoint/syscalls/sys_enter_init_module")
int tracepoint__syscalls__sys_enter_init_module(struct trace_event_raw_sys_enter *ctx) {
    struct module_event *event;

    event = bpf_ringbuf_reserve(&module_events, sizeof(*event), 0);
    if (!event)
        return 0;

    fill_common_module(event, EVENT_TYPE_INIT_MODULE);

    // args[0] = module_image, args[1] = len, args[2] = param_values
    // We can't read the module image, but we can get the size
    event->module_size = ctx->args[1];

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint for sys_enter_finit_module
SEC("tracepoint/syscalls/sys_enter_finit_module")
int tracepoint__syscalls__sys_enter_finit_module(struct trace_event_raw_sys_enter *ctx) {
    struct module_event *event;

    event = bpf_ringbuf_reserve(&module_events, sizeof(*event), 0);
    if (!event)
        return 0;

    fill_common_module(event, EVENT_TYPE_FINIT_MODULE);

    // args[0] = fd, args[1] = param_values, args[2] = flags
    event->flags = (__s32)ctx->args[2];

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint for sys_enter_delete_module
SEC("tracepoint/syscalls/sys_enter_delete_module")
int tracepoint__syscalls__sys_enter_delete_module(struct trace_event_raw_sys_enter *ctx) {
    struct module_event *event;
    const char *name;

    event = bpf_ringbuf_reserve(&module_events, sizeof(*event), 0);
    if (!event)
        return 0;

    fill_common_module(event, EVENT_TYPE_DELETE_MODULE);

    // args[0] = name_user, args[1] = flags
    name = (const char *)ctx->args[0];
    if (name) {
        bpf_probe_read_user_str(event->module_name, sizeof(event->module_name), name);
    }
    event->flags = (__s32)ctx->args[1];

    bpf_ringbuf_submit(event, 0);
    return 0;
}

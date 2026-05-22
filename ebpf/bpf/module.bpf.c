// SPDX-License-Identifier: GPL-2.0 OR MIT
// module.bpf.c - BPF program for tracing kernel module operations
// SOX/PCI Compliance: Tracks init_module, finit_module, delete_module syscalls
//
// Compiled in two modes:
//   Default:         Standard event output (struct module_event via ring buffer/perf)
//   -DUSE_ENRICHED:  Enriched event output (struct enriched_event with process lineage)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

#ifdef USE_ENRICHED
#include "enriched_helpers.h"
#else
#include "discarders.h"
#include "output.h"
#include "syscall_context.h"
#endif

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#ifdef USE_ENRICHED

// Ring buffer for enriched module events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} module_events_enriched SEC(".maps");

// Force BTF export
struct enriched_event *unused_enriched_module_event __attribute__((unused));

// Initialize enriched event fields for module events
static __always_inline void init_enriched_module_event(struct enriched_event *event) {
    init_enriched_event(event);
    event->module.module_name[0] = '\0';
    event->module.module_size = 0;
    event->module.module_flags = 0;
}

#else /* !USE_ENRICHED */

// Force BTF export
struct module_event *unused_module_event __attribute__((unused));

DECLARE_EVENT_OUTPUT(module_events, struct module_event, 256 * 1024);

// Saved context for module syscall enter/exit correlation
struct module_ctx {
    __u32 event_type;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    char module_name[MAX_MODULE_NAME_LEN];
    __u64 module_size;
    __s32 flags;
};
DECLARE_SYSCALL_CONTEXT(module_context, struct module_ctx, 512);

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

#endif /* USE_ENRICHED */

// =============================================================================
// Tracepoint: sys_enter_init_module
// =============================================================================
SEC("tracepoint/syscalls/sys_enter_init_module")
#ifdef USE_ENRICHED
int tracepoint__syscalls__sys_enter_init_module_enriched(struct trace_event_raw_sys_enter *ctx) {
#else
int tracepoint__syscalls__sys_enter_init_module(struct trace_event_raw_sys_enter *ctx) {
#endif
    // In-kernel discard check
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);

#ifdef USE_ENRICHED
    struct enriched_event *event = bpf_ringbuf_reserve(&module_events_enriched, sizeof(*event), 0);
    if (!event)
        return 0;

    init_enriched_module_event(event);

    __u64 uid_gid = bpf_get_current_uid_gid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_INIT_MODULE;
    event->pid = tgid;
    event->uid = (__u32)uid_gid;
    event->gid = (__u32)(uid_gid >> 32);

    // args[0] = module_image, args[1] = len, args[2] = param_values
    event->module.module_size = ctx->args[1];

    fill_process_context(event, tgid);

    bpf_ringbuf_submit(event, 0);
#else
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_KERNEL, tgid, comm))
        return 0;

    struct module_event *event = EVENT_OUTPUT_BEGIN(module_events, struct module_event);
    if (!event)
        return 0;

    fill_common_module(event, EVENT_TYPE_INIT_MODULE);

    // args[0] = module_image, args[1] = len, args[2] = param_values
    // We can't read the module image, but we can get the size
    event->module_size = ctx->args[1];

    EVENT_OUTPUT_END(module_events, event, struct module_event, ctx);
#endif
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_finit_module
// =============================================================================
SEC("tracepoint/syscalls/sys_enter_finit_module")
#ifdef USE_ENRICHED
int tracepoint__syscalls__sys_enter_finit_module_enriched(struct trace_event_raw_sys_enter *ctx) {
#else
int tracepoint__syscalls__sys_enter_finit_module(struct trace_event_raw_sys_enter *ctx) {
#endif
    // In-kernel discard check
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);

#ifdef USE_ENRICHED
    struct enriched_event *event = bpf_ringbuf_reserve(&module_events_enriched, sizeof(*event), 0);
    if (!event)
        return 0;

    init_enriched_module_event(event);

    __u64 uid_gid = bpf_get_current_uid_gid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_FINIT_MODULE;
    event->pid = tgid;
    event->uid = (__u32)uid_gid;
    event->gid = (__u32)(uid_gid >> 32);

    // args[0] = fd, args[1] = param_values, args[2] = flags
    event->module.module_flags = (__s32)ctx->args[2];

    fill_process_context(event, tgid);

    bpf_ringbuf_submit(event, 0);
#else
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_KERNEL, tgid, comm))
        return 0;

    struct module_event *event = EVENT_OUTPUT_BEGIN(module_events, struct module_event);
    if (!event)
        return 0;

    fill_common_module(event, EVENT_TYPE_FINIT_MODULE);

    // args[0] = fd, args[1] = param_values, args[2] = flags
    event->flags = (__s32)ctx->args[2];

    EVENT_OUTPUT_END(module_events, event, struct module_event, ctx);
#endif
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_delete_module
// =============================================================================
SEC("tracepoint/syscalls/sys_enter_delete_module")
#ifdef USE_ENRICHED
int tracepoint__syscalls__sys_enter_delete_module_enriched(struct trace_event_raw_sys_enter *ctx) {
#else
int tracepoint__syscalls__sys_enter_delete_module(struct trace_event_raw_sys_enter *ctx) {
#endif
    // In-kernel discard check
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);

#ifdef USE_ENRICHED
    struct enriched_event *event = bpf_ringbuf_reserve(&module_events_enriched, sizeof(*event), 0);
    if (!event)
        return 0;

    init_enriched_module_event(event);

    __u64 uid_gid = bpf_get_current_uid_gid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_DELETE_MODULE;
    event->pid = tgid;
    event->uid = (__u32)uid_gid;
    event->gid = (__u32)(uid_gid >> 32);

    // args[0] = name_user, args[1] = flags
    const char *name = (const char *)ctx->args[0];
    if (name)
        bpf_probe_read_user_str(event->module.module_name, sizeof(event->module.module_name), name);
    event->module.module_flags = (__s32)ctx->args[1];

    fill_process_context(event, tgid);

    bpf_ringbuf_submit(event, 0);
#else
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_KERNEL, tgid, comm))
        return 0;

    struct module_event *event = EVENT_OUTPUT_BEGIN(module_events, struct module_event);
    if (!event)
        return 0;

    fill_common_module(event, EVENT_TYPE_DELETE_MODULE);

    // args[0] = name_user, args[1] = flags
    const char *name = (const char *)ctx->args[0];
    if (name) {
        bpf_probe_read_user_str(event->module_name, sizeof(event->module_name), name);
    }
    event->flags = (__s32)ctx->args[1];

    EVENT_OUTPUT_END(module_events, event, struct module_event, ctx);
#endif
    return 0;
}

// =============================================================================
// Exit handlers (standard-only)
// =============================================================================
#ifndef USE_ENRICHED

// Shared exit handler for module syscalls
static __always_inline int handle_module_exit(struct trace_event_raw_sys_exit *ctx) {
    long ret = ctx->ret;
    if (ret == 0)
        return 0;

    struct module_event *event = EVENT_OUTPUT_BEGIN(module_events, struct module_event);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_INIT_MODULE;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = (u32)(pid_tgid >> 32);
    u64 uid_gid = bpf_get_current_uid_gid();
    event->uid = (u32)uid_gid;
    event->gid = (u32)(uid_gid >> 32);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->ret_code = (__s32)ret;

    EVENT_OUTPUT_END(module_events, event, struct module_event, ctx);
    return 0;
}

// sys_exit_init_module
SEC("tracepoint/syscalls/sys_exit_init_module")
int tracepoint__syscalls__sys_exit_init_module(struct trace_event_raw_sys_exit *ctx) {
    return handle_module_exit(ctx);
}

// sys_exit_finit_module
SEC("tracepoint/syscalls/sys_exit_finit_module")
int tracepoint__syscalls__sys_exit_finit_module(struct trace_event_raw_sys_exit *ctx) {
    return handle_module_exit(ctx);
}

#endif /* !USE_ENRICHED */

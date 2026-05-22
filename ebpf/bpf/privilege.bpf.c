// SPDX-License-Identifier: GPL-2.0 OR MIT
// privilege.bpf.c - BPF program for tracing privilege escalation operations
// SOX/PCI Compliance: Tracks setuid, setgid, setreuid, setregid syscalls
//
// Compiled in two modes:
//   Default:         Standard event output (struct privilege_event via ring buffer/perf)
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

// Ring buffer for enriched privilege events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} privilege_events_enriched SEC(".maps");

// Force BTF export
struct enriched_event *unused_enriched_priv_event __attribute__((unused));

// Initialize enriched event fields for privilege events
static __always_inline void init_enriched_priv_event(struct enriched_event *event) {
    init_enriched_event(event);
    event->privilege.old_uid = 0;
    event->privilege.new_uid = 0;
    event->privilege.old_euid = 0;
    event->privilege.new_euid = 0;
    event->privilege.old_gid = 0;
    event->privilege.new_gid = 0;
}

#else /* !USE_ENRICHED */

// Force BTF export
struct privilege_event *unused_privilege_event __attribute__((unused));

DECLARE_EVENT_OUTPUT(privilege_events, struct privilege_event, 256 * 1024);

// Saved context for privilege syscall enter/exit correlation
struct priv_ctx {
    __u32 event_type;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    __u32 new_uid;
    __u32 new_gid;
    __u32 new_euid;
    __u32 new_egid;
};
DECLARE_SYSCALL_CONTEXT(priv_context, struct priv_ctx, 2048);

// Helper to save privilege context on enter
static __always_inline void save_priv_ctx(__u32 event_type,
                                          __u32 new_uid, __u32 new_gid,
                                          __u32 new_euid, __u32 new_egid) {
    struct priv_ctx *saved = SYSCALL_CTX_SAVE(priv_context, struct priv_ctx);
    if (!saved) return;
    saved->event_type = event_type;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    saved->pid = (u32)(pid_tgid >> 32);
    u64 uid_gid = bpf_get_current_uid_gid();
    saved->uid = (u32)uid_gid;
    saved->gid = (u32)(uid_gid >> 32);
    bpf_get_current_comm(&saved->comm, sizeof(saved->comm));
    saved->new_uid = new_uid;
    saved->new_gid = new_gid;
    saved->new_euid = new_euid;
    saved->new_egid = new_egid;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = NULL;
        bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
        if (parent)
            bpf_probe_read_kernel(&saved->ppid, sizeof(saved->ppid), &parent->tgid);
    }
}

// Helper to fill common fields
static __always_inline void fill_common_priv(struct privilege_event *event, __u32 event_type) {
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
// Tracepoint: sys_enter_setuid
// =============================================================================
SEC("tracepoint/syscalls/sys_enter_setuid")
#ifdef USE_ENRICHED
int tracepoint__syscalls__sys_enter_setuid_enriched(struct trace_event_raw_sys_enter *ctx) {
#else
int tracepoint__syscalls__sys_enter_setuid(struct trace_event_raw_sys_enter *ctx) {
#endif
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);

#ifdef USE_ENRICHED
    __u32 new_uid = (__u32)ctx->args[0];

    // Get current UID
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 current_uid = (__u32)uid_gid;
    __u32 current_gid = (__u32)(uid_gid >> 32);

    // Only capture if escalating to root OR if current user is not root
    // This filters out most container initialization noise
    if (new_uid != 0 && current_uid == 0) {
        // Root dropping to non-root is usually benign
        return 0;
    }

    struct enriched_event *event = bpf_ringbuf_reserve(&privilege_events_enriched, sizeof(*event), 0);
    if (!event)
        return 0;

    init_enriched_priv_event(event);

    // Fill basic event info
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_SETUID;
    event->pid = tgid;
    event->uid = current_uid;
    event->gid = current_gid;

    // Fill privilege-specific data
    event->privilege.old_uid = current_uid;
    event->privilege.new_uid = new_uid;

    // Fill full process context from cache
    fill_process_context(event, tgid);

    bpf_ringbuf_submit(event, 0);
#else
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_PRIVILEGE, tgid, comm))
        return 0;

    struct privilege_event *event = EVENT_OUTPUT_BEGIN(privilege_events, struct privilege_event);
    if (!event)
        return 0;

    fill_common_priv(event, EVENT_TYPE_SETUID);

    // args[0] = uid
    event->new_uid = (__u32)ctx->args[0];

    save_priv_ctx(EVENT_TYPE_SETUID, (__u32)ctx->args[0], 0, 0, 0);

    EVENT_OUTPUT_END(privilege_events, event, struct privilege_event, ctx);
#endif
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_setgid
// =============================================================================
SEC("tracepoint/syscalls/sys_enter_setgid")
#ifdef USE_ENRICHED
int tracepoint__syscalls__sys_enter_setgid_enriched(struct trace_event_raw_sys_enter *ctx) {
#else
int tracepoint__syscalls__sys_enter_setgid(struct trace_event_raw_sys_enter *ctx) {
#endif
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);

#ifdef USE_ENRICHED
    __u32 new_gid = (__u32)ctx->args[0];

    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 current_uid = (__u32)uid_gid;
    __u32 current_gid = (__u32)(uid_gid >> 32);

    // Only capture if escalating to root group OR non-root doing it
    if (new_gid != 0 && current_uid == 0) {
        return 0;
    }

    struct enriched_event *event = bpf_ringbuf_reserve(&privilege_events_enriched, sizeof(*event), 0);
    if (!event)
        return 0;

    init_enriched_priv_event(event);

    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_SETGID;
    event->pid = tgid;
    event->uid = current_uid;
    event->gid = current_gid;

    event->privilege.old_gid = current_gid;
    event->privilege.new_gid = new_gid;

    fill_process_context(event, tgid);

    bpf_ringbuf_submit(event, 0);
#else
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_PRIVILEGE, tgid, comm))
        return 0;

    struct privilege_event *event = EVENT_OUTPUT_BEGIN(privilege_events, struct privilege_event);
    if (!event)
        return 0;

    fill_common_priv(event, EVENT_TYPE_SETGID);

    // args[0] = gid
    event->new_gid = (__u32)ctx->args[0];

    save_priv_ctx(EVENT_TYPE_SETGID, 0, (__u32)ctx->args[0], 0, 0);

    EVENT_OUTPUT_END(privilege_events, event, struct privilege_event, ctx);
#endif
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_setreuid
// =============================================================================
SEC("tracepoint/syscalls/sys_enter_setreuid")
#ifdef USE_ENRICHED
int tracepoint__syscalls__sys_enter_setreuid_enriched(struct trace_event_raw_sys_enter *ctx) {
#else
int tracepoint__syscalls__sys_enter_setreuid(struct trace_event_raw_sys_enter *ctx) {
#endif
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);

#ifdef USE_ENRICHED
    __u32 new_ruid = (__u32)ctx->args[0];
    __u32 new_euid = (__u32)ctx->args[1];

    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 current_uid = (__u32)uid_gid;
    __u32 current_gid = (__u32)(uid_gid >> 32);

    // Capture if escalating to root (either ruid or euid becomes 0)
    // -1 (0xffffffff) means "no change"
    int escalating_to_root = (new_ruid == 0 || new_euid == 0);
    int already_root = (current_uid == 0);

    if (!escalating_to_root && already_root) {
        return 0;
    }

    struct enriched_event *event = bpf_ringbuf_reserve(&privilege_events_enriched, sizeof(*event), 0);
    if (!event)
        return 0;

    init_enriched_priv_event(event);

    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_SETREUID;
    event->pid = tgid;
    event->uid = current_uid;
    event->gid = current_gid;

    event->privilege.old_uid = current_uid;
    event->privilege.new_uid = new_ruid;
    event->privilege.new_euid = new_euid;

    fill_process_context(event, tgid);

    bpf_ringbuf_submit(event, 0);
#else
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_PRIVILEGE, tgid, comm))
        return 0;

    struct privilege_event *event = EVENT_OUTPUT_BEGIN(privilege_events, struct privilege_event);
    if (!event)
        return 0;

    fill_common_priv(event, EVENT_TYPE_SETREUID);

    // args[0] = ruid, args[1] = euid
    event->new_uid = (__u32)ctx->args[0];
    event->new_euid = (__u32)ctx->args[1];

    save_priv_ctx(EVENT_TYPE_SETREUID, (__u32)ctx->args[0], 0, (__u32)ctx->args[1], 0);

    EVENT_OUTPUT_END(privilege_events, event, struct privilege_event, ctx);
#endif
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_setregid
// =============================================================================
SEC("tracepoint/syscalls/sys_enter_setregid")
#ifdef USE_ENRICHED
int tracepoint__syscalls__sys_enter_setregid_enriched(struct trace_event_raw_sys_enter *ctx) {
#else
int tracepoint__syscalls__sys_enter_setregid(struct trace_event_raw_sys_enter *ctx) {
#endif
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);

#ifdef USE_ENRICHED
    __u32 new_rgid = (__u32)ctx->args[0];
    __u32 new_egid = (__u32)ctx->args[1];

    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 current_uid = (__u32)uid_gid;
    __u32 current_gid = (__u32)(uid_gid >> 32);

    int escalating_to_root = (new_rgid == 0 || new_egid == 0);
    int already_root = (current_uid == 0);

    if (!escalating_to_root && already_root) {
        return 0;
    }

    struct enriched_event *event = bpf_ringbuf_reserve(&privilege_events_enriched, sizeof(*event), 0);
    if (!event)
        return 0;

    init_enriched_priv_event(event);

    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_SETREGID;
    event->pid = tgid;
    event->uid = current_uid;
    event->gid = current_gid;

    event->privilege.old_gid = current_gid;
    event->privilege.new_gid = new_rgid;

    fill_process_context(event, tgid);

    bpf_ringbuf_submit(event, 0);
#else
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_PRIVILEGE, tgid, comm))
        return 0;

    struct privilege_event *event = EVENT_OUTPUT_BEGIN(privilege_events, struct privilege_event);
    if (!event)
        return 0;

    fill_common_priv(event, EVENT_TYPE_SETREGID);

    // args[0] = rgid, args[1] = egid
    event->new_gid = (__u32)ctx->args[0];
    event->new_egid = (__u32)ctx->args[1];

    save_priv_ctx(EVENT_TYPE_SETREGID, 0, (__u32)ctx->args[0], 0, (__u32)ctx->args[1]);

    EVENT_OUTPUT_END(privilege_events, event, struct privilege_event, ctx);
#endif
    return 0;
}

// =============================================================================
// Standard-only: exit handlers and extended privilege syscalls
// =============================================================================
#ifndef USE_ENRICHED

// Shared sys_exit handler for setuid/setgid/setreuid/setregid
static __always_inline int handle_priv_exit(struct trace_event_raw_sys_exit *ctx) {
    struct priv_ctx *saved = SYSCALL_CTX_LOAD(priv_context, struct priv_ctx);
    if (!saved)
        return 0;

    long ret = ctx->ret;
    // Only emit on failure
    if (ret == 0)
        return 0;

    struct privilege_event *event = EVENT_OUTPUT_BEGIN(privilege_events, struct privilege_event);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = saved->event_type;
    event->pid = saved->pid;
    event->ppid = saved->ppid;
    event->uid = saved->uid;
    event->gid = saved->gid;
    __builtin_memcpy(event->comm, saved->comm, TASK_COMM_LEN);
    event->new_uid = saved->new_uid;
    event->new_gid = saved->new_gid;
    event->new_euid = saved->new_euid;
    event->new_egid = saved->new_egid;
    event->ret_code = (__s32)ret;

    EVENT_OUTPUT_END(privilege_events, event, struct privilege_event, ctx);
    return 0;
}

// sys_exit_setuid
SEC("tracepoint/syscalls/sys_exit_setuid")
int tracepoint__syscalls__sys_exit_setuid(struct trace_event_raw_sys_exit *ctx) {
    return handle_priv_exit(ctx);
}

// sys_exit_setgid
SEC("tracepoint/syscalls/sys_exit_setgid")
int tracepoint__syscalls__sys_exit_setgid(struct trace_event_raw_sys_exit *ctx) {
    return handle_priv_exit(ctx);
}

// sys_exit_setreuid
SEC("tracepoint/syscalls/sys_exit_setreuid")
int tracepoint__syscalls__sys_exit_setreuid(struct trace_event_raw_sys_exit *ctx) {
    return handle_priv_exit(ctx);
}

// sys_exit_setregid
SEC("tracepoint/syscalls/sys_exit_setregid")
int tracepoint__syscalls__sys_exit_setregid(struct trace_event_raw_sys_exit *ctx) {
    return handle_priv_exit(ctx);
}

// =============================================================================
// Extended privilege syscalls (standard-only)
// =============================================================================

// Tracepoint for sys_enter_setresuid
// setresuid(uid_t ruid, uid_t euid, uid_t suid)
SEC("tracepoint/syscalls/sys_enter_setresuid")
int tracepoint__syscalls__sys_enter_setresuid(struct trace_event_raw_sys_enter *ctx) {
    struct privilege_event *event;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_PRIVILEGE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(privilege_events, struct privilege_event);
    if (!event)
        return 0;

    fill_common_priv(event, EVENT_TYPE_SETRESUID);
    event->new_uid = (__u32)ctx->args[0];   // ruid
    event->new_euid = (__u32)ctx->args[1];  // euid

    save_priv_ctx(EVENT_TYPE_SETRESUID, (__u32)ctx->args[0], 0, (__u32)ctx->args[1], 0);

    EVENT_OUTPUT_END(privilege_events, event, struct privilege_event, ctx);
    return 0;
}

// Tracepoint for sys_enter_setresgid
// setresgid(gid_t rgid, gid_t egid, gid_t sgid)
SEC("tracepoint/syscalls/sys_enter_setresgid")
int tracepoint__syscalls__sys_enter_setresgid(struct trace_event_raw_sys_enter *ctx) {
    struct privilege_event *event;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_PRIVILEGE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(privilege_events, struct privilege_event);
    if (!event)
        return 0;

    fill_common_priv(event, EVENT_TYPE_SETRESGID);
    event->new_gid = (__u32)ctx->args[0];   // rgid
    event->new_egid = (__u32)ctx->args[1];  // egid

    save_priv_ctx(EVENT_TYPE_SETRESGID, 0, (__u32)ctx->args[0], 0, (__u32)ctx->args[1]);

    EVENT_OUTPUT_END(privilege_events, event, struct privilege_event, ctx);
    return 0;
}

// Tracepoint for sys_enter_setfsuid
SEC("tracepoint/syscalls/sys_enter_setfsuid")
int tracepoint__syscalls__sys_enter_setfsuid(struct trace_event_raw_sys_enter *ctx) {
    struct privilege_event *event;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_PRIVILEGE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(privilege_events, struct privilege_event);
    if (!event)
        return 0;

    fill_common_priv(event, EVENT_TYPE_SETFSUID);
    event->new_uid = (__u32)ctx->args[0];

    EVENT_OUTPUT_END(privilege_events, event, struct privilege_event, ctx);
    return 0;
}

// Tracepoint for sys_enter_setfsgid
SEC("tracepoint/syscalls/sys_enter_setfsgid")
int tracepoint__syscalls__sys_enter_setfsgid(struct trace_event_raw_sys_enter *ctx) {
    struct privilege_event *event;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_PRIVILEGE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(privilege_events, struct privilege_event);
    if (!event)
        return 0;

    fill_common_priv(event, EVENT_TYPE_SETFSGID);
    event->new_gid = (__u32)ctx->args[0];

    EVENT_OUTPUT_END(privilege_events, event, struct privilege_event, ctx);
    return 0;
}

#endif /* !USE_ENRICHED */

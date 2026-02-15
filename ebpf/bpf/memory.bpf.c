// SPDX-License-Identifier: GPL-2.0 OR MIT
// memory.bpf.c - BPF program for tracing memory protection changes
// Security: Tracks mprotect and mmap syscalls, especially PROT_EXEC additions
//
// Compiled in two modes:
//   Default:         Standard event output (struct memory_event via ring buffer/perf)
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
#endif

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Protection flags (from mman.h)
#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4

// mmap flags (from mman.h)
#define MAP_SHARED    0x01
#define MAP_PRIVATE   0x02
#define MAP_FIXED     0x10
#define MAP_ANONYMOUS 0x20

#ifdef USE_ENRICHED

// Ring buffer for enriched memory events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} memory_events_enriched SEC(".maps");

// Force BTF export
struct enriched_event *unused_enriched_memory_event __attribute__((unused));

// Initialize enriched event fields for memory events
static __always_inline void init_enriched_memory_event(struct enriched_event *event) {
    init_enriched_event(event);
    event->memory.addr = 0;
    event->memory.len = 0;
    event->memory.prot = 0;
    event->memory.old_prot = 0;
}

#else /* !USE_ENRICHED */

// Force BTF export
struct memory_event *unused_memory_event __attribute__((unused));

DECLARE_EVENT_OUTPUT(memory_events, struct memory_event, 256 * 1024);

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

#endif /* USE_ENRICHED */

// =============================================================================
// Tracepoint: sys_enter_mprotect
// =============================================================================
// Only capture events that add PROT_EXEC to reduce noise
SEC("tracepoint/syscalls/sys_enter_mprotect")
#ifdef USE_ENRICHED
int tracepoint__syscalls__sys_enter_mprotect_enriched(struct trace_event_raw_sys_enter *ctx) {
#else
int tracepoint__syscalls__sys_enter_mprotect(struct trace_event_raw_sys_enter *ctx) {
#endif
    __u32 prot;

    // args[0] = addr, args[1] = len, args[2] = prot
    prot = (__u32)ctx->args[2];

    // Only capture if PROT_EXEC is being added (potential code injection)
    if (!(prot & PROT_EXEC))
        return 0;

    // In-kernel discard check (after PROT_EXEC filter to avoid map lookups on non-exec mprotect)
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);

#ifdef USE_ENRICHED
    struct enriched_event *event = bpf_ringbuf_reserve(&memory_events_enriched, sizeof(*event), 0);
    if (!event)
        return 0;

    init_enriched_memory_event(event);

    __u64 uid_gid = bpf_get_current_uid_gid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_MPROTECT;
    event->pid = tgid;
    event->uid = (__u32)uid_gid;
    event->gid = (__u32)(uid_gid >> 32);

    event->memory.addr = ctx->args[0];
    event->memory.len = ctx->args[1];
    event->memory.prot = prot;

    fill_process_context(event, tgid);

    bpf_ringbuf_submit(event, 0);
#else
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_MEMORY, tgid, comm))
        return 0;

    struct memory_event *event = EVENT_OUTPUT_BEGIN(memory_events, struct memory_event);
    if (!event)
        return 0;

    fill_common_memory(event, EVENT_TYPE_MPROTECT);

    event->addr = ctx->args[0];
    event->len = ctx->args[1];
    event->prot = prot;

    EVENT_OUTPUT_END(memory_events, event, struct memory_event, ctx);
#endif
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_mmap
// =============================================================================
// mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
// args: [0]=addr, [1]=length, [2]=prot, [3]=flags, [4]=fd, [5]=offset
//
// Only captures security-relevant mmaps where PROT_EXEC is requested.
// This catches:
//   - Anonymous executable mappings (MAP_ANONYMOUS + PROT_EXEC) — shellcode injection
//   - RWX mappings (PROT_READ|PROT_WRITE|PROT_EXEC) — code injection / process hollowing
//   - Executable file-backed mappings from unusual sources
//
// Routine mmaps (library loads via ld.so, malloc arenas, etc.) that don't
// request PROT_EXEC are filtered out in-kernel to avoid overwhelming userspace.

SEC("tracepoint/syscalls/sys_enter_mmap")
#ifdef USE_ENRICHED
int tracepoint__syscalls__sys_enter_mmap_enriched(struct trace_event_raw_sys_enter *ctx) {
#else
int tracepoint__syscalls__sys_enter_mmap(struct trace_event_raw_sys_enter *ctx) {
#endif
    __u32 prot;

    // args[2] = prot
    prot = (__u32)ctx->args[2];

    // Only capture if PROT_EXEC is requested (potential code injection)
    if (!(prot & PROT_EXEC))
        return 0;

    // In-kernel discard check (after PROT_EXEC filter)
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);

#ifdef USE_ENRICHED
    struct enriched_event *event = bpf_ringbuf_reserve(&memory_events_enriched, sizeof(*event), 0);
    if (!event)
        return 0;

    init_enriched_memory_event(event);

    __u64 uid_gid = bpf_get_current_uid_gid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_MMAP;
    event->pid = tgid;
    event->uid = (__u32)uid_gid;
    event->gid = (__u32)(uid_gid >> 32);

    event->memory.addr = ctx->args[0];
    event->memory.len = ctx->args[1];
    event->memory.prot = prot;

    fill_process_context(event, tgid);

    bpf_ringbuf_submit(event, 0);
#else
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_MEMORY, tgid, comm))
        return 0;

    struct memory_event *event = EVENT_OUTPUT_BEGIN(memory_events, struct memory_event);
    if (!event)
        return 0;

    fill_common_memory(event, EVENT_TYPE_MMAP);

    event->addr = ctx->args[0];
    event->len = ctx->args[1];
    event->prot = prot;
    event->flags = (__u32)ctx->args[3];
    event->fd = (__s32)ctx->args[4];

    EVENT_OUTPUT_END(memory_events, event, struct memory_event, ctx);
#endif
    return 0;
}

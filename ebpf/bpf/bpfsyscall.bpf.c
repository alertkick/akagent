// SPDX-License-Identifier: GPL-2.0 OR MIT
// bpfsyscall.bpf.c - BPF program for monitoring the bpf() syscall
// Security: Detects eBPF rootkit loading, unauthorized BPF program creation,
// and kernel-level tampering via the bpf() system call.
//
// Threat scenarios:
// - Attacker loads malicious eBPF program as a rootkit
// - Unauthorized BPF program attachment to tracepoints/kprobes
// - BPF map creation for covert communication channels
// - BPF object pinning for persistence across reboots

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"
#include "discarders.h"
#include "output.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Force BTF export
struct bpf_syscall_event *unused_bpf_syscall_event __attribute__((unused));

DECLARE_EVENT_OUTPUT(bpf_syscall_events, struct bpf_syscall_event, 64 * 1024);

// =============================================================================
// BPF command constants (from include/uapi/linux/bpf.h)
// =============================================================================
#define BPF_CMD_MAP_CREATE           0
#define BPF_CMD_PROG_LOAD            5
#define BPF_CMD_OBJ_PIN             6
#define BPF_CMD_OBJ_GET             7
#define BPF_CMD_PROG_ATTACH          8
#define BPF_CMD_PROG_DETACH          9
#define BPF_CMD_RAW_TRACEPOINT_OPEN 17
#define BPF_CMD_BTF_LOAD            18
#define BPF_CMD_LINK_CREATE         28
#define BPF_CMD_LINK_UPDATE         29
#define BPF_CMD_PROG_BIND_MAP      35

// =============================================================================
// bpf_attr field offsets (from include/uapi/linux/bpf.h union bpf_attr)
// =============================================================================

// BPF_MAP_CREATE layout:
//   __u32 map_type;          offset 0
//   __u32 key_size;          offset 4
//   __u32 value_size;        offset 8
//   __u32 max_entries;       offset 12
//   __u32 map_flags;         offset 16
//   __u32 inner_map_fd;      offset 20
//   __u32 numa_node;         offset 24
//   char  map_name[16];      offset 28
#define MAP_CREATE_MAP_TYPE_OFF   0
#define MAP_CREATE_MAP_NAME_OFF  28

// BPF_PROG_LOAD layout:
//   __u32 prog_type;         offset 0
//   __u32 insn_cnt;          offset 4
//   __aligned_u64 insns;     offset 8
//   __aligned_u64 license;   offset 16
//   ...
//   char  prog_name[16];     offset 48
//   __u32 prog_ifindex;      offset 64
//   __u32 expected_attach_type; offset 68
#define PROG_LOAD_PROG_TYPE_OFF    0
#define PROG_LOAD_INSN_CNT_OFF     4
#define PROG_LOAD_PROG_NAME_OFF   48
#define PROG_LOAD_ATTACH_TYPE_OFF 68

// Check if a BPF command is security-critical and worth emitting
static __always_inline int is_security_critical_cmd(__u32 cmd) {
    switch (cmd) {
    case BPF_CMD_MAP_CREATE:
    case BPF_CMD_PROG_LOAD:
    case BPF_CMD_OBJ_PIN:
    case BPF_CMD_PROG_ATTACH:
    case BPF_CMD_PROG_DETACH:
    case BPF_CMD_RAW_TRACEPOINT_OPEN:
    case BPF_CMD_BTF_LOAD:
    case BPF_CMD_LINK_CREATE:
    case BPF_CMD_LINK_UPDATE:
    case BPF_CMD_PROG_BIND_MAP:
        return 1;
    default:
        return 0;
    }
}

// Helper to fill common fields
static __always_inline void fill_common_bpf(struct bpf_syscall_event *event) {
    struct task_struct *task;
    u64 pid_tgid, uid_gid;

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_BPF_CMD;

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
// Tracepoint: sys_enter_bpf
// =============================================================================
// bpf(int cmd, union bpf_attr *attr, unsigned int size)
// args: [0]=cmd, [1]=attr, [2]=size
//
// Detects bpf() syscall invocations that are security-relevant:
// - BPF_PROG_LOAD: Loading new eBPF programs (rootkit installation)
// - BPF_MAP_CREATE: Creating BPF maps (covert channels)
// - BPF_PROG_ATTACH: Attaching programs to hooks
// - BPF_OBJ_PIN: Pinning for persistence
// - BPF_LINK_CREATE: Creating BPF links
// - BPF_BTF_LOAD: Loading BTF data
//
// Read-only operations (MAP_LOOKUP_ELEM, PROG_GET_NEXT_ID, etc.) are
// intentionally skipped to avoid excessive noise.

SEC("tracepoint/syscalls/sys_enter_bpf")
int tracepoint__syscalls__sys_enter_bpf(struct trace_event_raw_sys_enter *ctx) {
    __u32 cmd = (__u32)ctx->args[0];

    // Fast path: skip non-security-critical commands
    if (!is_security_critical_cmd(cmd))
        return 0;

    // Apply discarder filtering (self-exclusion, config-based)
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_KERNEL, tgid, comm))
        return 0;

    const void *attr = (const void *)ctx->args[1];

    struct bpf_syscall_event *event = EVENT_OUTPUT_BEGIN(bpf_syscall_events, struct bpf_syscall_event);
    if (!event)
        return 0;

    fill_common_bpf(event);
    event->cmd = cmd;

    // Extract command-specific fields from bpf_attr
    if (attr) {
        switch (cmd) {
        case BPF_CMD_PROG_LOAD:
            bpf_probe_read_user(&event->prog_type, sizeof(event->prog_type),
                                attr + PROG_LOAD_PROG_TYPE_OFF);
            bpf_probe_read_user(&event->insn_cnt, sizeof(event->insn_cnt),
                                attr + PROG_LOAD_INSN_CNT_OFF);
            bpf_probe_read_user(&event->attach_type, sizeof(event->attach_type),
                                attr + PROG_LOAD_ATTACH_TYPE_OFF);
            bpf_probe_read_user(&event->obj_name, sizeof(event->obj_name),
                                attr + PROG_LOAD_PROG_NAME_OFF);
            break;

        case BPF_CMD_MAP_CREATE:
            bpf_probe_read_user(&event->prog_type, sizeof(event->prog_type),
                                attr + MAP_CREATE_MAP_TYPE_OFF);
            bpf_probe_read_user(&event->obj_name, sizeof(event->obj_name),
                                attr + MAP_CREATE_MAP_NAME_OFF);
            break;

        case BPF_CMD_PROG_ATTACH:
        case BPF_CMD_LINK_CREATE:
            // For attach/link, first u32 in attr is target_fd, second is prog_fd
            // We store attach_type which is at different offsets per command,
            // but the prog_type field isn't directly available here.
            // We leave prog_type=0 and rely on userspace correlation.
            break;

        default:
            // For other commands (OBJ_PIN, BTF_LOAD, etc.), emit basic info
            break;
        }
    }

    EVENT_OUTPUT_END(bpf_syscall_events, event, struct bpf_syscall_event, ctx);
    return 0;
}

// sys_exit_bpf - capture return value for bpf() syscall
SEC("tracepoint/syscalls/sys_exit_bpf")
int tracepoint__syscalls__sys_exit_bpf(struct trace_event_raw_sys_exit *ctx) {
    long ret = ctx->ret;
    // Only emit on failure
    if (ret >= 0)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_KERNEL, tgid, comm))
        return 0;

    struct bpf_syscall_event *event = EVENT_OUTPUT_BEGIN(bpf_syscall_events, struct bpf_syscall_event);
    if (!event)
        return 0;

    fill_common_bpf(event);
    // cmd is not available on exit, but we record the failure
    event->cmd = 0;  // Unknown on exit path

    EVENT_OUTPUT_END(bpf_syscall_events, event, struct bpf_syscall_event, ctx);
    return 0;
}

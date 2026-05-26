// SPDX-License-Identifier: GPL-2.0 OR MIT
// ioctl.bpf.c - BPF program for monitoring security-relevant ioctl commands
//
// Captures ioctl calls filtered to security-relevant commands:
//   - TIOCSTI (0x5412): Terminal injection - push characters to terminal input
//   - TIOCSWINSZ (0x5414): Window size change (can trigger signal-based attacks)
//   - TIOCLINUX (0x541C): Linux-specific terminal ioctls (potential escape)
//   - KDSETLED (0x4B32): Keyboard LED (unusual, potential indicator)
//   - LOOP_SET_FD (0x4C00): Loop device setup (can mount files as devices)
//   - LOOP_CLR_FD (0x4C01): Loop device teardown
//   - LOOP_SET_STATUS64 (0x4C04): Loop device configuration

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"
#include "discarders.h"
#include "output.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Force BTF export
struct ioctl_event *unused_ioctl_event __attribute__((unused));

// Security-relevant ioctl command numbers
#define TIOCSTI          0x5412
#define TIOCSWINSZ       0x5414
#define TIOCLINUX        0x541C
#define KDSETLED         0x4B32
#define LOOP_SET_FD      0x4C00
#define LOOP_CLR_FD      0x4C01
#define LOOP_SET_STATUS64 0x4C04

DECLARE_EVENT_OUTPUT(ioctl_events, struct ioctl_event, 64 * 1024);

// Helper to fill common fields
static __always_inline void fill_common_ioctl(struct ioctl_event *event) {
    struct task_struct *task;
    u64 pid_tgid, uid_gid;

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_IOCTL;

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

// Tracepoint for sys_enter_ioctl
// ioctl(int fd, unsigned long request, unsigned long arg)
// args: [0]=fd, [1]=request, [2]=arg
SEC("tracepoint/syscalls/sys_enter_ioctl")
int tracepoint__syscalls__sys_enter_ioctl(struct trace_event_raw_sys_enter *ctx) {
    __u32 cmd = (__u32)ctx->args[1];

    // Filter to security-relevant ioctl commands only
    switch (cmd) {
    case TIOCSTI:
    case TIOCSWINSZ:
    case TIOCLINUX:
    case KDSETLED:
    case LOOP_SET_FD:
    case LOOP_CLR_FD:
    case LOOP_SET_STATUS64:
        break;
    default:
        return 0;
    }

    // In-kernel discard check
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    struct ioctl_event *event = EVENT_OUTPUT_BEGIN(ioctl_events, struct ioctl_event);
    if (!event)
        return 0;

    fill_common_ioctl(event);

    event->fd = (__s32)ctx->args[0];
    event->cmd = cmd;
    event->arg = ctx->args[2];

    EVENT_OUTPUT_END(ioctl_events, event, struct ioctl_event, ctx);
    return 0;
}

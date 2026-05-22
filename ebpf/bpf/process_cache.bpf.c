// SPDX-License-Identifier: GPL-2.0 OR MIT
// process_cache.bpf.c - Process lifecycle tracking for event correlation
//
// This program maintains a cache of process information that is populated
// when processes execute (execve) and cleaned up when they exit. Other
// BPF programs can look up this cache to get full process context.


#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"
#include "dentry.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Force BTF export
struct process_info *unused_process_info __attribute__((unused));
struct enriched_event *unused_enriched_event __attribute__((unused));

// Process cache - stores process info keyed by PID
// This map is shared and can be accessed by other BPF programs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PROCESS_CACHE_SIZE);
    __type(key, __u32);
    __type(value, struct process_info);
} process_cache SEC(".maps");

// Per-CPU scratch space for building process_info (avoids stack overflow)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct process_info);
} proc_info_scratch SEC(".maps");

// Ring buffer for enriched security events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);  // 512 KB
} enriched_events SEC(".maps");

// Per-CPU scratch space for dentry path resolution
DECLARE_DENTRY_SCRATCH(dentry_scratch);

// Helper to read cmdline from task
// Note: Reading cmdline in BPF is limited - userspace enrichment provides better data
static __always_inline int read_cmdline(char *cmdline, __u32 max_len, struct task_struct *task) {
    struct mm_struct *mm;
    unsigned long arg_start, arg_end;
    __u32 len;

    if (!task) return 0;

    // Try to read mm struct - this may fail on some kernels
    mm = BPF_CORE_READ(task, mm);
    if (!mm) return 0;

    // Read arg boundaries
    arg_start = BPF_CORE_READ(mm, arg_start);
    arg_end = BPF_CORE_READ(mm, arg_end);

    if (arg_start == 0 || arg_end == 0 || arg_end <= arg_start)
        return 0;

    len = (__u32)(arg_end - arg_start);
    if (len > max_len - 1)
        len = max_len - 1;
    if (len > 256)
        len = 256;

    // Bitmask bound so the verifier can prove len is in [0, 511]
    len &= 0x1FF;
    if (len == 0)
        return 0;

    // Read cmdline from user memory
    if (bpf_probe_read_user(cmdline, len, (void *)arg_start) < 0)
        return 0;

    return len;
}

// Tracepoint for sched_process_exec - called when a process calls execve successfully
SEC("tracepoint/sched/sched_process_exec")
int handle_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    __u32 zero = 0;
    struct process_info *info;
    struct task_struct *task;
    struct task_struct *parent;
    struct process_info *parent_info;
    __u64 pid_tgid;
    __u32 pid, ppid;

    // Get scratch space (per-CPU, no stack usage)
    info = bpf_map_lookup_elem(&proc_info_scratch, &zero);
    if (!info) return 0;

    // Initialize key fields (per-CPU array is already zeroed on creation)
    info->pid = 0;
    info->ppid = 0;
    info->uid = 0;
    info->gid = 0;
    info->start_time_ns = 0;
    info->flags = 0;
    info->cgroup_id = 0;
    info->grandparent_pid = 0;
    info->parent_pid = 0;
    info->ns_pid = 0;
    info->comm[0] = '\0';
    info->exe[0] = '\0';
    info->cmdline[0] = '\0';
    info->parent_comm[0] = '\0';
    info->parent_exe[0] = '\0';
    info->grandparent_comm[0] = '\0';
    info->container_id[0] = '\0';

    pid_tgid = bpf_get_current_pid_tgid();
    pid = (__u32)(pid_tgid >> 32);

    // Initialize process info
    info->pid = pid;
    info->start_time_ns = bpf_ktime_get_ns();

    // Get UID/GID
    __u64 uid_gid = bpf_get_current_uid_gid();
    info->uid = (__u32)uid_gid;
    info->gid = (__u32)(uid_gid >> 32);

    // Set flags
    if (info->uid == 0) {
        info->flags |= PROC_FLAG_ROOT_USER;
    }

    // Get comm
    bpf_get_current_comm(&info->comm, sizeof(info->comm));

    // Get cgroup ID
    info->cgroup_id = bpf_get_current_cgroup_id();

    // Get task for further reads
    task = (struct task_struct *)bpf_get_current_task();

    // Resolve exe path from kernel dentry chain (gives absolute path)
    __u32 scratch_key = 0;
    struct path_scratch *dscratch = bpf_map_lookup_elem(&dentry_scratch, &scratch_key);
    if (dscratch) {
        int ret = resolve_exe_path(info->exe, sizeof(info->exe), dscratch);
        if (ret <= 0) {
            // Fallback: read from tracepoint context
            unsigned int filename_offset = ctx->__data_loc_filename & 0xFFFF;
            bpf_probe_read_kernel_str(&info->exe, sizeof(info->exe),
                                       (void *)ctx + filename_offset);
        }
    } else {
        // Fallback: read from tracepoint context
        unsigned int filename_offset = ctx->__data_loc_filename & 0xFFFF;
        bpf_probe_read_kernel_str(&info->exe, sizeof(info->exe),
                                   (void *)ctx + filename_offset);
    }

    // Read cmdline
    read_cmdline(info->cmdline, sizeof(info->cmdline), task);

    // Get parent info from task_struct
    if (task) {
        parent = BPF_CORE_READ(task, real_parent);
        if (parent) {
            ppid = BPF_CORE_READ(parent, tgid);
            info->ppid = ppid;
            info->parent_pid = ppid;

            // Read parent comm directly
            bpf_probe_read_kernel_str(&info->parent_comm, sizeof(info->parent_comm),
                                      &parent->comm);

            // Look up parent in our cache for even richer context
            parent_info = bpf_map_lookup_elem(&process_cache, &ppid);
            if (parent_info) {
                // Copy parent's full exe if we have it cached
                if (info->parent_exe[0] == '\0') {
                    __builtin_memcpy(&info->parent_exe, &parent_info->exe, sizeof(info->parent_exe));
                }
                // Get grandparent info from parent's cached info
                info->grandparent_pid = parent_info->ppid;
                __builtin_memcpy(&info->grandparent_comm, &parent_info->parent_comm,
                                sizeof(info->grandparent_comm));

                // Inherit container context from parent
                __builtin_memcpy(&info->container_id, &parent_info->container_id,
                                sizeof(info->container_id));
                if (parent_info->flags & PROC_FLAG_IN_CONTAINER) {
                    info->flags |= PROC_FLAG_IN_CONTAINER;
                }
            }
        }
    }

    // Store in cache
    bpf_map_update_elem(&process_cache, &pid, info, BPF_ANY);

    return 0;
}

// Tracepoint for sched_process_exit - cleanup cache when process exits
SEC("tracepoint/sched/sched_process_exit")
int handle_sched_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&process_cache, &pid);
    return 0;
}

// Tracepoint for sched_process_fork - pre-populate cache for child
SEC("tracepoint/sched/sched_process_fork")
int handle_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    __u32 zero = 0;
    struct process_info *info;
    struct process_info *parent_info;
    __u32 parent_pid = ctx->parent_pid;
    __u32 child_pid = ctx->child_pid;

    // Look up parent info
    parent_info = bpf_map_lookup_elem(&process_cache, &parent_pid);
    if (!parent_info) return 0;

    // Get scratch space
    info = bpf_map_lookup_elem(&proc_info_scratch, &zero);
    if (!info) return 0;

    // Copy parent info to child (will be updated on exec)
    // Use bpf_probe_read_kernel for large struct copy
    if (bpf_probe_read_kernel(info, sizeof(*info), parent_info) < 0)
        return 0;
    info->pid = child_pid;
    info->ppid = parent_pid;
    info->parent_pid = parent_pid;
    info->start_time_ns = bpf_ktime_get_ns();

    // Parent becomes the new parent context
    __builtin_memcpy(&info->parent_comm, &parent_info->comm, TASK_COMM_LEN);
    __builtin_memcpy(&info->parent_exe, &parent_info->exe, sizeof(info->parent_exe));

    // Grandparent is parent's parent
    info->grandparent_pid = parent_info->ppid;
    __builtin_memcpy(&info->grandparent_comm, &parent_info->parent_comm, TASK_COMM_LEN);

    bpf_map_update_elem(&process_cache, &child_pid, info, BPF_NOEXIST);

    return 0;
}

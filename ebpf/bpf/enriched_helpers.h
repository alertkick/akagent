// SPDX-License-Identifier: GPL-2.0 OR MIT
// enriched_helpers.h - Shared helpers for enriched BPF event programs
//
// Provides process cache map, init_enriched_event(), and fill_process_context()
// used by all enriched event programs. Only active when USE_ENRICHED is defined.

#ifndef __ENRICHED_HELPERS_H
#define __ENRICHED_HELPERS_H

#ifdef USE_ENRICHED

#include "common.h"

// Reference the shared process cache from process_cache.bpf.c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PROCESS_CACHE_SIZE);
    __type(key, __u32);
    __type(value, struct process_info);
} process_cache SEC(".maps");

// Initialize common enriched event fields (non-union fields).
// Caller must initialize union-specific fields before use.
static __always_inline void init_enriched_event(struct enriched_event *event) {
    event->timestamp_ns = 0;
    event->event_type = 0;
    event->flags = 0;
    event->pid = 0;
    event->ppid = 0;
    event->uid = 0;
    event->gid = 0;
    event->grandparent_pid = 0;
    event->cgroup_id = 0;
    event->ret_code = 0;
    event->comm[0] = '\0';
    event->exe[0] = '\0';
    event->cmdline[0] = '\0';
    event->parent_comm[0] = '\0';
    event->parent_exe[0] = '\0';
    event->grandparent_comm[0] = '\0';
    event->container_id[0] = '\0';
}

// Fill enriched event with full process context from cache.
// Falls back to basic info from current task if not in cache.
static __always_inline void fill_process_context(struct enriched_event *event, __u32 pid) {
    struct process_info *proc;

    proc = bpf_map_lookup_elem(&process_cache, &pid);
    if (proc) {
        event->ppid = proc->ppid;
        bpf_probe_read_kernel(&event->comm, sizeof(event->comm), &proc->comm);
        bpf_probe_read_kernel(&event->exe, sizeof(event->exe), &proc->exe);
        bpf_probe_read_kernel(&event->cmdline, sizeof(event->cmdline), &proc->cmdline);
        bpf_probe_read_kernel(&event->parent_comm, sizeof(event->parent_comm), &proc->parent_comm);
        bpf_probe_read_kernel(&event->parent_exe, sizeof(event->parent_exe), &proc->parent_exe);
        event->grandparent_pid = proc->grandparent_pid;
        bpf_probe_read_kernel(&event->grandparent_comm, sizeof(event->grandparent_comm), &proc->grandparent_comm);
        bpf_probe_read_kernel(&event->container_id, sizeof(event->container_id), &proc->container_id);
        event->cgroup_id = proc->cgroup_id;
        event->flags |= proc->flags;
    } else {
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        event->cgroup_id = bpf_get_current_cgroup_id();

        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        if (task) {
            struct task_struct *parent = BPF_CORE_READ(task, real_parent);
            if (parent) {
                event->ppid = BPF_CORE_READ(parent, tgid);
                bpf_probe_read_kernel_str(&event->parent_comm, sizeof(event->parent_comm),
                                          &parent->comm);
            }
        }
    }
}

#endif /* USE_ENRICHED */

#endif /* __ENRICHED_HELPERS_H */

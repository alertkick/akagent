// SPDX-License-Identifier: GPL-2.0 OR MIT
// discarders.h - In-kernel discarder maps for event filtering
//
// These maps are populated from userspace (Go) with filtering config.
// Each BPF program includes this header and checks discarders BEFORE
// reserving ring buffer space, preventing irrelevant events from ever
// reaching userspace. This significantly reduces CPU overhead on busy hosts.
//
// Design: All maps default to "allow" (zero-value = allow). Userspace
// writes explicit discard entries. This ensures safe behavior before
// maps are populated.

#ifndef __DISCARDERS_H
#define __DISCARDERS_H

#include "common.h"

// ============================================================================
// Discard category indices (must match Go DiscarderCategory constants)
// ============================================================================
#define DISCARD_CAT_GLOBAL     0
#define DISCARD_CAT_PROCESS    1
#define DISCARD_CAT_FILE       2
#define DISCARD_CAT_NETWORK    3
#define DISCARD_CAT_PRIVILEGE  4
#define DISCARD_CAT_FILESYSTEM 5
#define DISCARD_CAT_KERNEL     6
#define DISCARD_CAT_MEMORY     7
#define DISCARD_CAT_NAMESPACE  8
#define DISCARD_CAT_CAPS       9
#define DISCARD_CONFIG_SIZE    10

// ============================================================================
// Discarder Maps
// ============================================================================

// Config map: array indexed by category
// value 0 = allow (default for zero-initialized arrays), value 1 = discard
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, DISCARD_CONFIG_SIZE);
    __type(key, __u32);
    __type(value, __u8);
} discard_config SEC(".maps");

// Comm discarder: hash map keyed by process comm name (16 bytes)
// If a comm name is present in this map, events from that process are discarded.
// Populated from ExcludeComms config + native list exclusions.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, char[TASK_COMM_LEN]);
    __type(value, __u8);
} discard_comms SEC(".maps");

// PID discarder: hash map keyed by PID (thread group ID)
// Used to exclude the agent's own PID and other known-safe PIDs.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} discard_pids SEC(".maps");

// Per-category discard statistics (per-CPU for lock-free counting)
// Key = category index, Value = count of discarded events
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, DISCARD_CONFIG_SIZE);
    __type(key, __u32);
    __type(value, __u64);
} discard_stats SEC(".maps");

// ============================================================================
// Discarder Helper Functions
// ============================================================================

// Increment discard stats for a category
static __always_inline void inc_discard_stat(__u32 category) {
    __u64 *count = bpf_map_lookup_elem(&discard_stats, &category);
    if (count)
        __sync_fetch_and_add(count, 1);
}

// Check if a category is disabled (should discard)
// Array maps are zero-initialized, so default 0 = allow
static __always_inline int category_disabled(__u32 category) {
    __u8 *discard = bpf_map_lookup_elem(&discard_config, &category);
    return (discard && *discard == 1);
}

// Check if a comm name should be discarded
static __always_inline int comm_discarded(char comm[TASK_COMM_LEN]) {
    return bpf_map_lookup_elem(&discard_comms, comm) != NULL;
}

// Check if a PID should be discarded
static __always_inline int pid_discarded(__u32 pid) {
    return bpf_map_lookup_elem(&discard_pids, &pid) != NULL;
}

// Combined discard check - returns 1 if event should be discarded
// Checks are ordered by cost: array lookup < hash lookup
static __always_inline int should_discard(__u32 category, __u32 pid, char comm[TASK_COMM_LEN]) {
    // Check global disable first
    if (category_disabled(DISCARD_CAT_GLOBAL)) {
        inc_discard_stat(DISCARD_CAT_GLOBAL);
        return 1;
    }

    // Check category disable
    if (category_disabled(category)) {
        inc_discard_stat(category);
        return 1;
    }

    // Check PID discarder (agent self-exclusion, known-safe PIDs)
    if (pid_discarded(pid)) {
        inc_discard_stat(category);
        return 1;
    }

    // Check comm name discarder (excluded process names)
    if (comm_discarded(comm)) {
        inc_discard_stat(category);
        return 1;
    }

    return 0;
}

#endif /* __DISCARDERS_H */

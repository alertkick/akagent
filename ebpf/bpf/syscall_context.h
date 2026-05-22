// SPDX-License-Identifier: GPL-2.0 OR MIT
// syscall_context.h - Enter/exit correlation for syscall tracing
//
// Provides macros to save context on sys_enter and retrieve it on sys_exit,
// allowing BPF programs to emit events with both arguments and return values.
//
// Usage:
//   1. Declare a context map:
//        DECLARE_SYSCALL_CONTEXT(my_ctx, struct my_saved_args, 4096);
//   2. In sys_enter handler:
//        struct my_saved_args *ctx = SYSCALL_CTX_SAVE(my_ctx);
//        if (!ctx) return 0;
//        ctx->filename = ...; // save args
//   3. In sys_exit handler:
//        struct my_saved_args *ctx = SYSCALL_CTX_LOAD(my_ctx);
//        if (!ctx) return 0;
//        long ret = ... ; // get return value
//        // emit event using saved args + ret

#ifndef __SYSCALL_CONTEXT_H
#define __SYSCALL_CONTEXT_H

#include <bpf/bpf_helpers.h>

// Declare a per-CPU LRU hash map for enter/exit correlation.
// Keyed by PID+TID (u64 from bpf_get_current_pid_tgid()).
// LRU automatically evicts stale entries if a sys_exit is missed.
#define DECLARE_SYSCALL_CONTEXT(name, value_type, max_ents)   \
struct {                                                       \
    __uint(type, BPF_MAP_TYPE_LRU_HASH);                      \
    __uint(max_entries, max_ents);                             \
    __type(key, __u64);                                        \
    __type(value, value_type);                                 \
} name SEC(".maps")

// Save context on sys_enter. Returns a pointer to the saved value,
// or NULL on failure. Caller must fill in the fields.
#define SYSCALL_CTX_SAVE(map_name, value_type)                \
({                                                             \
    __u64 __pid_tgid = bpf_get_current_pid_tgid();           \
    value_type __zero = {};                                    \
    bpf_map_update_elem(&map_name, &__pid_tgid, &__zero, BPF_ANY); \
    (value_type *)bpf_map_lookup_elem(&map_name, &__pid_tgid); \
})

// Load saved context on sys_exit. Returns a pointer to the saved
// value, or NULL if no matching enter was found. Automatically
// deletes the entry after lookup.
#define SYSCALL_CTX_LOAD(map_name, value_type)                \
({                                                             \
    __u64 __pid_tgid = bpf_get_current_pid_tgid();           \
    value_type *__val = (value_type *)bpf_map_lookup_elem(    \
        &map_name, &__pid_tgid);                              \
    if (__val) {                                               \
        bpf_map_delete_elem(&map_name, &__pid_tgid);         \
    }                                                          \
    __val;                                                     \
})

// Like SYSCALL_CTX_LOAD but does NOT delete the entry (for peek)
#define SYSCALL_CTX_PEEK(map_name, value_type)                \
({                                                             \
    __u64 __pid_tgid = bpf_get_current_pid_tgid();           \
    (value_type *)bpf_map_lookup_elem(&map_name, &__pid_tgid); \
})

#endif /* __SYSCALL_CONTEXT_H */

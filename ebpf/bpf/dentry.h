// SPDX-License-Identifier: GPL-2.0 OR MIT
// dentry.h - Kernel dentry-based path resolution for BPF programs
//
// Provides helpers to walk the dentry chain and build absolute paths
// from kernel structures. This gives reliable full paths (e.g., /usr/bin/curl)
// rather than relying on tracepoint filename arguments which may be relative.
//
// Usage:
//   1. Declare a per-CPU scratch map in your BPF program:
//        DECLARE_DENTRY_SCRATCH(my_scratch);
//   2. Call resolve_dentry_path() or resolve_exe_path() with a buffer.
//
// Each BPF program that uses dentry resolution must declare its own scratch
// map. Maps are shared with Go via map replacement at load time.

#ifndef __DENTRY_H
#define __DENTRY_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Maximum depth of dentry chain to walk (prevents infinite loops)
#define MAX_PATH_DEPTH 8

// Maximum length of a single path component
#define MAX_COMPONENT_LEN 64

// Scratch space for building paths from dentry chains.
// Stored in per-CPU array to avoid BPF stack overflow (512 byte limit).
struct path_scratch {
    // Temporary storage for path components (reversed order)
    char components[MAX_PATH_DEPTH][MAX_COMPONENT_LEN];
    // Length of each component
    int comp_len[MAX_PATH_DEPTH];
    // Number of components found
    int depth;
};

// Macro to declare the per-CPU scratch map for dentry resolution.
// Each BPF program that uses dentry helpers must declare this.
#define DECLARE_DENTRY_SCRATCH(name)                 \
struct {                                              \
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);         \
    __uint(max_entries, 1);                           \
    __type(key, __u32);                               \
    __type(value, struct path_scratch);               \
} name SEC(".maps")

// resolve_dentry_path walks a dentry chain up to the root and builds
// the absolute path in buf. Returns the number of bytes written, or 0
// on failure.
//
// The algorithm:
//   1. Walk d_parent chain, reading d_name.name at each level
//   2. Store components in scratch space (reversed order)
//   3. Concatenate components with '/' separators into buf
static __always_inline int resolve_dentry_path(
    struct dentry *dentry,
    char *buf,
    int buf_len,
    struct path_scratch *scratch)
{
    struct dentry *d;
    struct dentry *parent;
    int depth = 0;
    int i, pos;

    if (!dentry || !buf || !scratch || buf_len < 2)
        return 0;

    // Zero the depth counter
    scratch->depth = 0;

    d = dentry;

    // Walk up the dentry chain, collecting path components
    #pragma unroll
    for (i = 0; i < MAX_PATH_DEPTH; i++) {
        if (!d)
            break;

        parent = BPF_CORE_READ(d, d_parent);

        // Root dentry: d_parent points to itself
        if (parent == d)
            break;

        // Read the component name
        const unsigned char *name = BPF_CORE_READ(d, d_name.name);
        if (!name)
            break;

        int ret = bpf_probe_read_kernel_str(
            scratch->components[depth],
            MAX_COMPONENT_LEN,
            name);
        if (ret <= 0)
            break;

        scratch->comp_len[depth] = ret - 1; // exclude null terminator
        depth++;
        d = parent;
    }

    if (depth == 0) {
        // Only root or empty - return "/"
        if (buf_len >= 2) {
            buf[0] = '/';
            buf[1] = '\0';
            return 1;
        }
        return 0;
    }

    scratch->depth = depth;

    // Build the path by concatenating components in reverse order
    pos = 0;

    // Iterate in reverse to build forward path
    #pragma unroll
    for (i = MAX_PATH_DEPTH - 1; i >= 0; i--) {
        if (i >= depth)
            continue;

        // Bounds check for verifier
        if (pos >= buf_len - 1)
            break;

        // Add separator
        buf[pos] = '/';
        pos++;

        // Copy component
        __u32 clen = (__u32)scratch->comp_len[i];
        if (clen == 0 || clen > MAX_COMPONENT_LEN - 1)
            continue;
        if (pos + (int)clen >= buf_len - 1)
            clen = (__u32)(buf_len - pos - 1);
        // Bitmask bound so verifier can prove clen is in [0, 63]
        clen &= (MAX_COMPONENT_LEN - 1);
        if (clen == 0)
            break;

        bpf_probe_read_kernel(buf + pos, clen, scratch->components[i]);
        pos += clen;
    }

    // Null-terminate
    if (pos < buf_len)
        buf[pos] = '\0';
    else
        buf[buf_len - 1] = '\0';

    return pos;
}

// resolve_exe_path resolves the current task's executable path via
// task_struct->mm->exe_file->f_path.dentry and writes it to buf.
// Returns the number of bytes written, or 0 on failure.
static __always_inline int resolve_exe_path(
    char *buf,
    int buf_len,
    struct path_scratch *scratch)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct file *exe_file;
    struct dentry *exe_dentry;

    task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    mm = BPF_CORE_READ(task, mm);
    if (!mm)
        return 0;

    exe_file = BPF_CORE_READ(mm, exe_file);
    if (!exe_file)
        return 0;

    exe_dentry = BPF_CORE_READ(exe_file, f_path.dentry);
    if (!exe_dentry)
        return 0;

    return resolve_dentry_path(exe_dentry, buf, buf_len, scratch);
}

#endif /* __DENTRY_H */

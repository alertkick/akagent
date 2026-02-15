// SPDX-License-Identifier: GPL-2.0 OR MIT
// vfs_hooks.bpf.c - BPF kprobe programs for VFS-layer monitoring
//
// Provides kernel-level file operation visibility via kprobes on VFS functions.
// Unlike syscall tracepoints, VFS hooks see operations from all sources
// (syscalls, kernel threads, NFS, FUSE, io_uring, etc.) and have access
// to resolved dentry paths rather than user-provided strings.
//
// Hooks:
//   - vfs_open: File opens at VFS layer (sees all opens, not just openat)
//   - vfs_unlink: File deletion at VFS layer
//   - vfs_rename: File rename at VFS layer
//   - security_inode_setattr: Attribute changes (chmod, chown, truncate)
//
// These kprobes are optional — they require CAP_PERFMON and may fail
// on kernels with lockdown mode enabled. The Go agent handles fallback.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"
#include "discarders.h"
#include "output.h"
#include "dentry.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Force BTF export
struct vfs_event *unused_vfs_event __attribute__((unused));

DECLARE_EVENT_OUTPUT(vfs_events, struct vfs_event, 256 * 1024);
DECLARE_DENTRY_SCRATCH(vfs_dentry_scratch);

// Helper to fill common fields
static __always_inline void fill_common_vfs(struct vfs_event *event, __u32 event_type) {
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

// Helper to read inode metadata
static __always_inline void read_inode_info(struct vfs_event *event, struct inode *inode) {
    if (!inode)
        return;
    event->i_mode = BPF_CORE_READ(inode, i_mode);
    event->i_uid = BPF_CORE_READ(inode, i_uid);
    event->i_ino = BPF_CORE_READ(inode, i_ino);
}

// =============================================================================
// kprobe: vfs_open
// =============================================================================
// int vfs_open(const struct path *path, struct file *file)
//
// Captures all file opens at the VFS layer, including those from
// kernel threads, NFS operations, and io_uring.

SEC("kprobe/vfs_open")
int BPF_KPROBE(kprobe_vfs_open, const struct path *path, struct file *file) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    struct vfs_event *event = EVENT_OUTPUT_BEGIN(vfs_events, struct vfs_event);
    if (!event)
        return 0;

    fill_common_vfs(event, EVENT_TYPE_VFS_OPEN);

    // Resolve path from dentry
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    if (dentry) {
        __u32 scratch_key = 0;
        struct path_scratch *scratch = bpf_map_lookup_elem(&vfs_dentry_scratch, &scratch_key);
        if (scratch) {
            resolve_dentry_path(dentry, event->path, sizeof(event->path), scratch);
        }

        // Read inode info
        struct inode *inode = BPF_CORE_READ(dentry, d_inode);
        read_inode_info(event, inode);
    }

    EVENT_OUTPUT_END(vfs_events, event, struct vfs_event, ctx);
    return 0;
}

// =============================================================================
// kprobe: vfs_unlink
// =============================================================================
// int vfs_unlink(struct mnt_idmap *idmap, struct inode *dir,
//                struct dentry *dentry, struct inode **delegated_inode)
//
// Note: Kernel 5.12+ changed the signature to include mnt_idmap.
// We use BPF_CORE_READ to be version-agnostic where possible.
// The dentry arg position varies; we use the named parameter approach.

SEC("kprobe/vfs_unlink")
int BPF_KPROBE(kprobe_vfs_unlink) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    struct vfs_event *event = EVENT_OUTPUT_BEGIN(vfs_events, struct vfs_event);
    if (!event)
        return 0;

    fill_common_vfs(event, EVENT_TYPE_VFS_UNLINK);

    // arg2 is the dentry on older kernels, arg3 on newer (with mnt_idmap)
    // Try reading from arg index 2 (most common on 5.12+)
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM3(ctx);
    if (dentry) {
        __u32 scratch_key = 0;
        struct path_scratch *scratch = bpf_map_lookup_elem(&vfs_dentry_scratch, &scratch_key);
        if (scratch) {
            resolve_dentry_path(dentry, event->path, sizeof(event->path), scratch);
        }

        struct inode *inode = BPF_CORE_READ(dentry, d_inode);
        read_inode_info(event, inode);
    }

    EVENT_OUTPUT_END(vfs_events, event, struct vfs_event, ctx);
    return 0;
}

// =============================================================================
// kprobe: vfs_rename
// =============================================================================
// int vfs_rename(struct renamedata *rd)  (kernel 5.12+)
// OR
// int vfs_rename(struct inode *old_dir, struct dentry *old_dentry,
//                struct inode *new_dir, struct dentry *new_dentry, ...)
//
// We target the modern single-arg version (5.12+).

SEC("kprobe/vfs_rename")
int BPF_KPROBE(kprobe_vfs_rename, struct renamedata *rd) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    struct vfs_event *event = EVENT_OUTPUT_BEGIN(vfs_events, struct vfs_event);
    if (!event)
        return 0;

    fill_common_vfs(event, EVENT_TYPE_VFS_RENAME);

    if (rd) {
        __u32 scratch_key = 0;
        struct path_scratch *scratch = bpf_map_lookup_elem(&vfs_dentry_scratch, &scratch_key);

        // Read old path from old_dentry
        struct dentry *old_dentry = BPF_CORE_READ(rd, old_dentry);
        if (old_dentry && scratch) {
            resolve_dentry_path(old_dentry, event->path, sizeof(event->path), scratch);

            struct inode *inode = BPF_CORE_READ(old_dentry, d_inode);
            read_inode_info(event, inode);
        }

        // Read new path from new_dentry
        struct dentry *new_dentry = BPF_CORE_READ(rd, new_dentry);
        if (new_dentry && scratch) {
            resolve_dentry_path(new_dentry, event->path2, sizeof(event->path2), scratch);
        }
    }

    EVENT_OUTPUT_END(vfs_events, event, struct vfs_event, ctx);
    return 0;
}

// =============================================================================
// kprobe: security_inode_setattr
// =============================================================================
// int security_inode_setattr(struct mnt_idmap *idmap,
//                            struct dentry *dentry, struct iattr *attr)
//
// This LSM hook is called for chmod, chown, truncate, and utimes.
// It provides the dentry and the proposed new attributes.

SEC("kprobe/security_inode_setattr")
int BPF_KPROBE(kprobe_security_inode_setattr) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    struct vfs_event *event = EVENT_OUTPUT_BEGIN(vfs_events, struct vfs_event);
    if (!event)
        return 0;

    fill_common_vfs(event, EVENT_TYPE_INODE_SETATTR);

    // arg2 is the dentry (after mnt_idmap on 6.x, or after dentry on 5.x)
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    if (dentry) {
        __u32 scratch_key = 0;
        struct path_scratch *scratch = bpf_map_lookup_elem(&vfs_dentry_scratch, &scratch_key);
        if (scratch) {
            resolve_dentry_path(dentry, event->path, sizeof(event->path), scratch);
        }

        struct inode *inode = BPF_CORE_READ(dentry, d_inode);
        read_inode_info(event, inode);
    }

    EVENT_OUTPUT_END(vfs_events, event, struct vfs_event, ctx);
    return 0;
}

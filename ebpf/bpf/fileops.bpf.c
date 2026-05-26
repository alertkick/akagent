// SPDX-License-Identifier: GPL-2.0 OR MIT
// fileops.bpf.c - BPF program for tracing file operations
//
// Compiled in two modes:
//   Default:         Standard event output (struct file_event via ring buffer/perf)
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

// AT_REMOVEDIR flag (from include/uapi/linux/fcntl.h)
#define AT_REMOVEDIR 0x200

#ifdef USE_ENRICHED

// Ring buffer for enriched file events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} file_events_enriched SEC(".maps");

// Force BTF export
struct enriched_event *unused_enriched_file_event __attribute__((unused));

// Initialize enriched event fields for file events
static __always_inline void init_enriched_file_event(struct enriched_event *event) {
    init_enriched_event(event);
    event->file.filename[0] = '\0';
    event->file.filename2[0] = '\0';
    event->file.file_flags = 0;
}

#else /* !USE_ENRICHED */

// Force BTF export
struct file_event *unused_file_event __attribute__((unused));

DECLARE_EVENT_OUTPUT(file_events, struct file_event, 256 * 1024);

// Saved context for openat enter/exit correlation
struct openat_ctx {
    char filename[MAX_FILENAME_LEN];
    __s32 flags;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
};
DECLARE_SYSCALL_CONTEXT(openat_context, struct openat_ctx, 4096);

// Helper to fill common fields
static __always_inline void fill_common(struct file_event *event, __u32 event_type) {
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
// Tracepoint: sys_enter_openat
// =============================================================================
// Saves context for exit correlation and emits the enter event
SEC("tracepoint/syscalls/sys_enter_openat")
#ifdef USE_ENRICHED
int tracepoint__syscalls__sys_enter_openat_enriched(struct trace_event_raw_sys_enter *ctx) {
#else
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
#endif
    const char *filename;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);

#ifdef USE_ENRICHED
    struct enriched_event *event = bpf_ringbuf_reserve(&file_events_enriched, sizeof(*event), 0);
    if (!event)
        return 0;

    init_enriched_file_event(event);

    __u64 uid_gid = bpf_get_current_uid_gid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_OPEN;
    event->pid = tgid;
    event->uid = (__u32)uid_gid;
    event->gid = (__u32)(uid_gid >> 32);

    // args[1] = filename, args[2] = flags
    filename = (const char *)ctx->args[1];
    if (filename)
        bpf_probe_read_user_str(event->file.filename, sizeof(event->file.filename), filename);
    event->file.file_flags = (__s32)ctx->args[2];

    fill_process_context(event, tgid);

    bpf_ringbuf_submit(event, 0);
#else
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    // Save context for sys_exit correlation
    struct openat_ctx *saved = SYSCALL_CTX_SAVE(openat_context, struct openat_ctx);
    if (saved) {
        saved->pid = tgid;
        saved->flags = (s32)ctx->args[2];
        __builtin_memcpy(saved->comm, comm, TASK_COMM_LEN);
        u64 uid_gid = bpf_get_current_uid_gid();
        saved->uid = (u32)uid_gid;
        saved->gid = (u32)(uid_gid >> 32);
        filename = (const char *)ctx->args[1];
        if (filename) {
            bpf_probe_read_user_str(saved->filename, sizeof(saved->filename), filename);
        }
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        if (task) {
            struct task_struct *parent = NULL;
            bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
            if (parent)
                bpf_probe_read_kernel(&saved->ppid, sizeof(saved->ppid), &parent->tgid);
        }
    }

    struct file_event *event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_OPEN);

    // args[1] = filename, args[2] = flags
    filename = (const char *)ctx->args[1];
    if (filename) {
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
    }
    event->flags = (s32)ctx->args[2];

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
#endif
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_unlinkat
// =============================================================================
// unlinkat(int dirfd, const char *pathname, int flags)
// When flags includes AT_REMOVEDIR, this is equivalent to rmdir.
SEC("tracepoint/syscalls/sys_enter_unlinkat")
#ifdef USE_ENRICHED
int tracepoint__syscalls__sys_enter_unlinkat_enriched(struct trace_event_raw_sys_enter *ctx) {
#else
int tracepoint__syscalls__sys_enter_unlinkat(struct trace_event_raw_sys_enter *ctx) {
#endif
    const char *filename;

    __s32 flags = (__s32)ctx->args[2];
    __u32 etype = (flags & AT_REMOVEDIR) ? EVENT_TYPE_RMDIR : EVENT_TYPE_UNLINK;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);

#ifdef USE_ENRICHED
    struct enriched_event *event = bpf_ringbuf_reserve(&file_events_enriched, sizeof(*event), 0);
    if (!event)
        return 0;

    init_enriched_file_event(event);

    __u64 uid_gid = bpf_get_current_uid_gid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = etype;
    event->pid = tgid;
    event->uid = (__u32)uid_gid;
    event->gid = (__u32)(uid_gid >> 32);

    // args[1] = filename
    filename = (const char *)ctx->args[1];
    if (filename)
        bpf_probe_read_user_str(event->file.filename, sizeof(event->file.filename), filename);
    event->file.file_flags = flags;

    fill_process_context(event, tgid);

    bpf_ringbuf_submit(event, 0);
#else
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    struct file_event *event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, etype);

    // args[1] = filename
    filename = (const char *)ctx->args[1];
    if (filename) {
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
    }
    event->flags = flags;

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
#endif
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_renameat2
// =============================================================================
SEC("tracepoint/syscalls/sys_enter_renameat2")
#ifdef USE_ENRICHED
int tracepoint__syscalls__sys_enter_renameat2_enriched(struct trace_event_raw_sys_enter *ctx) {
#else
int tracepoint__syscalls__sys_enter_renameat2(struct trace_event_raw_sys_enter *ctx) {
#endif
    const char *oldname;
    const char *newname;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);

#ifdef USE_ENRICHED
    struct enriched_event *event = bpf_ringbuf_reserve(&file_events_enriched, sizeof(*event), 0);
    if (!event)
        return 0;

    init_enriched_file_event(event);

    __u64 uid_gid = bpf_get_current_uid_gid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_RENAME;
    event->pid = tgid;
    event->uid = (__u32)uid_gid;
    event->gid = (__u32)(uid_gid >> 32);

    // args[1] = oldname, args[3] = newname
    oldname = (const char *)ctx->args[1];
    newname = (const char *)ctx->args[3];
    if (oldname)
        bpf_probe_read_user_str(event->file.filename, sizeof(event->file.filename), oldname);
    if (newname)
        bpf_probe_read_user_str(event->file.filename2, sizeof(event->file.filename2), newname);

    fill_process_context(event, tgid);

    bpf_ringbuf_submit(event, 0);
#else
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    struct file_event *event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_RENAME);

    // args[1] = oldname, args[3] = newname
    oldname = (const char *)ctx->args[1];
    newname = (const char *)ctx->args[3];

    if (oldname) {
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), oldname);
    }
    if (newname) {
        bpf_probe_read_user_str(event->filename2, sizeof(event->filename2), newname);
    }

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
#endif
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_fchmodat
// =============================================================================
SEC("tracepoint/syscalls/sys_enter_fchmodat")
#ifdef USE_ENRICHED
int tracepoint__syscalls__sys_enter_fchmodat_enriched(struct trace_event_raw_sys_enter *ctx) {
#else
int tracepoint__syscalls__sys_enter_fchmodat(struct trace_event_raw_sys_enter *ctx) {
#endif
    const char *filename;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);

#ifdef USE_ENRICHED
    struct enriched_event *event = bpf_ringbuf_reserve(&file_events_enriched, sizeof(*event), 0);
    if (!event)
        return 0;

    init_enriched_file_event(event);

    __u64 uid_gid = bpf_get_current_uid_gid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_CHMOD;
    event->pid = tgid;
    event->uid = (__u32)uid_gid;
    event->gid = (__u32)(uid_gid >> 32);

    // args[1] = filename, args[2] = mode
    filename = (const char *)ctx->args[1];
    if (filename)
        bpf_probe_read_user_str(event->file.filename, sizeof(event->file.filename), filename);
    event->file.file_flags = (__s32)ctx->args[2]; // mode

    fill_process_context(event, tgid);

    bpf_ringbuf_submit(event, 0);
#else
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    struct file_event *event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_CHMOD);

    // args[1] = filename, args[2] = mode
    filename = (const char *)ctx->args[1];
    if (filename) {
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
    }
    event->flags = (s32)ctx->args[2]; // mode

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
#endif
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_fchownat
// =============================================================================
// fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags)
// args: [0]=dirfd, [1]=pathname, [2]=owner, [3]=group, [4]=flags
//
// Ownership changes are critical for privilege escalation detection.
// Changing file ownership to root (UID 0) is highly suspicious.

SEC("tracepoint/syscalls/sys_enter_fchownat")
#ifdef USE_ENRICHED
int tracepoint__syscalls__sys_enter_fchownat_enriched(struct trace_event_raw_sys_enter *ctx) {
#else
int tracepoint__syscalls__sys_enter_fchownat(struct trace_event_raw_sys_enter *ctx) {
#endif
    const char *filename;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);

#ifdef USE_ENRICHED
    struct enriched_event *event = bpf_ringbuf_reserve(&file_events_enriched, sizeof(*event), 0);
    if (!event)
        return 0;

    init_enriched_file_event(event);

    __u64 uid_gid = bpf_get_current_uid_gid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_CHOWN;
    event->pid = tgid;
    event->uid = (__u32)uid_gid;
    event->gid = (__u32)(uid_gid >> 32);

    // args[1] = pathname, args[2] = owner, args[3] = group, args[4] = flags
    filename = (const char *)ctx->args[1];
    if (filename)
        bpf_probe_read_user_str(event->file.filename, sizeof(event->file.filename), filename);
    event->file.file_flags = (__s32)ctx->args[4];

    fill_process_context(event, tgid);

    bpf_ringbuf_submit(event, 0);
#else
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    struct file_event *event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_CHOWN);

    filename = (const char *)ctx->args[1];
    if (filename) {
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
    }
    event->new_uid = (__u32)ctx->args[2];
    event->new_gid = (__u32)ctx->args[3];
    event->flags = (__s32)ctx->args[4];

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
#endif
    return 0;
}

// =============================================================================
// Standard-only tracepoints (not needed in enriched mode)
// =============================================================================
#ifndef USE_ENRICHED

// sys_exit_openat - capture return value (fd or error)
SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct trace_event_raw_sys_exit *ctx) {
    struct openat_ctx *saved = SYSCALL_CTX_LOAD(openat_context, struct openat_ctx);
    if (!saved)
        return 0;

    long ret = ctx->ret;

    // Only emit exit event on error (negative return)
    if (ret >= 0)
        return 0;

    struct file_event *event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_OPEN;
    event->pid = saved->pid;
    event->ppid = saved->ppid;
    event->uid = saved->uid;
    event->gid = saved->gid;
    __builtin_memcpy(event->comm, saved->comm, TASK_COMM_LEN);
    __builtin_memcpy(event->filename, saved->filename, MAX_FILENAME_LEN);
    event->flags = saved->flags;
    event->ret_code = (__s32)ret;

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_mkdirat
// =============================================================================
// mkdirat(int dirfd, const char *pathname, mode_t mode)
// args: [0]=dirfd, [1]=pathname, [2]=mode

SEC("tracepoint/syscalls/sys_enter_mkdirat")
int tracepoint__syscalls__sys_enter_mkdirat(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;
    const char *filename;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_MKDIR);

    filename = (const char *)ctx->args[1];
    if (filename) {
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
    }
    event->flags = (__s32)ctx->args[2]; // mode

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_linkat
// =============================================================================
// linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags)
// args: [0]=olddirfd, [1]=oldpath, [2]=newdirfd, [3]=newpath, [4]=flags
//
// Hard link creation can be used in symlink/hardlink attacks to gain access
// to files by creating additional directory entries.

SEC("tracepoint/syscalls/sys_enter_linkat")
int tracepoint__syscalls__sys_enter_linkat(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;
    const char *oldpath;
    const char *newpath;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_LINK);

    oldpath = (const char *)ctx->args[1];
    newpath = (const char *)ctx->args[3];

    if (oldpath) {
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), oldpath);
    }
    if (newpath) {
        bpf_probe_read_user_str(event->filename2, sizeof(event->filename2), newpath);
    }
    event->flags = (__s32)ctx->args[4];

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_symlinkat
// =============================================================================
// symlinkat(const char *target, int newdirfd, const char *linkpath)
// args: [0]=target, [1]=newdirfd, [2]=linkpath

SEC("tracepoint/syscalls/sys_enter_symlinkat")
int tracepoint__syscalls__sys_enter_symlinkat(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;
    const char *target;
    const char *linkpath;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_SYMLINK);

    // filename = linkpath (the new symlink), filename2 = target (what it points to)
    linkpath = (const char *)ctx->args[2];
    target = (const char *)ctx->args[0];

    if (linkpath) {
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), linkpath);
    }
    if (target) {
        bpf_probe_read_user_str(event->filename2, sizeof(event->filename2), target);
    }

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_setxattr
// =============================================================================
// setxattr(const char *path, const char *name, const void *value, size_t size, int flags)
// args: [0]=path, [1]=name, [2]=value, [3]=size, [4]=flags
//
// Extended attribute changes are security-relevant: SELinux labels, capabilities,
// ACLs are all stored as xattrs. Changing security.* or system.* xattrs
// can bypass access controls.

SEC("tracepoint/syscalls/sys_enter_setxattr")
int tracepoint__syscalls__sys_enter_setxattr(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;
    const char *path;
    const char *name;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_SETXATTR);

    path = (const char *)ctx->args[0];
    name = (const char *)ctx->args[1];

    if (path) {
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), path);
    }
    if (name) {
        bpf_probe_read_user_str(event->filename2, sizeof(event->filename2), name);
    }
    event->flags = (__s32)ctx->args[4];

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_removexattr
// =============================================================================
// removexattr(const char *path, const char *name)
// args: [0]=path, [1]=name

SEC("tracepoint/syscalls/sys_enter_removexattr")
int tracepoint__syscalls__sys_enter_removexattr(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;
    const char *path;
    const char *name;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_REMOVEXATTR);

    path = (const char *)ctx->args[0];
    name = (const char *)ctx->args[1];

    if (path) {
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), path);
    }
    if (name) {
        bpf_probe_read_user_str(event->filename2, sizeof(event->filename2), name);
    }

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_utimensat
// =============================================================================
// utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags)
// args: [0]=dirfd, [1]=pathname, [2]=times, [3]=flags
//
// Timestamp manipulation is a key anti-forensics technique. Attackers modify
// atime/mtime to hide evidence of file access or modification.

SEC("tracepoint/syscalls/sys_enter_utimensat")
int tracepoint__syscalls__sys_enter_utimensat(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;
    const char *filename;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_UTIMES);

    filename = (const char *)ctx->args[1];
    if (filename) {
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
    }
    event->flags = (__s32)ctx->args[3]; // AT_SYMLINK_NOFOLLOW, etc.

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_openat2
// =============================================================================
// openat2(int dirfd, const char *pathname, struct open_how *how, size_t size)
// args: [0]=dirfd, [1]=pathname, [2]=how, [3]=size

SEC("tracepoint/syscalls/sys_enter_openat2")
int tracepoint__syscalls__sys_enter_openat2(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;
    const char *filename;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_OPENAT2);

    filename = (const char *)ctx->args[1];
    if (filename) {
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
    }
    // Read flags from open_how struct (first field is __u64 flags)
    const void *how = (const void *)ctx->args[2];
    if (how) {
        __u64 open_flags = 0;
        bpf_probe_read_user(&open_flags, sizeof(open_flags), how);
        event->flags = (__s32)open_flags;
    }

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_open_by_handle_at
// =============================================================================
// open_by_handle_at(int mount_fd, struct file_handle *handle, int flags)
// args: [0]=mount_fd, [1]=handle, [2]=flags
// Used in container escape attacks to access host filesystem

SEC("tracepoint/syscalls/sys_enter_open_by_handle_at")
int tracepoint__syscalls__sys_enter_open_by_handle_at(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_OPEN_BY_HANDLE);
    event->flags = (__s32)ctx->args[2];

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_truncate
// =============================================================================
// truncate(const char *path, long length)
// args: [0]=path, [1]=length

SEC("tracepoint/syscalls/sys_enter_truncate")
int tracepoint__syscalls__sys_enter_truncate(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;
    const char *filename;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_TRUNCATE);

    filename = (const char *)ctx->args[0];
    if (filename) {
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
    }
    event->flags = (__s32)ctx->args[1]; // length

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_ftruncate
// =============================================================================
// ftruncate(unsigned int fd, unsigned long length)
// args: [0]=fd, [1]=length

SEC("tracepoint/syscalls/sys_enter_ftruncate")
int tracepoint__syscalls__sys_enter_ftruncate(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_FTRUNCATE);
    event->flags = (__s32)ctx->args[1]; // length

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

// =============================================================================
// Legacy syscall variants
// These are older versions of the *at() syscalls. On modern Linux, glibc
// translates them to the *at() variants, but some statically-linked binaries
// or Go programs may still use them directly.
// =============================================================================

// sys_enter_open: open(const char *pathname, int flags, mode_t mode)
// args: [0]=pathname, [1]=flags, [2]=mode
SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;
    const char *filename;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_OPEN);

    filename = (const char *)ctx->args[0];
    if (filename)
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
    event->flags = (__s32)ctx->args[1];

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

// sys_enter_rename: rename(const char *oldpath, const char *newpath)
// args: [0]=oldpath, [1]=newpath
SEC("tracepoint/syscalls/sys_enter_rename")
int tracepoint__syscalls__sys_enter_rename(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_RENAME);

    const char *oldpath = (const char *)ctx->args[0];
    const char *newpath = (const char *)ctx->args[1];
    if (oldpath)
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), oldpath);
    if (newpath)
        bpf_probe_read_user_str(event->filename2, sizeof(event->filename2), newpath);

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

// sys_enter_renameat: renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
// args: [0]=olddirfd, [1]=oldpath, [2]=newdirfd, [3]=newpath
SEC("tracepoint/syscalls/sys_enter_renameat")
int tracepoint__syscalls__sys_enter_renameat(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_RENAME);

    const char *oldpath = (const char *)ctx->args[1];
    const char *newpath = (const char *)ctx->args[3];
    if (oldpath)
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), oldpath);
    if (newpath)
        bpf_probe_read_user_str(event->filename2, sizeof(event->filename2), newpath);

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

// sys_enter_unlink: unlink(const char *pathname)
// args: [0]=pathname
SEC("tracepoint/syscalls/sys_enter_unlink")
int tracepoint__syscalls__sys_enter_unlink(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_UNLINK);

    const char *filename = (const char *)ctx->args[0];
    if (filename)
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

// sys_enter_mkdir: mkdir(const char *pathname, mode_t mode)
// args: [0]=pathname, [1]=mode
SEC("tracepoint/syscalls/sys_enter_mkdir")
int tracepoint__syscalls__sys_enter_mkdir(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_MKDIR);

    const char *filename = (const char *)ctx->args[0];
    if (filename)
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
    event->flags = (__s32)ctx->args[1]; // mode

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

// sys_enter_rmdir: rmdir(const char *pathname)
// args: [0]=pathname
SEC("tracepoint/syscalls/sys_enter_rmdir")
int tracepoint__syscalls__sys_enter_rmdir(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_RMDIR);

    const char *filename = (const char *)ctx->args[0];
    if (filename)
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

// sys_enter_chmod: chmod(const char *pathname, mode_t mode)
// args: [0]=pathname, [1]=mode
SEC("tracepoint/syscalls/sys_enter_chmod")
int tracepoint__syscalls__sys_enter_chmod(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_CHMOD);

    const char *filename = (const char *)ctx->args[0];
    if (filename)
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
    event->flags = (__s32)ctx->args[1]; // mode

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

// sys_enter_fchmod: fchmod(int fd, mode_t mode)
// args: [0]=fd, [1]=mode
SEC("tracepoint/syscalls/sys_enter_fchmod")
int tracepoint__syscalls__sys_enter_fchmod(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_CHMOD);
    event->flags = (__s32)ctx->args[1]; // mode

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

// sys_enter_chown: chown(const char *pathname, uid_t owner, gid_t group)
// args: [0]=pathname, [1]=owner, [2]=group
SEC("tracepoint/syscalls/sys_enter_chown")
int tracepoint__syscalls__sys_enter_chown(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_CHOWN);

    const char *filename = (const char *)ctx->args[0];
    if (filename)
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
    event->new_uid = (__u32)ctx->args[1];
    event->new_gid = (__u32)ctx->args[2];

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

// sys_enter_fchown: fchown(int fd, uid_t owner, gid_t group)
// args: [0]=fd, [1]=owner, [2]=group
SEC("tracepoint/syscalls/sys_enter_fchown")
int tracepoint__syscalls__sys_enter_fchown(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_CHOWN);
    event->new_uid = (__u32)ctx->args[1];
    event->new_gid = (__u32)ctx->args[2];

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

// sys_enter_lchown: lchown(const char *pathname, uid_t owner, gid_t group)
// args: [0]=pathname, [1]=owner, [2]=group
SEC("tracepoint/syscalls/sys_enter_lchown")
int tracepoint__syscalls__sys_enter_lchown(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_CHOWN);

    const char *filename = (const char *)ctx->args[0];
    if (filename)
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
    event->new_uid = (__u32)ctx->args[1];
    event->new_gid = (__u32)ctx->args[2];

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

// sys_enter_fsetxattr: fsetxattr(int fd, const char *name, const void *value, size_t size, int flags)
// args: [0]=fd, [1]=name, [2]=value, [3]=size, [4]=flags
SEC("tracepoint/syscalls/sys_enter_fsetxattr")
int tracepoint__syscalls__sys_enter_fsetxattr(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_SETXATTR);

    const char *name = (const char *)ctx->args[1];
    if (name)
        bpf_probe_read_user_str(event->filename2, sizeof(event->filename2), name);
    event->flags = (__s32)ctx->args[4];

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

// sys_enter_lsetxattr: lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags)
// args: [0]=path, [1]=name, [2]=value, [3]=size, [4]=flags
SEC("tracepoint/syscalls/sys_enter_lsetxattr")
int tracepoint__syscalls__sys_enter_lsetxattr(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_SETXATTR);

    const char *path = (const char *)ctx->args[0];
    const char *name = (const char *)ctx->args[1];
    if (path)
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), path);
    if (name)
        bpf_probe_read_user_str(event->filename2, sizeof(event->filename2), name);
    event->flags = (__s32)ctx->args[4];

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

// sys_enter_fremovexattr: fremovexattr(int fd, const char *name)
// args: [0]=fd, [1]=name
SEC("tracepoint/syscalls/sys_enter_fremovexattr")
int tracepoint__syscalls__sys_enter_fremovexattr(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_REMOVEXATTR);

    const char *name = (const char *)ctx->args[1];
    if (name)
        bpf_probe_read_user_str(event->filename2, sizeof(event->filename2), name);

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

// sys_enter_lremovexattr: lremovexattr(const char *path, const char *name)
// args: [0]=path, [1]=name
SEC("tracepoint/syscalls/sys_enter_lremovexattr")
int tracepoint__syscalls__sys_enter_lremovexattr(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_FILE, tgid, comm))
        return 0;

    event = EVENT_OUTPUT_BEGIN(file_events, struct file_event);
    if (!event)
        return 0;

    fill_common(event, EVENT_TYPE_REMOVEXATTR);

    const char *path = (const char *)ctx->args[0];
    const char *name = (const char *)ctx->args[1];
    if (path)
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), path);
    if (name)
        bpf_probe_read_user_str(event->filename2, sizeof(event->filename2), name);

    EVENT_OUTPUT_END(file_events, event, struct file_event, ctx);
    return 0;
}

#endif /* !USE_ENRICHED */

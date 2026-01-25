// SPDX-License-Identifier: GPL-2.0 OR MIT
// common.h - Shared structures between BPF programs and userspace

#ifndef __COMMON_H
#define __COMMON_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define MAX_ARGS_LEN 256
#define MAX_MODULE_NAME_LEN 64

// Event types for different tracepoints
enum event_type {
    // Process events
    EVENT_TYPE_EXECVE = 1,
    EVENT_TYPE_CLONE = 10,
    EVENT_TYPE_KILL = 11,
    EVENT_TYPE_PTRACE = 12,

    // File events
    EVENT_TYPE_OPEN = 2,
    EVENT_TYPE_UNLINK = 3,
    EVENT_TYPE_RENAME = 4,
    EVENT_TYPE_CHMOD = 5,

    // Network events
    EVENT_TYPE_CONNECT = 6,
    EVENT_TYPE_ACCEPT = 7,
    EVENT_TYPE_BIND = 8,
    EVENT_TYPE_SOCKET = 9,

    // Privilege escalation events (SOX/PCI compliance)
    EVENT_TYPE_SETUID = 20,
    EVENT_TYPE_SETGID = 21,
    EVENT_TYPE_SETREUID = 22,
    EVENT_TYPE_SETREGID = 23,

    // Mount events (SOX/PCI compliance)
    EVENT_TYPE_MOUNT = 30,
    EVENT_TYPE_UMOUNT = 31,

    // Module events (SOX/PCI compliance)
    EVENT_TYPE_INIT_MODULE = 40,
    EVENT_TYPE_FINIT_MODULE = 41,
    EVENT_TYPE_DELETE_MODULE = 42,

    // Memory events (code injection detection)
    EVENT_TYPE_MPROTECT = 50,
};

// execve_event is the event structure for process execution
struct execve_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    char args[MAX_ARGS_LEN];
    __u32 args_count;
    __u32 ret_code;
};

// file_event is the event structure for file operations (open, unlink, rename, chmod)
struct file_event {
    __u64 timestamp_ns;
    __u32 event_type;       // EVENT_TYPE_OPEN, UNLINK, RENAME, CHMOD
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    char filename2[MAX_FILENAME_LEN];  // For rename (new name)
    __s32 flags;            // Open flags or chmod mode
    __s32 ret_code;
};

// network_event is the event structure for network operations
struct network_event {
    __u64 timestamp_ns;
    __u32 event_type;       // EVENT_TYPE_CONNECT, ACCEPT, BIND, SOCKET
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    __u16 family;           // AF_INET, AF_INET6, AF_UNIX
    __u16 sport;            // Source port
    __u16 dport;            // Destination port
    __u16 protocol;         // IPPROTO_TCP, IPPROTO_UDP
    __u8 saddr[16];         // Source address (IPv4 in first 4 bytes, IPv6 full)
    __u8 daddr[16];         // Destination address
    __s32 ret_code;
};

// process_event is the event structure for process operations (clone, kill, ptrace)
struct process_event {
    __u64 timestamp_ns;
    __u32 event_type;       // EVENT_TYPE_CLONE, KILL, PTRACE
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    __u32 target_pid;       // Target PID for kill/ptrace
    __s32 sig;              // Signal number for kill
    __s32 ptrace_request;   // Ptrace request type
    __u64 clone_flags;      // Clone flags
    __s32 ret_code;
};

// privilege_event is the event structure for privilege escalation operations
struct privilege_event {
    __u64 timestamp_ns;
    __u32 event_type;       // EVENT_TYPE_SETUID, SETGID, SETREUID, SETREGID
    __u32 pid;
    __u32 ppid;
    __u32 uid;              // Current UID before change
    __u32 gid;              // Current GID before change
    char comm[TASK_COMM_LEN];
    __u32 new_uid;          // Target UID (for setuid/setreuid)
    __u32 new_gid;          // Target GID (for setgid/setregid)
    __u32 new_euid;         // Target effective UID (for setreuid)
    __u32 new_egid;         // Target effective GID (for setregid)
    __s32 ret_code;
};

// mount_event is the event structure for mount operations
struct mount_event {
    __u64 timestamp_ns;
    __u32 event_type;       // EVENT_TYPE_MOUNT, UMOUNT
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    char source[MAX_FILENAME_LEN];      // Source device/path
    char target[MAX_FILENAME_LEN];      // Mount point
    char fstype[32];                    // Filesystem type
    __u64 flags;                        // Mount flags
    __s32 ret_code;
};

// module_event is the event structure for kernel module operations
struct module_event {
    __u64 timestamp_ns;
    __u32 event_type;       // EVENT_TYPE_INIT_MODULE, FINIT_MODULE, DELETE_MODULE
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    char module_name[MAX_MODULE_NAME_LEN];
    __u64 module_size;      // Size of module (for init_module)
    __s32 flags;            // Module flags
    __s32 ret_code;
};

// memory_event is the event structure for memory protection changes
struct memory_event {
    __u64 timestamp_ns;
    __u32 event_type;       // EVENT_TYPE_MPROTECT
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    __u64 addr;             // Memory address
    __u64 len;              // Length of region
    __u32 prot;             // Protection flags (PROT_READ, PROT_WRITE, PROT_EXEC)
    __s32 ret_code;
};

#endif /* __COMMON_H */

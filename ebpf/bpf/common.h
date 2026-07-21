// SPDX-License-Identifier: GPL-2.0 OR MIT
// common.h - Shared structures between BPF programs and userspace

#ifndef __COMMON_H
#define __COMMON_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define MAX_RESOLVED_PATH 256
#define MAX_ARGS_LEN 512  // power of two — the execve argv loop masks offsets with (MAX_ARGS_LEN - 1)
#define MAX_CMDLINE_LEN 512
#define MAX_MODULE_NAME_LEN 64
#define MAX_CONTAINER_ID_LEN 72
#define PROCESS_CACHE_SIZE 32768

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
    EVENT_TYPE_CHOWN = 13,
    EVENT_TYPE_MKDIR = 14,
    EVENT_TYPE_RMDIR = 15,
    EVENT_TYPE_LINK = 16,
    EVENT_TYPE_SYMLINK = 17,
    EVENT_TYPE_SETXATTR = 18,
    EVENT_TYPE_REMOVEXATTR = 19,
    EVENT_TYPE_UTIMES = 25,

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
    EVENT_TYPE_MMAP = 51,

    // DNS events
    EVENT_TYPE_DNS_QUERY = 60,

    // Cloud IMDS events
    EVENT_TYPE_IMDS_ACCESS = 61,

    // BPF syscall events (rootkit detection)
    EVENT_TYPE_BPF_CMD = 70,

    // Fileless execution events
    EVENT_TYPE_MEMFD_CREATE = 71,
    EVENT_TYPE_EXECVEAT = 72,

    // io_uring events (seccomp bypass detection)
    EVENT_TYPE_IO_URING_SETUP = 80,
    EVENT_TYPE_IO_URING_REGISTER = 81,

    // Namespace events (container breakout detection)
    EVENT_TYPE_SETNS = 90,
    EVENT_TYPE_UNSHARE = 91,

    // Capability events (privilege abuse detection)
    EVENT_TYPE_CAPSET = 92,

    // Extended signal events
    EVENT_TYPE_TGKILL = 93,
    EVENT_TYPE_TKILL = 94,

    // Extended privilege events
    EVENT_TYPE_SETRESUID = 95,
    EVENT_TYPE_SETRESGID = 96,
    EVENT_TYPE_SETFSUID = 97,
    EVENT_TYPE_SETFSGID = 98,

    // Extended file events
    EVENT_TYPE_OPENAT2 = 100,
    EVENT_TYPE_OPEN_BY_HANDLE = 101,
    EVENT_TYPE_TRUNCATE = 102,
    EVENT_TYPE_FTRUNCATE = 103,

    // Data exfiltration events
    EVENT_TYPE_SPLICE = 110,
    EVENT_TYPE_SENDFILE = 111,
    EVENT_TYPE_COPY_FILE_RANGE = 112,
    EVENT_TYPE_TEE = 113,

    // Directory events
    EVENT_TYPE_CHDIR = 120,
    EVENT_TYPE_FCHDIR = 121,
    EVENT_TYPE_CHROOT = 122,
    EVENT_TYPE_PIVOT_ROOT = 123,

    // io_uring enter event
    EVENT_TYPE_IO_URING_ENTER = 82,

    // VFS hook events (kprobes)
    EVENT_TYPE_VFS_OPEN = 130,
    EVENT_TYPE_VFS_UNLINK = 131,
    EVENT_TYPE_VFS_RENAME = 132,
    EVENT_TYPE_INODE_SETATTR = 133,

    // Credential/exit events (kprobes)
    EVENT_TYPE_COMMIT_CREDS = 140,
    EVENT_TYPE_PROCESS_EXIT = 141,

    // Ioctl events
    EVENT_TYPE_IOCTL = 150,};

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
    __u32 ret_code;};

// file_event is the event structure for file operations
struct file_event {
    __u64 timestamp_ns;
    __u32 event_type;       // EVENT_TYPE_OPEN, UNLINK, RENAME, CHMOD, CHOWN, MKDIR, etc.
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    char filename2[MAX_FILENAME_LEN];  // rename:newname, link/symlink:target, xattr:name
    __s32 flags;            // Open flags, chmod/mkdir mode, xattr/utimes flags
    __s32 ret_code;
    __u32 new_uid;          // chown: target UID
    __u32 new_gid;          // chown: target GID
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

// memory_event is the event structure for memory protection changes and mappings
struct memory_event {
    __u64 timestamp_ns;
    __u32 event_type;       // EVENT_TYPE_MPROTECT or EVENT_TYPE_MMAP
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    __u64 addr;             // Memory address
    __u64 len;              // Length of region
    __u32 prot;             // Protection flags (PROT_READ, PROT_WRITE, PROT_EXEC)
    __s32 ret_code;
    __u32 flags;            // mmap flags (MAP_ANONYMOUS, MAP_PRIVATE, MAP_FIXED, etc.)
    __s32 fd;               // mmap file descriptor (-1 for anonymous)
};

// DNS constants
#define DNS_MAX_NAME_LEN 128
#define DNS_HEADER_SIZE 12

// dns_event is the event structure for DNS query monitoring
struct dns_event {
    __u64 timestamp_ns;
    __u32 event_type;               // EVENT_TYPE_DNS_QUERY
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    __u16 id;                       // DNS transaction ID
    __u16 qtype;                    // Query type (A=1, AAAA=28, etc.)
    __u16 qclass;                   // Query class (IN=1)
    __u16 family;                   // AF_INET or AF_INET6
    __u16 dport;                    // Destination port (53)
    __u16 name_len;                 // Actual length of decoded name
    __u8 daddr[16];                 // DNS server address
    char qname[DNS_MAX_NAME_LEN];   // Decoded DNS query name (dot-separated)
};

// imds_event is the event structure for cloud IMDS access detection
struct imds_event {
    __u64 timestamp_ns;
    __u32 event_type;               // EVENT_TYPE_IMDS_ACCESS
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    __u16 family;                   // AF_INET (IMDS is always IPv4)
    __u16 dport;                    // Destination port (80, 443)
    __u8 daddr[16];                 // Destination address (169.254.169.254)
};

// BPF_OBJ_NAME_LEN matches the kernel constant
#define BPF_OBJ_NAME_LEN_COMPAT 16

// bpf_syscall_event is the event structure for bpf() syscall monitoring
struct bpf_syscall_event {
    __u64 timestamp_ns;
    __u32 event_type;                       // EVENT_TYPE_BPF_CMD
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    __u32 cmd;                              // BPF command (BPF_MAP_CREATE, BPF_PROG_LOAD, etc.)
    __u32 prog_type;                        // bpf_prog_type for PROG_LOAD, bpf_map_type for MAP_CREATE
    __u32 insn_cnt;                         // Instruction count (PROG_LOAD only)
    __u32 attach_type;                      // expected_attach_type (PROG_LOAD only)
    char obj_name[BPF_OBJ_NAME_LEN_COMPAT]; // prog_name or map_name
};

// memfd name length (memfd names are typically short)
#define MEMFD_NAME_LEN 64

// memfd_event is the event structure for fileless execution monitoring
// Covers both memfd_create and execveat syscalls
struct memfd_event {
    __u64 timestamp_ns;
    __u32 event_type;               // EVENT_TYPE_MEMFD_CREATE or EVENT_TYPE_EXECVEAT
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    char name[MEMFD_NAME_LEN];      // memfd name (memfd_create) or pathname (execveat)
    __u32 flags;                    // MFD_* flags (memfd_create) or AT_* flags (execveat)
    __s32 fd;                       // dirfd for execveat (-1 for memfd_create)
};

// iouring_event is the event structure for io_uring monitoring
struct iouring_event {
    __u64 timestamp_ns;
    __u32 event_type;               // EVENT_TYPE_IO_URING_SETUP or _REGISTER
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    __u32 sq_entries;               // Number of SQ entries (setup)
    __u32 setup_flags;              // io_uring_params.flags (setup)
    __s32 fd;                       // io_uring fd (register)
    __u32 opcode;                   // IORING_REGISTER_* opcode (register)
    __u32 nr_args;                  // Number of args (register)
};

// namespace_event is the event structure for namespace operations (setns, unshare)
struct namespace_event {
    __u64 timestamp_ns;
    __u32 event_type;       // EVENT_TYPE_SETNS or EVENT_TYPE_UNSHARE
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    __s32 fd;               // setns: file descriptor for namespace (0 for unshare)
    __u32 nstype;           // setns: namespace type (CLONE_NEWPID, etc.)
    __u64 flags;            // unshare: unshare flags (CLONE_NEW* bitmask)
    __s32 ret_code;
};

// capset_event is the event structure for capability changes
struct capset_event {
    __u64 timestamp_ns;
    __u32 event_type;       // EVENT_TYPE_CAPSET
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    __u32 target_pid;       // PID targeted by capset (0 = self)
    __u32 cap_version;      // capability version from header
    __u64 cap_effective;    // effective capability bits (64-bit combined)
    __u64 cap_permitted;    // permitted capability bits (64-bit combined)
    __u64 cap_inheritable;  // inheritable capability bits (64-bit combined)
    __s32 ret_code;
};

// dataexfil_event for data exfiltration syscalls (splice, sendfile, etc.)
struct dataexfil_event {
    __u64 timestamp_ns;
    __u32 event_type;       // EVENT_TYPE_SPLICE, SENDFILE, COPY_FILE_RANGE, TEE
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    __s32 fd_in;            // Source file descriptor
    __s32 fd_out;           // Destination file descriptor
    __u64 len;              // Number of bytes to transfer
    __u32 flags;            // Splice/sendfile flags
    __s32 ret_code;
};

// dirops_event for directory operation syscalls (chdir, chroot, pivot_root)
struct dirops_event {
    __u64 timestamp_ns;
    __u32 event_type;       // EVENT_TYPE_CHDIR, FCHDIR, CHROOT, PIVOT_ROOT
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    char path[MAX_FILENAME_LEN];       // Target path
    char path2[MAX_FILENAME_LEN];      // pivot_root: put_old path
    __s32 fd;               // fchdir: directory fd
    __s32 ret_code;
};

// ioctl_event for security-relevant ioctl commands
struct ioctl_event {
    __u64 timestamp_ns;
    __u32 event_type;       // EVENT_TYPE_IOCTL
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    __s32 fd;               // File descriptor
    __u32 cmd;              // Ioctl command
    __u64 arg;              // Ioctl argument
    __s32 ret_code;
};

// vfs_event for VFS kprobe hooks
struct vfs_event {
    __u64 timestamp_ns;
    __u32 event_type;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    char path[MAX_FILENAME_LEN];
    char path2[MAX_FILENAME_LEN];       // rename: new path
    __u32 i_mode;           // File mode (from inode)
    __u32 i_uid;            // File owner UID
    __u64 i_ino;            // Inode number
    __s32 ret_code;
};

// cred_event for credential change kprobes
struct cred_event {
    __u64 timestamp_ns;
    __u32 event_type;       // EVENT_TYPE_COMMIT_CREDS or EVENT_TYPE_PROCESS_EXIT
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    __u32 new_uid;
    __u32 new_euid;
    __u32 new_gid;
    __u32 new_egid;
    __s32 exit_code;        // Process exit code (for do_exit)
    __s32 ret_code;
};

// ============================================================================
// Process Cache Structures
// ============================================================================

// Cached process information - populated on execve, looked up on other syscalls
struct process_info {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u64 start_time_ns;

    // Current process
    char comm[TASK_COMM_LEN];
    char exe[MAX_FILENAME_LEN];
    char cmdline[MAX_CMDLINE_LEN];

    // Parent process context
    __u32 parent_pid;
    char parent_comm[TASK_COMM_LEN];
    char parent_exe[MAX_FILENAME_LEN];

    // Grandparent (for full lineage)
    __u32 grandparent_pid;
    char grandparent_comm[TASK_COMM_LEN];

    // Container context
    char container_id[MAX_CONTAINER_ID_LEN];
    __u64 cgroup_id;
    __u64 ns_pid;    // PID namespace inode

    // Flags
    __u32 flags;};

// Process info flags
#define PROC_FLAG_IN_CONTAINER   (1 << 0)
#define PROC_FLAG_ROOT_USER      (1 << 1)
#define PROC_FLAG_PRIVILEGED     (1 << 2)

// Unified enriched security event - includes full process context
struct enriched_event {
    __u64 timestamp_ns;
    __u32 event_type;
    __u32 flags;

    // Current process context (from cache or direct)
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    char exe[MAX_FILENAME_LEN];
    char cmdline[MAX_CMDLINE_LEN];

    // Parent context
    char parent_comm[TASK_COMM_LEN];
    char parent_exe[MAX_FILENAME_LEN];

    // Grandparent context
    __u32 grandparent_pid;
    char grandparent_comm[TASK_COMM_LEN];

    // Container context
    char container_id[MAX_CONTAINER_ID_LEN];
    __u64 cgroup_id;

    // Event-specific data
    union {
        // Privilege escalation
        struct {
            __u32 old_uid;
            __u32 new_uid;
            __u32 old_euid;
            __u32 new_euid;
            __u32 old_gid;
            __u32 new_gid;
        } privilege;

        // Mount operations
        struct {
            char source[MAX_FILENAME_LEN];
            char target[MAX_FILENAME_LEN];
            char fstype[32];
            __u64 mount_flags;
        } mount;

        // Module operations
        struct {
            char module_name[MAX_MODULE_NAME_LEN];
            __u64 module_size;
            __s32 module_flags;
        } module;

        // Memory protection
        struct {
            __u64 addr;
            __u64 len;
            __u32 prot;
            __u32 old_prot;
        } memory;

        // Process operations (ptrace, kill)
        struct {
            __u32 target_pid;
            __s32 sig;
            __s32 ptrace_request;
        } process;

        // File operations
        struct {
            char filename[MAX_FILENAME_LEN];
            char filename2[MAX_FILENAME_LEN];
            __s32 file_flags;
        } file;

        // Network operations
        struct {
            __u16 family;
            __u16 sport;
            __u16 dport;
            __u16 protocol;
            __u8 saddr[16];
            __u8 daddr[16];
        } network;
    };

    __s32 ret_code;
};

#endif /* __COMMON_H */

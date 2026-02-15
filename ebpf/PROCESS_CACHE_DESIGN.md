# Process Cache Architecture for eBPF Agent

## Current Problem

Events like `runc:[2:INIT] called setuid to UID 0` lack context because:
1. Each syscall is captured independently without correlation
2. Only `comm` (16 chars max) is captured, not full cmdline or exe path
3. No process lineage - we don't know what spawned this process
4. No way to correlate related syscalls from the same process tree

## Solution: In-Kernel Process Cache

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           BPF Kernel Space                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    PROCESS_CACHE (BPF Hash Map)                   │   │
│  │                                                                    │   │
│  │  Key: PID (u32)                                                   │   │
│  │  Value: process_info {                                            │   │
│  │    pid, ppid, uid, gid, start_time                               │   │
│  │    comm[16], exe[256], cmdline[512]                              │   │
│  │    parent_comm[16], parent_exe[256]                              │   │
│  │    grandparent_pid, grandparent_comm[16]                         │   │
│  │    container_id[64], cgroup_id                                   │   │
│  │  }                                                                │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│           ▲                                    │                         │
│           │ populate on                        │ lookup on               │
│           │ sched_process_exec                 │ other syscalls          │
│           │                                    ▼                         │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────────┐    │
│  │ sched_process_ │  │ sched_process_ │  │ setuid/mount/module/   │    │
│  │ exec           │  │ exit           │  │ mprotect handlers      │    │
│  │ (populate)     │  │ (cleanup)      │  │ (lookup + emit)        │    │
│  └────────────────┘  └────────────────┘  └────────────────────────┘    │
│           │                  │                       │                   │
│           └──────────────────┴───────────────────────┘                  │
│                              │                                           │
│                              ▼                                           │
│                    ┌───────────────────┐                                │
│                    │   events ringbuf  │ (enriched events)              │
│                    └───────────────────┘                                │
│                              │                                           │
└──────────────────────────────┼───────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          Go Userspace                                    │
├─────────────────────────────────────────────────────────────────────────┤
│  - Receive enriched events with full process context                    │
│  - Decision making with complete picture                                 │
│  - Alert correlation and deduplication                                   │
└─────────────────────────────────────────────────────────────────────────┘
```

### Key Components

#### 1. Process Cache Map (BPF Hash Map)

```c
#define MAX_EXE_LEN 256
#define MAX_CMDLINE_LEN 512
#define MAX_CONTAINER_ID_LEN 64
#define PROCESS_CACHE_SIZE 65536

// Cached process information
struct process_info {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u64 start_time_ns;

    // Current process
    char comm[TASK_COMM_LEN];
    char exe[MAX_EXE_LEN];
    char cmdline[MAX_CMDLINE_LEN];

    // Parent process context
    __u32 parent_pid;
    char parent_comm[TASK_COMM_LEN];
    char parent_exe[MAX_EXE_LEN];

    // Grandparent (for full lineage)
    __u32 grandparent_pid;
    char grandparent_comm[TASK_COMM_LEN];

    // Container context
    char container_id[MAX_CONTAINER_ID_LEN];
    __u64 cgroup_id;

    // Flags
    __u32 flags;  // In container, has network namespace, etc.
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PROCESS_CACHE_SIZE);
    __type(key, __u32);   // PID
    __type(value, struct process_info);
} process_cache SEC(".maps");
```

#### 2. Process Lifecycle Tracking

**On sched_process_exec (or sys_exit_execve):**
```c
SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct process_info info = {};
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Fill current process info
    info.pid = pid;
    info.start_time_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    // Read exe path from ctx->filename
    bpf_probe_read_kernel_str(&info.exe, sizeof(info.exe), ctx->filename);

    // Read cmdline from /proc/self/cmdline equivalent
    // (using task_struct->mm->arg_start/arg_end)

    // Get parent info from process_cache (if parent was tracked)
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    info.ppid = ppid;

    struct process_info *parent = bpf_map_lookup_elem(&process_cache, &ppid);
    if (parent) {
        __builtin_memcpy(&info.parent_comm, &parent->comm, TASK_COMM_LEN);
        __builtin_memcpy(&info.parent_exe, &parent->exe, MAX_EXE_LEN);
        info.grandparent_pid = parent->ppid;
        __builtin_memcpy(&info.grandparent_comm, &parent->parent_comm, TASK_COMM_LEN);
    }

    // Get container ID from cgroup path
    info.cgroup_id = bpf_get_current_cgroup_id();

    // Store in cache
    bpf_map_update_elem(&process_cache, &pid, &info, BPF_ANY);

    return 0;
}
```

**On sched_process_exit:**
```c
SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&process_cache, &pid);
    return 0;
}
```

#### 3. Enriched Event Structure

```c
// New unified event with full context
struct security_event {
    __u64 timestamp_ns;
    __u32 event_type;

    // Current process (from cache)
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    char exe[MAX_EXE_LEN];
    char cmdline[MAX_CMDLINE_LEN];

    // Parent context
    char parent_comm[TASK_COMM_LEN];
    char parent_exe[MAX_EXE_LEN];

    // Grandparent context
    __u32 grandparent_pid;
    char grandparent_comm[TASK_COMM_LEN];

    // Container context
    char container_id[MAX_CONTAINER_ID_LEN];
    __u64 cgroup_id;

    // Event-specific data (union)
    union {
        struct {
            __u32 new_uid;
            __u32 new_euid;
        } privilege;
        struct {
            char source[MAX_FILENAME_LEN];
            char target[MAX_FILENAME_LEN];
            char fstype[32];
            __u64 flags;
        } mount;
        struct {
            char module_name[MAX_MODULE_NAME_LEN];
            __u64 module_size;
        } module;
        struct {
            __u64 addr;
            __u64 len;
            __u32 prot;
        } memory;
    };

    __s32 ret_code;
};
```

#### 4. Example: Enriched setuid Handler

```c
SEC("tracepoint/syscalls/sys_enter_setuid")
int handle_setuid(struct trace_event_raw_sys_enter *ctx) {
    struct security_event *event;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 new_uid = (__u32)ctx->args[0];

    // Skip if not escalating to root (or other high-value targets)
    if (new_uid != 0) {
        return 0;
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_SETUID;
    event->pid = pid;
    event->privilege.new_uid = new_uid;

    // Lookup cached process info
    struct process_info *proc = bpf_map_lookup_elem(&process_cache, &pid);
    if (proc) {
        // Copy full context from cache
        event->ppid = proc->ppid;
        event->uid = proc->uid;
        event->gid = proc->gid;
        __builtin_memcpy(&event->comm, &proc->comm, TASK_COMM_LEN);
        __builtin_memcpy(&event->exe, &proc->exe, MAX_EXE_LEN);
        __builtin_memcpy(&event->cmdline, &proc->cmdline, MAX_CMDLINE_LEN);
        __builtin_memcpy(&event->parent_comm, &proc->parent_comm, TASK_COMM_LEN);
        __builtin_memcpy(&event->parent_exe, &proc->parent_exe, MAX_EXE_LEN);
        event->grandparent_pid = proc->grandparent_pid;
        __builtin_memcpy(&event->grandparent_comm, &proc->grandparent_comm, TASK_COMM_LEN);
        __builtin_memcpy(&event->container_id, &proc->container_id, MAX_CONTAINER_ID_LEN);
        event->cgroup_id = proc->cgroup_id;
    } else {
        // Fallback: get basic info directly
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}
```

### Example Output

**Before (current):**
```
Process runc:[2:INIT] (pid=455039) called setuid to UID 0 [ESCALATION TO ROOT]
```

**After (with process cache):**
```
Privilege Escalation: setuid to UID 0

Process Context:
  PID: 455039
  Exe: /usr/bin/runc
  Cmdline: runc init
  User: root (uid=0, was uid=1000)
  CWD: /run/containerd/io.containerd.runtime.v2.task/moby/abc123def456

Parent Context:
  PPID: 455020
  Exe: /usr/bin/containerd-shim-runc-v2
  Comm: containerd-shim

Grandparent:
  PID: 1234
  Comm: containerd

Container Context:
  Container ID: abc123def456789...
  Cgroup: docker/abc123...

[ESCALATION TO ROOT - Container initialization by containerd - EXPECTED]
```

### Implementation Phases

#### Phase 1: Process Cache Infrastructure
1. Create new `process_cache.bpf.c` with process_info struct and map
2. Add `sched_process_exec` handler to populate cache
3. Add `sched_process_exit` handler to cleanup
4. Add shared map in vmlinux.h or common.h

#### Phase 2: Update Event Emitters
1. Create unified `security_event` structure
2. Update privilege.bpf.c to lookup process cache
3. Update module.bpf.c, mount.bpf.c, memory.bpf.c
4. Single ring buffer for all enriched events

#### Phase 3: Go-side Updates
1. Update bpfgen to generate new structures
2. Single event reader with type switching
3. Rich event formatting with full context
4. Intelligent filtering based on process lineage

#### Phase 4: Intelligent Alerting
1. Allow-list known patterns (containerd -> runc init -> setuid)
2. Alert on unexpected privilege escalations
3. Correlate events from same process tree
4. Aggregate rapid-fire events

### Kernel Requirements
- Linux 5.8+ for ring buffers
- Linux 5.8+ for BPF_MAP_TYPE_HASH in tracepoints
- BTF support for CO-RE

### References
- Linux kernel BPF documentation: https://docs.kernel.org/bpf/

---

## Build Instructions

### Prerequisites
- Linux kernel 5.8+ with BTF support
- clang (for BPF compilation)
- llvm (for BPF target)
- bpf2go: `go install github.com/cilium/ebpf/cmd/bpf2go@latest`

### Generate BPF Objects

```bash
# Generate vmlinux.h if not present
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/bpf/vmlinux.h

# Generate Go bindings from BPF C code
cd apagent
go generate ./ebpf/bpfgen/...

# Build the agent
go build ./...
```

### Testing the Enriched Agent

```go
import "apagent/ebpf"

// Create enriched agent instead of basic native agent
agent, err := ebpf.NewNativeEnrichedAgent()
if err != nil {
    log.Fatal(err)
}

// Start the agent
if err := agent.Start(context.Background()); err != nil {
    log.Fatal(err)
}

// Start event listener
if err := agent.StartEventListener(context.Background()); err != nil {
    log.Fatal(err)
}

// Read events
for event := range agent.EventChannel() {
    fmt.Printf("Event: %s\n", event.Output)
    fmt.Printf("Process: %s (PID: %d)\n", event.Process.Name, event.Process.PID)
    fmt.Printf("Exe: %s\n", event.Process.ExePath)
    fmt.Printf("Cmdline: %s\n", event.Process.Cmdline)
    fmt.Printf("Parent: %s\n", event.Process.ParentName)
}
```

### Files Added/Modified

**New BPF Programs:**
- `bpf/process_cache.bpf.c` - Process lifecycle tracking (exec, exit, fork)
- `bpf/privilege_enriched.bpf.c` - Enriched privilege escalation with process context

**New Go Files:**
- `enriched_events.go` - Go types for parsing enriched BPF events
- `native_enriched.go` - Enriched native agent implementation

**Modified Files:**
- `bpf/common.h` - Added process_info and enriched_event structures
- `bpfgen/generate.go` - Added generate directives for new BPF programs
- `bpfgen/exports.go` - Added exports for new BPF types

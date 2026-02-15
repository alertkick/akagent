# eBPF Subsystem Architecture

## Overview

The `apagent/ebpf/` package implements a kernel-level security monitoring agent using Linux eBPF. It instruments ~60 syscalls and kernel functions via tracepoints and kprobes to capture security-relevant events (process execution, file operations, network connections, privilege escalation, etc.) with minimal overhead.

Events are captured in kernel space, filtered in-kernel via discarder maps and CDE scope maps, then delivered to userspace Go code via ring buffers (kernel 5.8+) or perf event arrays (kernel 5.5+ fallback).

---

## Directory Structure

```
apagent/ebpf/
  bpf/                      # BPF C source files + shared headers
    *.bpf.c                  # BPF programs (compiled to .o by clang)
    *.h                      # Shared headers (structs, helpers, macros)
    vmlinux.h                # Kernel type definitions (generated from BTF)
  bpfgen/                    # Auto-generated Go bindings (bpf2go output)
    generate.go              # go:generate directives for all programs
    *_bpfel.go / *_bpfeb.go  # Generated Go loaders (little/big endian)
    *_bpfel.o / *_bpfeb.o    # Compiled BPF ELF objects (embedded in Go)
    types.go                 # Shared type aliases
  *.go                       # Go orchestration code
```

---

## Data Flow

```
                        KERNEL SPACE                          USER SPACE
 ┌─────────────────────────────────────────────┐    ┌──────────────────────────────┐
 │                                             │    │                              │
 │  Syscall / Kprobe fires                     │    │                              │
 │       │                                     │    │                              │
 │       v                                     │    │                              │
 │  ┌──────────────┐                           │    │                              │
 │  │ should_      │──discard──> (dropped)     │    │                              │
 │  │ discard()    │                           │    │                              │
 │  └──────┬───────┘                           │    │                              │
 │         │ pass                               │    │                              │
 │         v                                   │    │                              │
 │  ┌──────────────┐                           │    │                              │
 │  │ EVENT_OUTPUT │  ringbuf_reserve /        │    │                              │
 │  │ _BEGIN()     │  map_lookup_elem          │    │                              │
 │  └──────┬───────┘                           │    │                              │
 │         │                                   │    │                              │
 │         v                                   │    │                              │
 │  Fill event struct                          │    │                              │
 │  (pid, uid, comm, syscall args)             │    │                              │
 │         │                                   │    │                              │
 │         v                                   │    │                              │
 │  ┌──────────────┐                           │    │                              │
 │  │ check_cde_   │──filter──> (dropped)      │    │                              │
 │  │ scope()      │                           │    │                              │
 │  └──────┬───────┘                           │    │                              │
 │         │ pass                               │    │                              │
 │         v                                   │    │                              │
 │  ┌──────────────┐    Ring Buffer / Perf     │    │  ┌────────────────────┐      │
 │  │ EVENT_OUTPUT │ ═══════════════════════════╪═══>│  │ EventReader.Read() │      │
 │  │ _END()       │    (shared memory)        │    │  └────────┬───────────┘      │
 │  └──────────────┘                           │    │           │                  │
 │                                             │    │           v                  │
 │                                             │    │  parse*Event() → SecurityEvent│
 │                                             │    │           │                  │
 │                                             │    │           v                  │
 │                                             │    │  EventFilter / AlertFilter   │
 │                                             │    │  RateLimiter / RuleEngine    │
 │                                             │    │           │                  │
 │                                             │    │           v                  │
 │                                             │    │  eventChan → Kafka / API     │
 └─────────────────────────────────────────────┘    └──────────────────────────────┘
```

### Step-by-step

1. **Syscall fires** - Kernel hits a tracepoint (e.g., `sys_enter_execve`) or kprobe (e.g., `security_bpf`)
2. **Discard check** - `should_discard()` checks PID, comm name, and category discard maps. Excluded events are dropped before any ring buffer allocation.
3. **Event allocation** - `EVENT_OUTPUT_BEGIN()` reserves space in the ring buffer (or gets per-CPU scratch space for perf mode)
4. **Event population** - BPF program fills the event struct with process info, syscall arguments, etc.
5. **CDE scope tagging** - `check_cde_scope()` tags the event with CDE boundary flags (network/file/process/uid match). If filter mode is active, non-CDE events are dropped.
6. **Event submission** - `EVENT_OUTPUT_END()` submits to the ring buffer or perf event array
7. **Userspace read** - Go `EventReader` (wrapping `ringbuf.Reader` or `perf.Reader`) blocks until events arrive
8. **Parsing** - `parse*Event()` in `native_parsers.go` deserializes raw bytes into `SecurityEvent` structs
9. **Filtering & enrichment** - Events pass through `EventFilter`, `AlertFilter`, `RateLimiter`, and `RuleEngine`
10. **Delivery** - Events are sent to `eventChan` for consumption by the endpoint (Kafka/API)

---

## BPF C Source Files (`bpf/`)

### Shared Headers

| File | Purpose |
|------|---------|
| `vmlinux.h` | Kernel type definitions (BTF-generated). All kernel structs like `task_struct`, `dentry`, etc. |
| `common.h` | All event struct definitions (`execve_event`, `file_event`, `network_event`, etc.), event type enums, process cache structs (`process_info`, `enriched_event`) |
| `discarders.h` | In-kernel event filtering. Declares `discard_config`, `discard_comms`, `discard_pids`, `discard_stats` maps and `should_discard()` helper |
| `cde_scope.h` | PCI CDE boundary tagging. Declares `cde_config`, `cde_networks` (LPM trie), `cde_files`, `cde_comms`, `cde_uids` maps and `check_cde_scope()` helper |
| `output.h` | Output abstraction layer. Compile-time switch between ring buffer (`BPF_MAP_TYPE_RINGBUF`) and perf event array (`BPF_MAP_TYPE_PERF_EVENT_ARRAY`) via `USE_PERF_OUTPUT` define. Provides `EVENT_OUTPUT_BEGIN/END/DISCARD` macros. |
| `syscall_context.h` | Enter/exit syscall correlation. `DECLARE_SYSCALL_CONTEXT` creates per-PID LRU hash maps. `SYSCALL_CTX_SAVE/LOAD` macros store args on enter, retrieve on exit. |
| `dentry.h` | Kernel dentry path resolution. Walks `d_parent` chain to build absolute paths from kernel `struct dentry`. Uses per-CPU scratch maps to avoid stack overflow. |

### Standard BPF Programs

Each `.bpf.c` is compiled into **3 variants** via `bpf2go`: **ringbuf** (default), **perf** (`-DUSE_PERF_OUTPUT`), and for some files, **enriched** (separate `*_enriched.bpf.c`).

| File | Tracepoints / Hooks | Event Struct | Maps | Enriched? | Purpose |
|------|---------------------|--------------|------|-----------|---------|
| `execve.bpf.c` | `sys_enter_execve`, `sys_exit_execve` | `execve_event` | `events` (ringbuf), `execve_context` (LRU hash) | No | Process execution monitoring. Captures filename, args, return code. |
| `fileops.bpf.c` | `sys_enter_openat`, `sys_enter_unlinkat`, `sys_enter_renameat2`, `sys_enter_fchmodat`, `sys_enter_fchownat`, `sys_enter_mkdirat`, `sys_enter_linkat`, `sys_enter_symlinkat`, `sys_enter_fsetxattr`, `sys_enter_fremovexattr`, `sys_enter_utimensat`, `sys_enter_openat2`, `sys_enter_open_by_handle_at`, `sys_enter_truncate`, `sys_enter_ftruncate` | `file_event` | `file_events` (ringbuf) | Yes (`fileops_enriched.bpf.c`) | File operation monitoring. 15 syscalls covering open, delete, rename, chmod, chown, mkdir, link, symlink, xattr, truncate. |
| `network.bpf.c` | `sys_enter_connect`, `sys_exit_connect`, `sys_enter_accept4`, `sys_enter_bind`, `sys_enter_socket` | `network_event` | `network_events` (ringbuf), `connect_context` (LRU hash) | Yes (`network_enriched.bpf.c`) | Network operation monitoring. Parses sockaddr for address/port. Uses enter/exit correlation for connect return codes. |
| `process.bpf.c` | `sys_enter_clone`, `sys_enter_kill`, `sys_enter_ptrace`, `sys_enter_tgkill`, `sys_enter_tkill` | `process_event` | `process_events` (ringbuf) | No | Process lifecycle. Clone (fork), signal sending, ptrace (debugger attach). |
| `privilege.bpf.c` | `sys_enter_setuid`, `sys_enter_setgid`, `sys_enter_setreuid`, `sys_enter_setregid`, `sys_enter_setresuid`, `sys_enter_setresgid`, `sys_enter_setfsuid`, `sys_enter_setfsgid` | `privilege_event` | `privilege_events` (ringbuf) | Yes (`privilege_enriched.bpf.c`) | Privilege escalation detection (SOX/PCI). 8 set*id syscalls. |
| `mount.bpf.c` | `sys_enter_mount`, `sys_enter_umount2` | `mount_event` | `mount_events` (ringbuf) | Yes (`mount_enriched.bpf.c`) | Filesystem mount/unmount (SOX/PCI compliance). |
| `module.bpf.c` | `sys_enter_init_module`, `sys_enter_finit_module`, `sys_enter_delete_module` | `module_event` | `module_events` (ringbuf) | Yes (`module_enriched.bpf.c`) | Kernel module load/unload (rootkit detection). |
| `memory.bpf.c` | `sys_enter_mprotect`, `sys_enter_mmap` | `memory_event` | `memory_events` (ringbuf) | Yes (`memory_enriched.bpf.c`) | Memory protection changes (code injection detection). Flags W+X transitions. |
| `dns.bpf.c` | `sys_enter_sendto`, `sys_enter_sendmsg` | `dns_event` | `dns_events` (ringbuf) | No | DNS query monitoring. Parses DNS wire format to extract query names. Filters for port 53 packets. |
| `imds.bpf.c` | `sys_enter_connect` | `imds_event` | `imds_events` (ringbuf) | No | Cloud IMDS access detection. Flags connections to `169.254.169.254` (AWS/GCP/Azure metadata service). |
| `bpfsyscall.bpf.c` | `sys_enter_bpf` | `bpf_syscall_event` | `bpf_events` (ringbuf) | No | BPF syscall monitoring (rootkit detection). Captures `BPF_PROG_LOAD`, `BPF_MAP_CREATE`, etc. |
| `memfd.bpf.c` | `sys_enter_memfd_create`, `sys_enter_execveat` | `memfd_event` | `memfd_events` (ringbuf) | No | Fileless malware detection. `memfd_create` + `execveat(AT_EMPTY_PATH)` is the primary fileless execution vector. |
| `iouring.bpf.c` | `sys_enter_io_uring_setup`, `sys_enter_io_uring_register`, `sys_enter_io_uring_enter` | `iouring_event` | `iouring_events` (ringbuf) | No | io_uring monitoring (seccomp bypass detection). |
| `namespace.bpf.c` | `sys_enter_setns`, `sys_enter_unshare` | `namespace_event` | `namespace_events` (ringbuf) | No | Namespace manipulation (container breakout detection). |
| `caps.bpf.c` | `sys_enter_capset` | `capset_event` | `caps_events` (ringbuf) | No | Capability changes (privilege abuse detection). |
| `dataexfil.bpf.c` | `sys_enter_splice`, `sys_enter_sendfile64`, `sys_enter_copy_file_range`, `sys_enter_tee` | `dataexfil_event` | `dataexfil_events` (ringbuf) | No | Data exfiltration detection. Zero-copy transfer syscalls. |
| `dirops.bpf.c` | `sys_enter_chdir`, `sys_enter_fchdir`, `sys_enter_chroot`, `sys_enter_pivot_root` | `dirops_event` | `dirops_events` (ringbuf) | No | Directory operations (container escape via chroot/pivot_root). |
| `vfs_hooks.bpf.c` | kprobes: `vfs_open`, `vfs_unlink`, `vfs_rename`, `security_inode_setattr` | `vfs_event` | `vfs_events` (ringbuf), dentry scratch | No | VFS-level monitoring via kprobes. Provides reliable full paths via dentry resolution. Optional (requires kernel CO-RE compatibility). |
| `cred_hooks.bpf.c` | kprobes: `commit_creds`, `do_exit` | `cred_event` | `cred_events` (ringbuf) | No | Credential change monitoring. Catches uid/gid changes that bypass set*id syscalls. Process exit tracking. Optional (requires kprobe support). |
| `ioctl.bpf.c` | `sys_enter_ioctl` | `ioctl_event` | `ioctl_events` (ringbuf) | No | Security-relevant ioctl commands (TIOCSTI terminal injection, loop device setup, etc.). Filtered to ~7 specific commands. |
| `process_cache.bpf.c` | `sched_process_exec` (tracepoint), `sched_process_exit` (tracepoint) | `process_info`, `enriched_event` | `process_cache` (hash), `enriched_events` (ringbuf), `proc_info_scratch`, `dentry_scratch` | N/A (IS the cache) | Process lifecycle cache. Populates on exec with full process context (exe path, cmdline, parent/grandparent lineage, container ID). Cleaned up on exit. Shared with enriched programs via map pinning. |

### Enriched BPF Programs

Enriched variants (`*_enriched.bpf.c`) emit the unified `enriched_event` struct instead of per-subsystem structs. They look up the `process_cache` map to include full process lineage (exe, cmdline, parent, grandparent, container ID).

| File | Standard Equivalent | Extra Context |
|------|-------------------|---------------|
| `fileops_enriched.bpf.c` | `fileops.bpf.c` | Full process lineage + container context for file events |
| `network_enriched.bpf.c` | `network.bpf.c` | Full process lineage for network events |
| `privilege_enriched.bpf.c` | `privilege.bpf.c` | Full process lineage for privilege changes |
| `mount_enriched.bpf.c` | `mount.bpf.c` | Full process lineage for mount operations |
| `module_enriched.bpf.c` | `module.bpf.c` | Full process lineage for module operations |
| `memory_enriched.bpf.c` | `memory.bpf.c` | Full process lineage for memory operations |

---

## Compilation & Code Generation (`bpfgen/`)

### How It Works

`generate.go` contains `//go:generate` directives that invoke `bpf2go` from the `cilium/ebpf` library. Running `go generate ./...` in `bpfgen/` does the following for each program:

1. **Compiles** the `.bpf.c` file with `clang` targeting the BPF architecture
2. **Generates** Go source files (`*_bpfel.go` for little-endian, `*_bpfeb.go` for big-endian)
3. **Embeds** the compiled `.o` ELF binary into the Go source via `//go:embed`
4. **Creates** type-safe Go structs for BPF maps, programs, and C types

### Variant Matrix

Each standard `.bpf.c` produces **4 files** (2 endianness x 2 output modes):

| Source | Ringbuf Variant | Perf Variant |
|--------|----------------|--------------|
| `execve.bpf.c` | `Execve` | `Perfexecve` |
| `fileops.bpf.c` | `Fileops` | `Perffileops` |
| `network.bpf.c` | `Network` | `Perfnetwork` |
| ... | ... | ... |

Enriched programs are **ringbuf-only** (no perf variants):
| Source | Variant |
|--------|---------|
| `process_cache.bpf.c` | `Processcache` |
| `privilege_enriched.bpf.c` | `Privilegeenriched` |
| `network_enriched.bpf.c` | `Networkenriched` |
| ... | ... |

### Total Generated Files

- **20 standard programs** x 2 output modes x 2 endianness = **80 generated .go files**
- **7 enriched programs** x 1 output mode x 2 endianness = **14 generated .go files**
- **20 standard programs** x 2 output modes x 2 endianness = **80 .o files**
- **7 enriched programs** x 2 endianness = **14 .o files**
- **Total: ~94 generated .go files + ~94 .o files**

---

## Go Orchestration Code

### Agent Types

| File | Type | Description |
|------|------|-------------|
| `interface.go` | `EBPFAgent` interface | Common interface: Start/Stop, event listener, config, rules, service management |
| `native.go` | `NativeEBPFAgent` | **Primary agent**. Uses standard per-subsystem event structs. Supports both ringbuf and perf output. Production agent. |
| `native_enriched.go` | `NativeEnrichedAgent` | **Next-gen agent** (build tag: `enriched`). Uses process cache + enriched event structs. Ringbuf only. |

### Lifecycle Files

| File | Responsibility |
|------|---------------|
| `native.go` | Agent struct, `Start()` / `Stop()` orchestration, config management |
| `native_load.go` | `loadAllPrograms()` - loads all BPF objects (ringbuf or perf variant based on kernel). `pinAllPrograms()` - pins to `/sys/fs/bpf/alertpriority/`. `closeAllObjects()` - cleanup. |
| `native_attach.go` | `attachAllTracepoints()` - attaches BPF programs to tracepoints/kprobes using `cilium/ebpf/link`. ~25,000 lines handling all tracepoint attachments for both perf and ringbuf variants. |
| `native_readers.go` | `StartEventListener()` - creates `EventReader` for each program's output map, spawns goroutines that loop reading events. `StopEventListener()` - closes all readers. |
| `native_parsers.go` | `parse*Event()` functions - deserializes raw BPF event bytes into `SecurityEvent` structs. One parser per event type. |

### Event Processing Pipeline

| File | Responsibility |
|------|---------------|
| `events.go` | `SecurityEvent` struct definition (unified output format), priority levels, process/network/file/container/k8s context structs |
| `enriched_events.go` | Parsers for enriched event format (enriched_event union → SecurityEvent) |
| `enrichment.go` | `EventEnricher` - userspace enrichment of events (username lookup, additional process info). Supplements in-kernel data. |
| `filter.go` | `EventFilter` - userspace event filtering based on config (min priority, category enable/disable) |
| `alert_filter.go` | `AlertFilter` - rule-based alert classification. Integrates with `RuleEngine`. |
| `rate_limiter.go` | `RateLimiter` - prevents event flooding. Per-rule rate limiting with configurable windows. |
| `rules/` | `RuleEngine`, `Parser`, `Macros`, `Lists` - compliance rule evaluation engine. Loaded from profile JSON via `refresh_compliance` API command. |

### In-Kernel Filtering Management

| File | Responsibility |
|------|---------------|
| `discarder_manager.go` | `DiscarderManager` - Go-side management of discarder BPF maps. Syncs config (excluded PIDs, comm names, disabled categories) into kernel maps across all loaded programs. |
| `cde_scope_manager.go` | `CDEScopeManager` - Go-side management of CDE scope BPF maps. Pushes CDE boundary config (CIDRs, file paths, process names, UIDs) into LPM trie and hash maps. |
| `bpf_pin.go` | `BPFPinManager` - Pins BPF programs to `/sys/fs/bpf/alertpriority/` for lifecycle management. Programs persist across agent restarts. |

### Support Files

| File | Responsibility |
|------|---------------|
| `kernel.go` | `KernelSupport` - feature detection (kernel version, ringbuf/perf support, tracepoint/kprobe support, BPF permissions) |
| `event_reader.go` | `EventReader` interface with `ringbufEventReader` and `perfEventReader` implementations. Abstracts the difference between ring buffer and perf event array reads. |
| `native_config.go` | `NativeConfig` - agent configuration (categories, rate limits, enrichment, discarders, CDE scope). Load/save/merge/validate. |
| `native_lists.go` | Built-in exclusion lists (known-safe processes, common system comms to exclude). |

---

## Three-Tier Agent Architecture

The system supports three program compilation tiers:

### Tier 1: Standard + Ringbuf (default, kernel 5.8+)
- Uses `BPF_MAP_TYPE_RINGBUF` for zero-copy event delivery
- Single shared ring buffer per subsystem across all CPUs
- Reservation-based API (no copy on submit)
- `NativeEBPFAgent` with per-subsystem event structs

### Tier 2: Standard + Perf (fallback, kernel 5.5-5.7)
- Uses `BPF_MAP_TYPE_PERF_EVENT_ARRAY` with per-CPU scratch maps
- `bpf_perf_event_output()` copies events to per-CPU ring buffers
- Slightly higher overhead than ringbuf
- Same `NativeEBPFAgent` with identical parsers

### Tier 3: Enriched + Ringbuf (build tag `enriched`)
- Uses `process_cache` BPF map shared across programs
- Emits unified `enriched_event` struct with full process lineage
- `NativeEnrichedAgent` with enriched event parsers
- Ringbuf only (no perf variant)

---

## Redundancies & Optimization Opportunities

### 1. Standard vs Enriched Duplication (HIGH IMPACT)

**Problem:** 6 subsystems have both standard and enriched `.bpf.c` files with heavily duplicated logic:
- `fileops.bpf.c` / `fileops_enriched.bpf.c`
- `network.bpf.c` / `network_enriched.bpf.c`
- `privilege.bpf.c` / `privilege_enriched.bpf.c`
- `mount.bpf.c` / `mount_enriched.bpf.c`
- `module.bpf.c` / `module_enriched.bpf.c`
- `memory.bpf.c` / `memory_enriched.bpf.c`

Each pair shares ~80% of the same code (discard checks, sockaddr parsing, common field population). Only the event struct and process context filling differ.

**Optimization:** Unify into a single `.bpf.c` per subsystem using a compile-time `#ifdef USE_ENRICHED` flag (like `USE_PERF_OUTPUT`). The `fill_common` helper can be split into `fill_standard` and `fill_enriched` behind the ifdef. This would:
- Eliminate 6 source files (~2000 lines of duplicated C)
- Reduce generated Go/binary file count by 14 files
- Ensure bug fixes apply to both variants simultaneously

### 2. Perf + Ringbuf Variant Explosion (HIGH IMPACT)

**Problem:** Every standard program is compiled twice (ringbuf and perf), generating **40 extra Go/object files** for the perf variants. This doubles the binary size of the embedded BPF objects. The agent only loads ONE variant at runtime based on kernel support.

**Current state:** 20 programs x 2 output modes x 2 endianness = 80 .o files embedded in the binary.

**Optimization options:**
- **Runtime compilation:** Ship only source and compile on first start (used by Cilium). Too complex for this use case.
- **Drop big-endian:** If only targeting x86_64/arm64 (little-endian), drop `bpfeb` targets. Saves 50% of generated files.
- **Drop perf for newer subsystems:** Programs like `ioctl`, `iouring`, `namespace`, `caps`, `dataexfil`, `dirops`, `vfshooks`, `credhooks` were added recently and target kernel 5.8+. They don't need perf variants. Could save 16 .o files.

### 3. `fill_common_*` Helper Duplication (MEDIUM IMPACT)

**Problem:** Almost every `.bpf.c` file has its own `fill_common_*` helper that does the same thing:
```c
static __always_inline void fill_common_X(struct X_event *event, ...) {
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    pid_tgid = bpf_get_current_pid_tgid();
    event->pid = (u32)(pid_tgid >> 32);
    uid_gid = bpf_get_current_uid_gid();
    event->uid = (u32)uid_gid;
    event->gid = (u32)(uid_gid >> 32);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    // ... parent PID lookup ...
}
```

These are nearly identical across `network.bpf.c`, `memfd.bpf.c`, `ioctl.bpf.c`, `iouring.bpf.c`, etc. The only reason they're duplicated is that each takes its own event struct type.

**Optimization:** Create a `common_fill.h` with a macro or generic inline that works with any event struct sharing the common field layout (all structs start with `timestamp_ns, event_type, pid, ppid, uid, gid, comm`):
```c
#define FILL_COMMON_FIELDS(event) do { \
    __builtin_memset(event, 0, sizeof(*(event))); \
    (event)->timestamp_ns = bpf_ktime_get_ns(); \
    /* ... */ \
} while(0)
```

### 4. Go Boilerplate in `native_load.go`, `native_attach.go` (MEDIUM IMPACT)

**Problem:** `native_load.go` (876 lines) and `native_attach.go` (25,800+ lines) contain massive amounts of repetitive if/else blocks for perf vs ringbuf variants:
```go
if perf {
    a.perfExecveObjs = &bpfgen.PerfexecveObjects{}
    if err = bpfgen.LoadPerfexecveObjects(a.perfExecveObjs, nil); err != nil {
        return fmt.Errorf("failed to load execve BPF objects: %w", err)
    }
} else {
    a.execveObjs = &bpfgen.ExecveObjects{}
    if err = bpfgen.LoadExecveObjects(a.execveObjs, nil); err != nil {
        return fmt.Errorf("failed to load execve BPF objects: %w", err)
    }
}
```

This pattern repeats for all 20 programs across load, pin, attach, close, and reader creation.

**Optimization:** Use a registry/table-driven approach:
```go
type programEntry struct {
    name       string
    loadRingbuf func() error
    loadPerf    func() error
    getMap      func() *ebpf.Map
    // ...
}
```
This could reduce `native_load.go` from ~876 to ~100 lines and `native_attach.go` significantly.

### 5. `NativeEBPFAgent` Struct Size (LOW IMPACT)

**Problem:** The `NativeEBPFAgent` struct holds 40 BPF object pointers (20 ringbuf + 20 perf) plus 20 EventReader fields. Only half are ever used at runtime.

**Optimization:** Use a single `map[string]interface{}` or typed wrapper for BPF objects, keyed by program name. Or use a generics-based approach to avoid storing both variants.

### 6. Enriched Agent as Separate Build Tag (LOW IMPACT)

**Problem:** `NativeEnrichedAgent` in `native_enriched.go` is gated behind a `//go:build enriched` tag. It's a parallel implementation of the entire agent lifecycle, duplicating the Start/Stop/Listen flow.

**Optimization:** Rather than a separate agent type, the enriched programs could be integrated into `NativeEBPFAgent` as an option. When enriched mode is enabled, load the enriched program variants alongside (or instead of) the standard ones. The enriched event parsers would be an additional code path in the existing agent, not a separate agent.

### 7. Missing Enriched Variants for Newer Programs (LOW IMPACT)

**Problem:** The following programs have NO enriched variant:
- `execve.bpf.c` (process cache itself handles execve enrichment)
- `process.bpf.c` (clone/kill/ptrace)
- `dns.bpf.c`
- `imds.bpf.c`
- `bpfsyscall.bpf.c`
- `memfd.bpf.c`
- `iouring.bpf.c`
- `namespace.bpf.c`
- `caps.bpf.c`
- `dataexfil.bpf.c`
- `dirops.bpf.c`
- `ioctl.bpf.c`
- `vfs_hooks.bpf.c`
- `cred_hooks.bpf.c`

If the enriched agent becomes the primary path, these would need enriched variants or a different strategy (e.g., userspace enrichment using the same process cache data).

### 8. DNS Parsing in Kernel (LOW IMPACT)

**Problem:** `dns.bpf.c` parses DNS wire format in BPF (label length encoding → dot-separated names). This is complex BPF code that's fragile and limited to 128-byte names.

**Optimization:** Capture the raw DNS payload (first 256 bytes) and parse in userspace Go. Simpler BPF, more flexible parsing, no verifier issues. Trade-off: slightly more data copied to userspace.

---

## Summary Statistics

| Metric | Count |
|--------|-------|
| BPF C source files | 27 (20 standard + 7 enriched) |
| Shared headers | 6 (.h files) |
| Syscalls instrumented | ~60 |
| Event struct types | 16 standard + 1 enriched union |
| Generated Go files | ~94 |
| Compiled BPF .o files | ~94 |
| Go orchestration files | ~25 |
| Total tracepoints attached | ~65 |
| Kprobe hooks (optional) | 6 |

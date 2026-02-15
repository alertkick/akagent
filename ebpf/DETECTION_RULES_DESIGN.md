# Detection Rules Architecture

## Overview

This document describes the detection rules architecture for the eBPF security agent. The design uses **lists**, **macros**, and **rules** to provide flexible, profile-based detection that integrates with the process cache for full context awareness.

## Design Goals

1. **Early filtering** - Filter events as early as possible to avoid wasting cycles
2. **Profile-based** - Different security profiles for different host types
3. **Dynamic updates** - Lists can be updated without agent restart
4. **Context-aware** - Leverage process cache for full lineage information
5. **Performant** - O(1) lookups using hash maps for lists

---

## Architecture Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           BPF Kernel Space                                   │
│                                                                              │
│  ┌──────────────────────────┐    ┌────────────────────────────────────────┐ │
│  │     Process Cache        │    │     Event Handlers                      │ │
│  │     (BPF Hash Map)       │    │     (setuid, mount, module, etc.)       │ │
│  │                          │    │                                          │ │
│  │  Key: PID                │◄───│  1. Capture syscall                      │ │
│  │  Value: process_info     │    │  2. Lookup process cache                 │ │
│  │    - pid, ppid, uid      │    │  3. Fill enriched_event with context     │ │
│  │    - comm, exe, cmdline  │    │  4. Submit to ring buffer                │ │
│  │    - parent_comm/exe     │    │                                          │ │
│  │    - grandparent info    │    └────────────────────────────────────────┘ │
│  │    - container_id        │                      │                         │
│  │    - cgroup_id           │                      │                         │
│  └──────────────────────────┘                      │                         │
│         ▲                                          │                         │
│         │ populated on                             │ enriched events         │
│         │ exec/fork/exit                           ▼                         │
│  ┌──────────────────────────┐    ┌────────────────────────────────────────┐ │
│  │  Lifecycle Tracepoints   │    │         Ring Buffer                     │ │
│  │  - sched_process_exec    │    │         (events ready for userspace)    │ │
│  │  - sched_process_fork    │    └────────────────────────────────────────┘ │
│  │  - sched_process_exit    │                      │                         │
│  └──────────────────────────┘                      │                         │
└────────────────────────────────────────────────────┼─────────────────────────┘
                                                     │
                                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Go Userspace                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  STAGE 1: Raw Event Read                                             │    │
│  │                                                                       │    │
│  │  record, err := ringbuf.Read()                                       │    │
│  │  // Minimal overhead - just read bytes from ring buffer              │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                       │                                      │
│                                       ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  STAGE 2: Quick Pre-Filter (Minimal Parsing)                         │    │
│  │                                                                       │    │
│  │  // Parse only header (first ~32 bytes)                              │    │
│  │  header := ParseEventHeader(record.RawSample[:32])                   │    │
│  │                                                                       │    │
│  │  // Fast rejection based on:                                         │    │
│  │  //   - event_type: Skip uninteresting event types                   │    │
│  │  //   - uid: Skip if UID in global_ignore_users                      │    │
│  │  //   - pid: Skip if PID in global_ignore_pids                       │    │
│  │                                                                       │    │
│  │  if quickFilter.ShouldSkip(header) {                                 │    │
│  │      continue  // Skip expensive parsing                             │    │
│  │  }                                                                    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                       │                                      │
│                                       ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  STAGE 3: Extract Key Fields                                         │    │
│  │                                                                       │    │
│  │  // Parse fields needed for list-based filtering                     │    │
│  │  keyFields := ExtractKeyFields(record.RawSample)                     │    │
│  │  //   - exe: /usr/bin/runc                                           │    │
│  │  //   - comm: runc                                                   │    │
│  │  //   - parent_comm: containerd-shim                                 │    │
│  │  //   - container_id: abc123def456...                                │    │
│  │  //   - uid, new_uid (for privilege events)                          │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                       │                                      │
│                                       ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  STAGE 4: List-Based Filtering                                       │    │
│  │                                           ┌───────────────────────┐  │    │
│  │  // Check against loaded lists            │   Security Profile    │  │    │
│  │  //                                       │   (pushed from API)   │  │    │
│  │  // allowed_binaries:                     │                       │  │    │
│  │  //   [/usr/bin/runc, /usr/bin/sudo...]  │   Lists:              │  │    │
│  │  //                                       │   - allowed_binaries  │  │    │
│  │  // blocked_processes:                    │   - blocked_processes │  │    │
│  │  //   [cryptominer, xmrig...]            │   - expected_parents  │  │    │
│  │  //                                       │   - trusted_users     │  │    │
│  │  // expected_parents:                     │   - ignored_containers│  │    │
│  │  //   {runc: [containerd-shim, crio]}    │                       │  │    │
│  │  //                                       │   Macros:             │  │    │
│  │  // trusted_users:                        │   - is_container_init │  │    │
│  │  //   [0, 1000, ...]                     │   - is_package_mgr    │  │    │
│  │  //                                       │                       │  │    │
│  │  if lists.IsExpectedBehavior(keyFields) { │   Rules:              │  │    │
│  │      continue  // Known good pattern      │   - name, condition   │  │    │
│  │  }                                        │   - priority, tags    │  │    │
│  │                                           └───────────────────────┘  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                       │                                      │
│                                       ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  STAGE 5: Full Event Parsing                                         │    │
│  │                                                                       │    │
│  │  // Only parse fully if event passed list filters                    │    │
│  │  event := ParseEnrichedEvent(record.RawSample)                       │    │
│  │  securityEvent := event.ToSecurityEvent()                            │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                       │                                      │
│                                       ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  STAGE 6: Macro Expansion & Rule Evaluation                          │    │
│  │                                                                       │    │
│  │  // Expand macros to evaluate conditions                             │    │
│  │  //                                                                   │    │
│  │  // Macro: is_container_init                                         │    │
│  │  //   = parent_comm in (container_init_parents) AND                  │    │
│  │  //     exe in (container_runtimes)                                  │    │
│  │  //                                                                   │    │
│  │  // Rule: "Unexpected privilege escalation"                          │    │
│  │  //   condition: setuid AND new_uid == 0 AND NOT is_expected_setuid  │    │
│  │  //   priority: CRITICAL                                             │    │
│  │  //                                                                   │    │
│  │  matchedRules := ruleEngine.Evaluate(securityEvent)                  │    │
│  │  if len(matchedRules) == 0 {                                         │    │
│  │      continue  // No rules matched                                   │    │
│  │  }                                                                    │    │
│  │                                                                       │    │
│  │  // Annotate event with matched rule info                            │    │
│  │  securityEvent.Rule = matchedRules[0].Name                           │    │
│  │  securityEvent.Priority = matchedRules[0].Priority                   │    │
│  │  securityEvent.Tags = matchedRules[0].Tags                           │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                       │                                      │
│                                       ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  STAGE 7: Send to Endpoint                                           │    │
│  │                                                                       │    │
│  │  // Only events that matched a rule reach here                       │    │
│  │  eventChan <- securityEvent                                          │    │
│  │                                                                       │    │
│  │  // Event includes:                                                  │    │
│  │  //   - Full process context (from cache)                            │    │
│  │  //   - Parent/grandparent lineage                                   │    │
│  │  //   - Container context                                            │    │
│  │  //   - Matched rule name, priority, tags                            │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Rule Format Specification

### File Structure

Rules are defined in YAML files with three main sections: `lists`, `macros`, and `rules`.

```yaml
# Security Profile: <profile-name>
# Description: <what this profile is for>
# Version: <semantic version>

lists:
  <list_name>:
    - <item1>
    - <item2>
    ...

macros:
  <macro_name>: <condition_expression>
  ...

rules:
  - name: <rule_name>
    condition: <condition_expression>
    priority: <CRITICAL|HIGH|WARNING|INFO>
    tags: [<tag1>, <tag2>, ...]
    enabled: <true|false>
    description: <optional description>
```

### Lists

Lists are named collections of values used in conditions. They support:
- Strings (process names, paths, etc.)
- Numbers (UIDs, GIDs, ports)
- Patterns (glob-style wildcards)

```yaml
lists:
  # Simple string list
  container_runtimes:
    - /usr/bin/runc
    - /usr/bin/containerd-shim-runc-v2
    - /usr/bin/crun
    - /usr/bin/crio

  # Process names (comm field)
  container_init_parents:
    - containerd-shim
    - runc
    - crio
    - dockerd

  # Package managers
  package_managers:
    - apt
    - apt-get
    - dpkg
    - yum
    - dnf
    - rpm
    - apk
    - pacman

  # Trusted binaries for setuid
  trusted_setuid_binaries:
    - /usr/bin/sudo
    - /usr/bin/su
    - /usr/bin/newgrp
    - /usr/bin/passwd
    - /usr/bin/chsh

  # Trusted UIDs
  trusted_users:
    - 0      # root
    - 1000   # first regular user

  # Sensitive file paths (with wildcards)
  sensitive_paths:
    - /etc/shadow
    - /etc/passwd
    - /etc/sudoers*
    - /root/.ssh/*
    - /home/*/.ssh/*

  # Ignored container patterns
  ignored_container_images:
    - k8s.gcr.io/pause*
    - registry.k8s.io/pause*
    - docker.io/library/pause*

  # Known miner processes (blocklist)
  crypto_miners:
    - xmrig
    - minerd
    - cpuminer
    - cgminer
    - bfgminer
    - ethminer
    - cryptonight
```

### Macros

Macros are reusable condition snippets that can reference lists and other macros.

```yaml
macros:
  # Container detection
  is_container: >
    container_id != "" OR cgroup_id != 0

  # Container initialization pattern
  is_container_init: >
    parent_comm in (container_init_parents) AND
    exe in (container_runtimes)

  # Package management activity
  is_package_manager: >
    comm in (package_managers)

  # Expected privilege escalation
  is_expected_setuid: >
    is_container_init OR
    exe in (trusted_setuid_binaries) OR
    (is_package_manager AND uid == 0)

  # Sensitive file access
  is_sensitive_file: >
    filename matches (sensitive_paths)

  # Known malware patterns
  is_known_miner: >
    comm in (crypto_miners) OR
    exe contains "miner" OR
    cmdline contains "stratum+tcp"

  # Shell spawned from web server
  shell_from_webserver: >
    comm in (bash, sh, zsh, dash) AND
    parent_comm in (apache2, nginx, httpd, php-fpm, node, python)

  # Reverse shell indicators
  is_reverse_shell: >
    (comm in (bash, sh, nc, ncat) AND
     cmdline contains "/dev/tcp") OR
    (comm == "python" AND cmdline contains "socket") OR
    (comm == "perl" AND cmdline contains "socket")
```

### Rules

Rules combine lists and macros into detection logic.

```yaml
rules:
  # ============================================
  # Privilege Escalation Rules
  # ============================================

  - name: Unexpected privilege escalation to root
    description: >
      Detects setuid/setreuid calls that escalate to root (UID 0)
      from processes not in the expected allow list.
    condition: >
      event_type in (setuid, setreuid) AND
      new_uid == 0 AND
      NOT is_expected_setuid
    priority: CRITICAL
    tags:
      - privilege
      - escalation
      - compliance
      - sox
      - pci
    enabled: true

  - name: Privilege escalation in container
    description: >
      Setuid to root inside a container outside of initialization.
    condition: >
      event_type == setuid AND
      new_uid == 0 AND
      is_container AND
      NOT is_container_init
    priority: CRITICAL
    tags:
      - container
      - privilege
      - escape_attempt
    enabled: true

  # ============================================
  # Kernel Module Rules
  # ============================================

  - name: Kernel module loaded
    description: >
      Any kernel module load is security-relevant for compliance.
    condition: >
      event_type in (init_module, finit_module)
    priority: HIGH
    tags:
      - kernel
      - module
      - compliance
      - sox
    enabled: true

  - name: Kernel module loaded in container
    description: >
      Kernel module operations from within a container may indicate escape attempt.
    condition: >
      event_type in (init_module, finit_module, delete_module) AND
      is_container
    priority: CRITICAL
    tags:
      - container
      - kernel
      - escape_attempt
    enabled: true

  # ============================================
  # Mount Rules
  # ============================================

  - name: Sensitive mount operation
    description: >
      Mount operations can be used to escape containers or access sensitive data.
    condition: >
      event_type == mount AND
      (target contains "/proc" OR
       target contains "/sys" OR
       target contains "/dev" OR
       fstype in (proc, sysfs, devtmpfs, cgroup))
    priority: HIGH
    tags:
      - mount
      - filesystem
      - compliance
    enabled: true

  - name: Mount operation in container
    description: >
      Mount syscall from within a container outside of initialization.
    condition: >
      event_type == mount AND
      is_container AND
      NOT is_container_init
    priority: CRITICAL
    tags:
      - container
      - mount
      - escape_attempt
    enabled: true

  # ============================================
  # Memory Protection Rules
  # ============================================

  - name: Memory marked writable and executable
    description: >
      Memory with W+X permissions may indicate code injection or exploitation.
    condition: >
      event_type == mprotect AND
      prot_write == true AND
      prot_exec == true
    priority: CRITICAL
    tags:
      - memory
      - code_injection
      - exploit
    enabled: true

  # ============================================
  # Malware Detection Rules
  # ============================================

  - name: Known crypto miner detected
    description: >
      Process matching known cryptocurrency miner signatures.
    condition: >
      is_known_miner
    priority: CRITICAL
    tags:
      - malware
      - cryptominer
      - threat
    enabled: true

  - name: Reverse shell detected
    description: >
      Patterns commonly associated with reverse shell activity.
    condition: >
      is_reverse_shell
    priority: CRITICAL
    tags:
      - malware
      - reverse_shell
      - threat
    enabled: true

  - name: Shell spawned from web server
    description: >
      Web server process spawning a shell may indicate exploitation.
    condition: >
      shell_from_webserver
    priority: CRITICAL
    tags:
      - webshell
      - exploit
      - threat
    enabled: true

  # ============================================
  # File Access Rules
  # ============================================

  - name: Sensitive file access
    description: >
      Access to sensitive system files.
    condition: >
      event_type == open AND
      is_sensitive_file AND
      NOT is_package_manager
    priority: WARNING
    tags:
      - file
      - sensitive
      - compliance
    enabled: true
```

---

## Condition Expression Syntax

### Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `==` | Equals | `uid == 0` |
| `!=` | Not equals | `uid != 0` |
| `>`, `<`, `>=`, `<=` | Numeric comparison | `new_uid >= 1000` |
| `in` | Membership in list | `comm in (bash, sh, zsh)` |
| `contains` | String contains | `cmdline contains "password"` |
| `matches` | Glob pattern match | `filename matches "/etc/*"` |
| `startswith` | String prefix | `exe startswith "/usr/bin/"` |
| `endswith` | String suffix | `filename endswith ".sh"` |
| `AND` | Logical AND | `uid == 0 AND new_uid != 0` |
| `OR` | Logical OR | `comm == "bash" OR comm == "sh"` |
| `NOT` | Logical NOT | `NOT is_container_init` |

### Available Fields

Fields available from enriched events:

| Field | Type | Description |
|-------|------|-------------|
| `event_type` | string | Event type (setuid, mount, etc.) |
| `pid` | int | Process ID |
| `ppid` | int | Parent process ID |
| `uid` | int | User ID |
| `gid` | int | Group ID |
| `comm` | string | Process command name (16 char max) |
| `exe` | string | Full executable path |
| `cmdline` | string | Full command line |
| `parent_comm` | string | Parent process command name |
| `parent_exe` | string | Parent executable path |
| `grandparent_pid` | int | Grandparent process ID |
| `grandparent_comm` | string | Grandparent command name |
| `container_id` | string | Container ID (if containerized) |
| `cgroup_id` | int | Cgroup ID |
| `flags` | int | Process flags |

Event-specific fields:

| Field | Events | Description |
|-------|--------|-------------|
| `new_uid`, `old_uid` | setuid, setreuid | Target/original UID |
| `new_gid`, `old_gid` | setgid, setregid | Target/original GID |
| `new_euid` | setreuid | Target effective UID |
| `source`, `target` | mount | Mount source and target |
| `fstype` | mount | Filesystem type |
| `mount_flags` | mount | Mount flags |
| `module_name` | init_module, etc. | Kernel module name |
| `module_size` | init_module | Module size in bytes |
| `addr`, `len`, `prot` | mprotect | Memory address, length, protection |
| `prot_read`, `prot_write`, `prot_exec` | mprotect | Protection flags (boolean) |
| `filename` | open, unlink, etc. | File path |

---

## Security Profiles

Security profiles are pre-configured rule sets for different environments.

### Profile Types

1. **baseline** - Minimal detection, low noise
2. **kubernetes-node** - Optimized for K8s worker nodes
3. **kubernetes-master** - Optimized for K8s control plane
4. **web-server** - Optimized for web servers
5. **database** - Optimized for database servers
6. **strict** - Maximum detection, higher noise tolerance
7. **compliance-sox** - SOX compliance focused
8. **compliance-pci** - PCI-DSS compliance focused

### Profile Structure

```yaml
# Profile: kubernetes-node
# Version: 1.0.0
# Description: Security profile for Kubernetes worker nodes

metadata:
  name: kubernetes-node
  version: "1.0.0"
  description: "Optimized for Kubernetes worker nodes"

# Include base lists/macros/rules from other profiles
includes:
  - baseline
  - compliance-sox

# Override or extend lists
lists:
  # Add K8s-specific binaries to allowed list
  container_runtimes:
    - /usr/bin/runc
    - /usr/bin/containerd-shim-runc-v2
    - /usr/local/bin/containerd-shim-kata-v2

  # K8s system processes to ignore
  k8s_system_processes:
    - kubelet
    - kube-proxy
    - containerd
    - dockerd

# Override macros
macros:
  is_k8s_system: >
    comm in (k8s_system_processes) OR
    exe startswith "/var/lib/kubelet"

# Additional rules for this profile
rules:
  - name: Unexpected process in kube-system namespace
    condition: >
      is_container AND
      container_namespace == "kube-system" AND
      NOT is_k8s_system
    priority: WARNING
    tags:
      - kubernetes
      - suspicious
```

---

## Implementation Data Structures

### Go Types

```go
// FilterLists holds all loaded lists as hash maps for O(1) lookup
type FilterLists struct {
    // String lists (exact match)
    StringLists map[string]map[string]bool

    // Numeric lists
    IntLists map[string]map[int]bool

    // Pattern lists (for glob matching)
    PatternLists map[string][]glob.Glob

    // Parent-child relationship lists
    ExpectedParents map[string][]string
}

// Macro represents a reusable condition
type Macro struct {
    Name       string
    Expression string
    Compiled   CompiledCondition
}

// Rule represents a detection rule
type Rule struct {
    Name        string
    Description string
    Condition   string
    Priority    PriorityLevel
    Tags        []string
    Enabled     bool
    Compiled    CompiledCondition
}

// SecurityProfile holds the complete profile
type SecurityProfile struct {
    Metadata ProfileMetadata
    Lists    FilterLists
    Macros   map[string]*Macro
    Rules    []*Rule
}

// RuleEngine evaluates events against rules
type RuleEngine struct {
    mu       sync.RWMutex
    profile  *SecurityProfile
    compiled *CompiledProfile
}

// Hot-reload support
func (e *RuleEngine) UpdateProfile(profile *SecurityProfile) error {
    compiled, err := CompileProfile(profile)
    if err != nil {
        return err
    }

    e.mu.Lock()
    defer e.mu.Unlock()

    e.profile = profile
    e.compiled = compiled
    return nil
}
```

---

## Profile Distribution

### API Endpoints

```
GET  /api/v1/security-profiles                    # List available profiles
GET  /api/v1/security-profiles/{name}             # Get profile details
POST /api/v1/hosts/{hostId}/security-profile      # Assign profile to host
GET  /api/v1/hosts/{hostId}/security-profile      # Get host's profile
```

### Agent Pull Model

```
Agent                                    API
  │                                       │
  │  GET /api/v1/agent/profile            │
  │  Authorization: Bearer <token>        │
  │  X-Host-ID: <host-id>                 │
  │ ─────────────────────────────────────>│
  │                                       │
  │  200 OK                               │
  │  ETag: "v1.2.3"                       │
  │  {profile YAML}                       │
  │ <─────────────────────────────────────│
  │                                       │
  │  (agent loads profile)                │
  │                                       │
  │  ... later, check for updates ...     │
  │                                       │
  │  GET /api/v1/agent/profile            │
  │  If-None-Match: "v1.2.3"              │
  │ ─────────────────────────────────────>│
  │                                       │
  │  304 Not Modified                     │
  │ <─────────────────────────────────────│
```

### Push via WebSocket

```
API                                    Agent
  │                                       │
  │  (profile updated for host)           │
  │                                       │
  │  WS: {"type": "profile_update",       │
  │       "version": "v1.2.4",            │
  │       "profile": {...}}               │
  │ ─────────────────────────────────────>│
  │                                       │
  │                                       │  (agent hot-reloads profile)
  │                                       │
  │  WS: {"type": "profile_ack",          │
  │       "version": "v1.2.4",            │
  │       "status": "loaded"}             │
  │ <─────────────────────────────────────│
```

---

## Performance Considerations

### List Lookup Complexity

| Operation | Data Structure | Complexity |
|-----------|----------------|------------|
| Exact string match | `map[string]bool` | O(1) |
| Numeric match | `map[int]bool` | O(1) |
| Glob pattern match | `[]glob.Glob` | O(n) patterns |
| Prefix match | Trie | O(k) key length |

### Optimization Strategies

1. **Bloom filters** for very large blocklists (millions of entries)
2. **Compiled regex** for complex patterns
3. **Trie structures** for prefix-based matching (paths)
4. **Cache macro evaluation results** per event

### Benchmarks (Target)

| Stage | Target Latency |
|-------|----------------|
| Raw read | < 1 µs |
| Quick pre-filter | < 5 µs |
| Key field extraction | < 10 µs |
| List-based filtering | < 20 µs |
| Full event parsing | < 50 µs |
| Rule evaluation | < 100 µs |
| **Total (filtered out)** | **< 40 µs** |
| **Total (rule match)** | **< 200 µs** |

---

## Integration with Process Cache

The detection rules leverage the process cache for context:

```
Event: setuid(0)
       │
       ▼
┌──────────────────────────────────────────────────────┐
│  Enriched Event (from BPF with cache lookup)         │
│                                                       │
│  event_type: setuid                                  │
│  pid: 12345                                          │
│  uid: 1000 → new_uid: 0                              │
│                                                       │
│  From Process Cache:                                 │
│  ├─ comm: "runc"                                     │
│  ├─ exe: "/usr/bin/runc"                             │
│  ├─ cmdline: "runc init"                             │
│  ├─ parent_comm: "containerd-shim"                   │
│  ├─ parent_exe: "/usr/bin/containerd-shim-runc-v2"  │
│  ├─ grandparent_comm: "containerd"                   │
│  ├─ container_id: "abc123..."                        │
│  └─ cgroup_id: 4026532198                            │
└──────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────┐
│  List Check                                          │
│                                                       │
│  exe "/usr/bin/runc" in container_runtimes? YES     │
│  parent "containerd-shim" in container_init_parents? YES │
│                                                       │
│  → Macro is_container_init = TRUE                    │
│  → Macro is_expected_setuid = TRUE                   │
│                                                       │
│  Rule "Unexpected privilege escalation":             │
│    condition: setuid AND new_uid == 0 AND NOT is_expected_setuid │
│    evaluation: TRUE AND TRUE AND NOT TRUE = FALSE   │
│                                                       │
│  → Event FILTERED (expected container behavior)      │
└──────────────────────────────────────────────────────┘
```

---

## Files

| File | Description |
|------|-------------|
| `ebpf/rules/engine.go` | Rule engine implementation |
| `ebpf/rules/lists.go` | List data structures and loading |
| `ebpf/rules/macros.go` | Macro expansion |
| `ebpf/rules/parser.go` | YAML rule parser |
| `ebpf/rules/compiler.go` | Condition compiler |
| `ebpf/rules/profiles/` | Built-in security profiles |
| `config/security-profile.yaml` | Local profile override |

---

## References

- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)

---

## Implementation Status

### Completed Features (January 2026)

The following components have been fully implemented:

#### Agent-Side Rule Engine (`apagent/ebpf/rules/`)

| File | Status | Description |
|------|--------|-------------|
| `engine.go` | **Implemented** | RuleEngine with hot-reload support, condition evaluation, macro expansion |
| `lists.go` | **Implemented** | FilterLists with O(1) hash map lookups for strings, integers, and pattern matching |
| `macros.go` | **Implemented** | MacroRegistry with recursive expansion and word-boundary replacement |
| `parser.go` | **Implemented** | YAML/JSON profile parsing using `gopkg.in/yaml.v3` |

#### Agent Command Handler (`apagent/compliance/`)

| File | Status | Description |
|------|--------|-------------|
| `handler.go` | **Implemented** | Handles `agent.refresh_compliance` command, manages rule engine lifecycle |

#### API Data Models (`apapi/models/`)

| File | Status | Description |
|------|--------|-------------|
| `compliance_list.go` | **Implemented** | ComplianceList with type constants (binaries, processes, paths, users, ports) |
| `compliance_macro.go` | **Implemented** | ComplianceMacro with dependency tracking (UsesLists, UsesMacros) |
| `compliance_rule.go` | **Implemented** | ComplianceRule with framework, severity, condition expressions |
| `compliance_profile.go` | **Implemented** | ComplianceProfile with RuleConfigs, ListOverrides, MacroOverrides |
| `host_compliance_config.go` | **Implemented** | Per-host compliance configuration with profile references |

#### API Endpoints (`apapi/api/v1/`)

| Endpoint Package | Status | Routes |
|------------------|--------|--------|
| `compliance_lists/` | **Implemented** | GET/POST/DELETE for `/compliance-lists/*` |
| `compliance_macros/` | **Implemented** | GET/POST/DELETE for `/compliance-macros/*` |
| `compliance_rules/` | **Implemented** | GET/POST/DELETE for `/compliance-rules/*`, by-framework endpoint |
| `compliance_profiles/` | **Implemented** | GET/POST/DELETE for `/compliance-profiles/*`, clone endpoint |
| `host_compliance/` | **Implemented** | GET/POST for `/hosts/{uuid}/compliance/*`, resolved config, refresh |

#### Resolution & Notification (`apapi/compliance/`)

| File | Status | Description |
|------|--------|-------------|
| `resolver.go` | **Implemented** | Hierarchy resolution: Defaults → Profile Overrides → Host Overrides |
| `notifier.go` | **Implemented** | Agent notification via Kafka (decoupled from kafka package) |

#### Seeding (`apapi/seeding/`)

| File | Status | Description |
|------|--------|-------------|
| `compliance.go` | **Implemented** | Seeds default lists, macros, rules, and profiles at startup |

### Default Data Seeded

#### Lists (20+)
- `container_runtimes` - runc, containerd-shim-runc-v2, crun, crio, podman, buildah
- `container_init_parents` - containerd-shim, runc, crio, dockerd, containerd
- `trusted_setuid_binaries` - sudo, su, newgrp, passwd, chsh, mount, umount, ping
- `user_mgmt_binaries` - useradd, usermod, userdel, passwd, groupadd, chpasswd
- `package_managers` - apt, apt-get, dpkg, yum, dnf, rpm, pip, npm, apk
- `shell_binaries` - bash, sh, zsh, dash, fish, tcsh, ksh
- `ssh_binaries` - ssh, sshd, ssh-agent, sftp, scp
- `sensitive_paths` - /etc/shadow, /etc/passwd, /etc/sudoers, /root/.ssh/*
- `audit_log_paths` - /var/log/audit/*, /var/log/secure, /var/log/auth.log
- `crypto_miners` - xmrig, minerd, cpuminer, cgminer, ethminer
- `network_recon_tools` - nmap, masscan, netcat, nc, tcpdump
- `offensive_security_tools` - mimikatz, hashcat, john, hydra, sqlmap
- `kernel_module_tools` - insmod, rmmod, modprobe, modinfo, lsmod
- `suspicious_ports` - 4444, 5555, 6666, 1337, 31337, 6667

#### Macros (16+)
- `is_container` - container_id != "" OR cgroup_id != 0
- `is_container_init` - parent_comm in (container_init_parents) AND exe in (container_runtimes)
- `is_package_manager` - comm in (package_managers)
- `is_expected_setuid` - is_container_init OR exe in (trusted_setuid_binaries) OR ...
- `is_shell` - comm in (shell_binaries)
- `is_sensitive_file` - filename matches (sensitive_paths)
- `is_audit_log` - filename matches (audit_log_paths)
- `is_known_miner` - comm in (crypto_miners) OR exe contains "miner"
- `is_recon_tool` - comm in (network_recon_tools)
- `is_offensive_tool` - comm in (offensive_security_tools)
- `is_user_mgmt_command` - comm in (user_mgmt_binaries)
- `is_kernel_module_operation` - comm in (kernel_module_tools)
- `is_memory_execution` - syscall == memfd_create OR exe startswith "/dev/shm/"
- `is_container_escape_attempt` - filename matches (container_escape_paths)
- `is_crypto_key_access` - filename matches (crypto_key_paths)
- `is_suspicious_port` - dst_port in (suspicious_ports)

#### Rules (20)

**SOX Compliance (7 rules):**
- `SOX-001` - Privilege Escalation Detection (CRITICAL)
- `SOX-002` - Sudo Command Execution (WARNING)
- `SOX-003` - User Account Modification (HIGH)
- `SOX-004` - SSH Key Modification (HIGH)
- `SOX-005` - Audit Log Access (HIGH)
- `SOX-006` - System Configuration Change (WARNING)
- `SOX-007` - Kernel Module Operation (CRITICAL)

**PCI-DSS Compliance (11 rules):**
- `PCI-001` - Suspicious Network Connection (HIGH)
- `PCI-002` - Suspicious Process Execution (HIGH)
- `PCI-003` - Memory-based Execution (CRITICAL)
- `PCI-004` - Privilege Escalation (CRITICAL)
- `PCI-005` - Authentication Anomaly (HIGH)
- `PCI-006` - Critical File Access (WARNING)
- `PCI-007` - System Binary Modification (CRITICAL)
- `PCI-008` - Configuration File Modification (HIGH)
- `PCI-009` - Kernel Module Operation (CRITICAL)
- `PCI-010` - Container Escape Attempt (CRITICAL)
- `PCI-011` - Cryptographic Key Access (HIGH)

**Security Rules (2 rules):**
- `SEC-001` - Cryptocurrency Miner Detection (HIGH)
- `SEC-002` - Reverse Shell Detection (CRITICAL)

#### Profiles (4)
- `sox-compliance` - SOX rules enabled
- `pci-dss-compliance` - PCI-DSS rules enabled
- `combined-compliance` - All SOX + PCI + Security rules
- `security-monitoring` - Threat detection focused

### Architecture Highlights

1. **Database-Driven Configuration**
   - All rules stored in MongoDB (not hardcoded in Go)
   - Direct MongoDB access pattern (no DAO/services layer)
   - Idempotent seeding at startup

2. **Hierarchical Override System**
   ```
   Default Lists/Rules (is_default=true)
        ↓
   Compliance Profile Overrides (add/remove items)
        ↓
   Host-Level Overrides (highest priority)
        ↓
   Resolved YAML Config → Agent
   ```

3. **Agent Hot-Reload**
   - `UpdateProfile()` method for atomic profile swap
   - No agent restart required for rule updates
   - Thread-safe with RWMutex

4. **Decoupled Kafka Integration**
   - Compliance package uses `KafkaQueueFunc` type
   - No import cycle between compliance and kafka packages
   - Function injected at startup

### Pending Work

- [ ] Integration with `alert_filter.go` for full event filtering pipeline
- [ ] Agent native command handler integration in `native_agent.go`
- [ ] Frontend UI for list/profile management
- [ ] Webhook notifications for rule matches
- [ ] Rate limiting for high-volume events

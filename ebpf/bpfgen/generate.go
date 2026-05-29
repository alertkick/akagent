// Package bpfgen contains generated eBPF code from BPF C programs.
//
// This package uses bpf2go to compile BPF C code into Go-loadable objects.
// The generated code provides type-safe access to BPF maps and programs.
//
// To regenerate the code after modifying BPF C sources:
//   make bpf/generate
// or:
//   go generate ./...
//
// Requirements:
//   - clang (for BPF compilation)
//   - llvm (for BPF target support)
//   - bpf2go (go install github.com/cilium/ebpf/cmd/bpf2go@latest)
package bpfgen

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type execve_event Execve ../bpf/execve.bpf.c -- -I../bpf -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type file_event Fileops ../bpf/fileops.bpf.c -- -I../bpf -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type network_event Network ../bpf/network.bpf.c -- -I../bpf -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type process_event Process ../bpf/process.bpf.c -- -I../bpf -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type privilege_event Privilege ../bpf/privilege.bpf.c -- -I../bpf -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type mount_event Mount ../bpf/mount.bpf.c -- -I../bpf -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type module_event Module ../bpf/module.bpf.c -- -I../bpf -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type memory_event Memory ../bpf/memory.bpf.c -- -I../bpf -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type dns_event Dns ../bpf/dns.bpf.c -- -I../bpf -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type imds_event Imds ../bpf/imds.bpf.c -- -I../bpf -Wall -Werror

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type bpf_syscall_event Bpfsyscall ../bpf/bpfsyscall.bpf.c -- -I../bpf -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type memfd_event Memfd ../bpf/memfd.bpf.c -- -I../bpf -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type iouring_event Iouring ../bpf/iouring.bpf.c -- -I../bpf -Wall -Werror

// Namespace and capability monitoring (container security)
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type namespace_event Namespace ../bpf/namespace.bpf.c -- -I../bpf -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type capset_event Caps ../bpf/caps.bpf.c -- -I../bpf -Wall -Werror

// Data exfiltration and directory operation monitoring
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type dataexfil_event Dataexfil ../bpf/dataexfil.bpf.c -- -I../bpf -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type dirops_event Dirops ../bpf/dirops.bpf.c -- -I../bpf -Wall -Werror

// VFS kprobe hooks and credential monitoring
// Note: kprobe programs need -D__TARGET_ARCH_x86 for BPF_KPROBE macro
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type vfs_event Vfshooks ../bpf/vfs_hooks.bpf.c -- -I../bpf -Wall -Werror -D__TARGET_ARCH_x86
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type cred_event Credhooks ../bpf/cred_hooks.bpf.c -- -I../bpf -Wall -Werror -D__TARGET_ARCH_x86

// Ioctl monitoring (security-relevant commands)
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type ioctl_event Ioctl ../bpf/ioctl.bpf.c -- -I../bpf -Wall -Werror

// ============================================================================
// Perf event array variants (for kernels without ring buffer support)
// These compile the same BPF sources with -DUSE_PERF_OUTPUT, which switches
// the output maps from BPF_MAP_TYPE_RINGBUF to BPF_MAP_TYPE_PERF_EVENT_ARRAY.
// ============================================================================
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type execve_event Perfexecve ../bpf/execve.bpf.c -- -I../bpf -Wall -Werror -DUSE_PERF_OUTPUT
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type file_event Perffileops ../bpf/fileops.bpf.c -- -I../bpf -Wall -Werror -DUSE_PERF_OUTPUT
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type network_event Perfnetwork ../bpf/network.bpf.c -- -I../bpf -Wall -Werror -DUSE_PERF_OUTPUT
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type process_event Perfprocess ../bpf/process.bpf.c -- -I../bpf -Wall -Werror -DUSE_PERF_OUTPUT
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type privilege_event Perfprivilege ../bpf/privilege.bpf.c -- -I../bpf -Wall -Werror -DUSE_PERF_OUTPUT
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type mount_event Perfmount ../bpf/mount.bpf.c -- -I../bpf -Wall -Werror -DUSE_PERF_OUTPUT
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type module_event Perfmodule ../bpf/module.bpf.c -- -I../bpf -Wall -Werror -DUSE_PERF_OUTPUT
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type memory_event Perfmemory ../bpf/memory.bpf.c -- -I../bpf -Wall -Werror -DUSE_PERF_OUTPUT
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type dns_event Perfdns ../bpf/dns.bpf.c -- -I../bpf -Wall -Werror -DUSE_PERF_OUTPUT
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type imds_event Perfimds ../bpf/imds.bpf.c -- -I../bpf -Wall -Werror -DUSE_PERF_OUTPUT
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type bpf_syscall_event Perfbpfsyscall ../bpf/bpfsyscall.bpf.c -- -I../bpf -Wall -Werror -DUSE_PERF_OUTPUT
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type memfd_event Perfmemfd ../bpf/memfd.bpf.c -- -I../bpf -Wall -Werror -DUSE_PERF_OUTPUT
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type iouring_event Perfiouring ../bpf/iouring.bpf.c -- -I../bpf -Wall -Werror -DUSE_PERF_OUTPUT
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type namespace_event Perfnamespace ../bpf/namespace.bpf.c -- -I../bpf -Wall -Werror -DUSE_PERF_OUTPUT
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type capset_event Perfcaps ../bpf/caps.bpf.c -- -I../bpf -Wall -Werror -DUSE_PERF_OUTPUT
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type dataexfil_event Perfdataexfil ../bpf/dataexfil.bpf.c -- -I../bpf -Wall -Werror -DUSE_PERF_OUTPUT
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type dirops_event Perfdirops ../bpf/dirops.bpf.c -- -I../bpf -Wall -Werror -DUSE_PERF_OUTPUT
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type vfs_event Perfvfshooks ../bpf/vfs_hooks.bpf.c -- -I../bpf -Wall -Werror -DUSE_PERF_OUTPUT -D__TARGET_ARCH_x86
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type cred_event Perfcredhooks ../bpf/cred_hooks.bpf.c -- -I../bpf -Wall -Werror -DUSE_PERF_OUTPUT -D__TARGET_ARCH_x86
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type ioctl_event Perfioctl ../bpf/ioctl.bpf.c -- -I../bpf -Wall -Werror -DUSE_PERF_OUTPUT

// Process cache for userspace enrichment (always loaded)
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type process_info -type enriched_event Processcache ../bpf/process_cache.bpf.c -- -I../bpf -Wall -Werror

// SSH lockdown LSM blocker. No event type — the program is enforcement-
// only, not telemetry. Loaded conditionally (only on kernels with
// CONFIG_BPF_LSM=y and lsm=bpf in cmdline); see sshlockdown/capability.go
// for the runtime probe.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb Sshlockdown ../bpf/ssh_lockdown.bpf.c -- -I../bpf -Wall -Werror

// SSH lockdown TC fallback. Attaches as a clsact ingress filter when
// the LSM path isn't available. Has its own map set (parallel naming
// with "tc" prefix) so both programs can coexist without state stomping
// during testing.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb Sshlockdowntc ../bpf/ssh_lockdown_tc.bpf.c -- -I../bpf -Wall -Werror

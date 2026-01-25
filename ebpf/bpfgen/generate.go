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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type execve_event execve ../bpf/execve.bpf.c -- -I../bpf -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type file_event fileops ../bpf/fileops.bpf.c -- -I../bpf -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type network_event network ../bpf/network.bpf.c -- -I../bpf -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type process_event process ../bpf/process.bpf.c -- -I../bpf -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type privilege_event privilege ../bpf/privilege.bpf.c -- -I../bpf -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type mount_event mount ../bpf/mount.bpf.c -- -I../bpf -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type module_event module ../bpf/module.bpf.c -- -I../bpf -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type memory_event memory ../bpf/memory.bpf.c -- -I../bpf -Wall -Werror

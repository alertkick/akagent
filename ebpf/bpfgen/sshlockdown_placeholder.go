// Placeholder for the SSH lockdown LSM BPF bindings. This file gets
// REPLACED by `make bpf/generate` (or `go generate ./...`) — bpf2go
// produces sshlockdown_bpfel.go and sshlockdown_bpfeb.go containing the
// real CollectionSpec embedded from sshlockdown_bpfel.o / _bpfeb.o.
//
// We commit this stub so the agent module compiles before the BPF
// toolchain (clang, llvm) has been run. LoadSshlockdownObjects returns
// an error in this stub state so a host that picks the LSM path
// without the bpf2go output present degrades gracefully to the
// NoopBlocker via SelectBlocker's error-handling branch.
//
// Remove this file from VCS once `make bpf/generate` has produced the
// real bindings — bpf2go and this stub will both define the same
// symbols and the build will fail.

//go:build linux

package bpfgen

import (
	"errors"

	"github.com/cilium/ebpf"
)

// SshlockdownObjects mirrors the shape bpf2go will emit. Map field
// names follow bpf2go's snake_case → CamelCase rule, matching the
// SEC(".maps") declarations in ssh_lockdown.bpf.c.
type SshlockdownObjects struct {
	SshlockdownPrograms
	SshlockdownMaps
}

type SshlockdownPrograms struct {
	SshlockdownSocketAccept *ebpf.Program `ebpf:"sshlockdown_socket_accept"`
}

type SshlockdownMaps struct {
	SshLockdownState       *ebpf.Map `ebpf:"ssh_lockdown_state"`
	SshLockdownPorts       *ebpf.Map `ebpf:"ssh_lockdown_ports"`
	SshLockdownV4Allowlist *ebpf.Map `ebpf:"ssh_lockdown_v4_allowlist"`
	SshLockdownV6Allowlist *ebpf.Map `ebpf:"ssh_lockdown_v6_allowlist"`
	SshLockdownStats       *ebpf.Map `ebpf:"ssh_lockdown_stats"`
}

// errSshlockdownBindingsNotGenerated is the loud signal that the BPF
// toolchain hasn't run yet on this build. The factory catches it,
// records the diagnostic, and falls back to NoopBlocker — the agent
// stays up; only kernel-side enforcement is missing.
var errSshlockdownBindingsNotGenerated = errors.New(
	"sshlockdown BPF bindings missing — run `make bpf/generate` (requires clang + llvm)",
)

// LoadSshlockdownObjects in this placeholder errors out without
// touching the kernel. bpf2go's real version embeds the compiled .o
// and calls ebpf.LoadCollectionSpecFromReader.
func LoadSshlockdownObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	_ = obj
	_ = opts
	return errSshlockdownBindingsNotGenerated
}

func (o *SshlockdownObjects) Close() error {
	if p := o.SshlockdownSocketAccept; p != nil {
		_ = p.Close()
	}
	return nil
}

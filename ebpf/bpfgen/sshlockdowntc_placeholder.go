// Placeholder for the SSH lockdown TC BPF bindings. REPLACED by
// `make bpf/generate` — bpf2go emits sshlockdowntc_bpfel.go and
// sshlockdowntc_bpfeb.go with the real CollectionSpec embedded from
// the compiled .o files.
//
// See sshlockdown_placeholder.go for the rationale. Same pattern:
// committed so the agent module compiles before the BPF toolchain has
// been run; replaced on first `make bpf/generate`.

//go:build linux

package bpfgen

import (
	"errors"

	"github.com/cilium/ebpf"
)

// SshlockdowntcObjects mirrors the shape bpf2go will emit. Field names
// follow bpf2go's snake_case → CamelCase rule.
type SshlockdowntcObjects struct {
	SshlockdowntcPrograms
	SshlockdowntcMaps
}

type SshlockdowntcPrograms struct {
	SshLockdownTc *ebpf.Program `ebpf:"ssh_lockdown_tc"`
}

type SshlockdowntcMaps struct {
	SshLockdownTcState       *ebpf.Map `ebpf:"ssh_lockdown_tc_state"`
	SshLockdownTcPorts       *ebpf.Map `ebpf:"ssh_lockdown_tc_ports"`
	SshLockdownTcV4Allowlist *ebpf.Map `ebpf:"ssh_lockdown_tc_v4_allowlist"`
	SshLockdownTcV6Allowlist *ebpf.Map `ebpf:"ssh_lockdown_tc_v6_allowlist"`
	SshLockdownTcStats       *ebpf.Map `ebpf:"ssh_lockdown_tc_stats"`
}

var errSshlockdowntcBindingsNotGenerated = errors.New(
	"sshlockdowntc BPF bindings missing — run `make bpf/generate` (requires clang + llvm)",
)

func LoadSshlockdowntcObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	_ = obj
	_ = opts
	return errSshlockdowntcBindingsNotGenerated
}

func (o *SshlockdowntcObjects) Close() error {
	if p := o.SshLockdownTc; p != nil {
		_ = p.Close()
	}
	return nil
}

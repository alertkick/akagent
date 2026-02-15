package ebpf

import (
	"errors"
	"fmt"
	"testing"
)

func TestIsBPFVerifierIncompat_Nil(t *testing.T) {
	if IsBPFVerifierIncompat(nil) {
		t.Fatal("nil error should return false")
	}
}

func TestIsBPFVerifierIncompat_InvalidFunc(t *testing.T) {
	err := errors.New("loading objects: field TracepointSyscallsSysEnterOpen: program tracepoint__syscalls__sys_enter_open: invalid func unknown#195896080")
	if !IsBPFVerifierIncompat(err) {
		t.Fatal("should detect 'invalid func' as verifier incompatibility")
	}
}

func TestIsBPFVerifierIncompat_UnknownFunc(t *testing.T) {
	err := errors.New("unknown func bpf_probe_read_kernel#113")
	if !IsBPFVerifierIncompat(err) {
		t.Fatal("should detect 'unknown func' as verifier incompatibility")
	}
}

func TestIsBPFVerifierIncompat_COREBadRelocation(t *testing.T) {
	// 0x0BAD0B10 = 195896080 — CO-RE sentinel value
	err := fmt.Errorf("program test: apply CO-RE relocations: invalid func unknown#195896080")
	if !IsBPFVerifierIncompat(err) {
		t.Fatal("should detect CO-RE sentinel 195896080 as verifier incompatibility")
	}
}

func TestIsBPFVerifierIncompat_SentinelOnly(t *testing.T) {
	err := errors.New("failed relocation: helper 195896080 not supported")
	if !IsBPFVerifierIncompat(err) {
		t.Fatal("should detect bare 195896080 sentinel as verifier incompatibility")
	}
}

func TestIsBPFVerifierIncompat_PermissionError(t *testing.T) {
	err := errors.New("operation not permitted")
	if IsBPFVerifierIncompat(err) {
		t.Fatal("permission errors should not be detected as verifier incompatibility")
	}
}

func TestIsBPFVerifierIncompat_LockdownError(t *testing.T) {
	err := errors.New("kernel lockdown: BPF is restricted")
	if IsBPFVerifierIncompat(err) {
		t.Fatal("lockdown errors should not be detected as verifier incompatibility")
	}
}

func TestIsBPFVerifierIncompat_GenericError(t *testing.T) {
	err := errors.New("something completely unrelated went wrong")
	if IsBPFVerifierIncompat(err) {
		t.Fatal("unrelated errors should not be detected as verifier incompatibility")
	}
}

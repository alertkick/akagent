//go:build linux

package ebpf

import "testing"

// TestBuildKernelDiscardComms_WriteCapableExempt — write-capable file tools
// must never reach the in-kernel discarder: the kernel discard runs before
// fimNotify, so discarding cp/touch/sed/vim there makes the file-integrity
// monitor permanently blind to changes made through them. They must still be
// present in the userspace exclusion set (BuildExcludeComms) so raw telemetry
// noise stays filtered.
func TestBuildKernelDiscardComms_WriteCapableExempt(t *testing.T) {
	cfg := DefaultNativeListConfig()
	kernel := cfg.BuildKernelDiscardComms()
	userspace := cfg.BuildExcludeComms()

	for comm := range AKFileWriteCapableBinaries {
		if _, ok := kernel[comm]; ok {
			t.Errorf("write-capable binary %q must not be in the kernel discard set", comm)
		}
		if _, ok := userspace[comm]; !ok {
			t.Errorf("write-capable binary %q should remain in the userspace exclusion set", comm)
		}
	}

	// Read-only viewers stay kernel-discarded — they are the noise volume
	// the discarder exists for.
	for _, comm := range []string{"cat", "ls", "grep", "head", "tail", "find", "stat", "wc"} {
		if _, ok := kernel[comm]; !ok {
			t.Errorf("read-only binary %q should stay in the kernel discard set", comm)
		}
	}
}

// TestAKFileWriteCapableBinaries_SubsetOfCoreutils — the write-capable set is
// defined as a carve-out of AKCoreutilsBinaries; an entry not in the parent
// list would silently do nothing.
func TestAKFileWriteCapableBinaries_SubsetOfCoreutils(t *testing.T) {
	for comm := range AKFileWriteCapableBinaries {
		if _, ok := AKCoreutilsBinaries[comm]; !ok {
			t.Errorf("%q is in AKFileWriteCapableBinaries but not in AKCoreutilsBinaries", comm)
		}
	}
}

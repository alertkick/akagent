package native

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
)

// KernelRequirements defines the minimum kernel requirements for native eBPF
const (
	MinKernelMajor = 5
	MinKernelMinor = 8
)

// KernelSupport holds information about kernel eBPF support
type KernelSupport struct {
	Version       string
	Major         int
	Minor         int
	Patch         int
	HasRingBuf    bool
	HasTracepoint bool
	CanLoadBPF    bool
	Error         error
}

// CheckKernelSupport performs comprehensive kernel feature detection
func CheckKernelSupport() KernelSupport {
	support := KernelSupport{}

	// Get kernel version
	support.Version = getKernelVersion()
	support.Major, support.Minor, support.Patch = parseKernelVersion(support.Version)

	// Check minimum version requirement
	if support.Major < MinKernelMajor || (support.Major == MinKernelMajor && support.Minor < MinKernelMinor) {
		support.Error = fmt.Errorf("kernel version %s is too old, minimum required is %d.%d",
			support.Version, MinKernelMajor, MinKernelMinor)
		return support
	}

	// Check for ring buffer map support (kernel 5.8+)
	if err := features.HaveMapType(ebpf.RingBuf); err != nil {
		support.Error = fmt.Errorf("kernel does not support ring buffer maps: %w", err)
		return support
	}
	support.HasRingBuf = true

	// Check for tracepoint program support
	if err := features.HaveProgramType(ebpf.TracePoint); err != nil {
		support.Error = fmt.Errorf("kernel does not support tracepoint programs: %w", err)
		return support
	}
	support.HasTracepoint = true

	// Check if we can actually load BPF programs (requires CAP_BPF or root)
	support.CanLoadBPF = checkBPFPermissions()

	if !support.CanLoadBPF {
		support.Error = fmt.Errorf("insufficient permissions to load BPF programs (requires CAP_BPF or root)")
		return support
	}

	return support
}

// IsSupported returns true if the kernel supports all required features
func (k *KernelSupport) IsSupported() bool {
	return k.Error == nil && k.HasRingBuf && k.HasTracepoint && k.CanLoadBPF
}

// String returns a human-readable description of kernel support status
func (k *KernelSupport) String() string {
	if k.Error != nil {
		return fmt.Sprintf("Kernel %s: Not supported - %v", k.Version, k.Error)
	}
	return fmt.Sprintf("Kernel %s: Supported (RingBuf=%v, Tracepoint=%v, CanLoad=%v)",
		k.Version, k.HasRingBuf, k.HasTracepoint, k.CanLoadBPF)
}

// getKernelVersion returns the kernel version string
func getKernelVersion() string {
	// Try uname first
	output, err := exec.Command("uname", "-r").Output()
	if err == nil {
		return strings.TrimSpace(string(output))
	}

	// Fall back to /proc/version
	data, err := os.ReadFile("/proc/version")
	if err == nil {
		// Parse "Linux version X.Y.Z..." format
		parts := strings.Fields(string(data))
		if len(parts) >= 3 {
			return parts[2]
		}
	}

	return "unknown"
}

// parseKernelVersion parses a kernel version string like "5.15.0-generic"
func parseKernelVersion(version string) (major, minor, patch int) {
	// Remove any suffix after the version numbers
	version = strings.Split(version, "-")[0]
	parts := strings.Split(version, ".")

	if len(parts) >= 1 {
		major, _ = strconv.Atoi(parts[0])
	}
	if len(parts) >= 2 {
		minor, _ = strconv.Atoi(parts[1])
	}
	if len(parts) >= 3 {
		patch, _ = strconv.Atoi(parts[2])
	}

	return major, minor, patch
}

// checkBPFPermissions checks if the current process can load BPF programs
func checkBPFPermissions() bool {
	// Check if running as root
	if os.Geteuid() == 0 {
		return true
	}

	// Check for CAP_BPF capability
	// This is a simplified check - in production you might want to use
	// golang.org/x/sys/unix to check capabilities properly
	capFile := "/proc/self/status"
	data, err := os.ReadFile(capFile)
	if err != nil {
		return false
	}

	// Look for CapEff line and check for CAP_BPF (bit 39) or CAP_SYS_ADMIN (bit 21)
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				caps, err := strconv.ParseUint(parts[1], 16, 64)
				if err == nil {
					// CAP_BPF = 39, CAP_SYS_ADMIN = 21
					hasBPF := (caps & (1 << 39)) != 0
					hasSysAdmin := (caps & (1 << 21)) != 0
					return hasBPF || hasSysAdmin
				}
			}
		}
	}

	return false
}

// RequiresRoot returns true if BPF loading requires root privileges on this system
func RequiresRoot() bool {
	// On most systems, loading BPF programs requires root or CAP_BPF
	return os.Geteuid() != 0 && !checkBPFPermissions()
}

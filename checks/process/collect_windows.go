//go:build windows

package process

import (
	"strings"

	"github.com/shirou/gopsutil/process"
)

// findProcessPIDs finds PIDs whose executable name matches the configured
// process name. Matching is case-insensitive and tolerant of a missing
// ".exe" suffix in the check config, so "nginx" matches "nginx.exe".
func (c *ProcessCheck) findProcessPIDs() []int {
	procs, err := process.Processes()
	if err != nil {
		return nil
	}

	want := strings.ToLower(c.processName)
	wantExe := want
	if !strings.HasSuffix(wantExe, ".exe") {
		wantExe += ".exe"
	}

	var pids []int
	for _, p := range procs {
		name, err := p.Name()
		if err != nil {
			continue
		}
		n := strings.ToLower(name)
		if n == want || n == wantExe {
			pids = append(pids, int(p.Pid))
		}
	}
	return pids
}

// readProcCPU returns the process's accumulated CPU time in seconds. Like
// the Linux collector (which reports raw utime+stime ticks), this is a
// monotonically increasing number meant for trending, not a percentage.
func readProcCPU(pid int) float64 {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return 0
	}
	times, err := p.Times()
	if err != nil {
		return 0
	}
	return times.User + times.System
}

// readProcRSS returns the process's working set size in kB, matching the
// Linux collector's VmRSS unit.
func readProcRSS(pid int) uint64 {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return 0
	}
	mi, err := p.MemoryInfo()
	if err != nil || mi == nil {
		return 0
	}
	return mi.RSS / 1024
}

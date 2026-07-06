//go:build linux

package process

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// findProcessPIDs uses pgrep to find PIDs matching the process name
func (c *ProcessCheck) findProcessPIDs() []int {
	cmd := exec.Command("pgrep", "-x", c.processName)
	output, err := cmd.Output()
	if err != nil {
		// pgrep returns exit code 1 when no processes found - not an error
		return nil
	}

	var pids []int
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		pidStr := strings.TrimSpace(scanner.Text())
		if pid, err := strconv.Atoi(pidStr); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

// readProcCPU reads CPU time from /proc/<pid>/stat and returns a rough percentage
// This is a snapshot-based approach reading utime+stime from /proc/pid/stat
func readProcCPU(pid int) float64 {
	path := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}

	fields := strings.Fields(string(data))
	if len(fields) < 15 {
		return 0
	}

	// fields[13] = utime, fields[14] = stime (in clock ticks)
	utime, err1 := strconv.ParseFloat(fields[13], 64)
	stime, err2 := strconv.ParseFloat(fields[14], 64)
	if err1 != nil || err2 != nil {
		return 0
	}

	// Total CPU ticks - to get a true percentage we'd need to track deltas
	// across intervals. For now, report the raw tick sum for trending.
	return utime + stime
}

// readProcRSS reads resident set size from /proc/<pid>/status in kB
func readProcRSS(pid int) uint64 {
	path := fmt.Sprintf("/proc/%d/status", pid)
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				val, err := strconv.ParseUint(parts[1], 10, 64)
				if err == nil {
					return val // in kB
				}
			}
			break
		}
	}
	return 0
}

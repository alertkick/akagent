package checks

import (
	"bufio"
	"os/exec"
	"strconv"
	"strings"
)

// GetSystemServices returns all systemd services for system info collection
// This is separate from the monitoring check to avoid circular dependencies
func GetSystemServices() ([]SystemServiceInfo, error) {
	// Use systemctl to list all services with their status
	cmd := exec.Command("systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain", "--no-legend")
	output, err := cmd.Output()
	if err != nil {
		// Fallback: try without --plain flag for older systemd versions
		cmd = exec.Command("systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend")
		output, err = cmd.Output()
		if err != nil {
			return nil, err
		}
	}

	var services []SystemServiceInfo
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Parse line: UNIT LOAD ACTIVE SUB DESCRIPTION
		// Example: ssh.service loaded active running OpenBSD Secure Shell server
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		name := fields[0]
		loadState := fields[1]
		activeState := fields[2]
		subState := fields[3]

		// Only include actual service units (not templates)
		if !strings.HasSuffix(name, ".service") {
			continue
		}

		svc := SystemServiceInfo{
			Name:        name,
			LoadState:   loadState,
			ActiveState: activeState,
			SubState:    subState,
			Status:      activeState,
		}

		// Try to get PID for running services
		if activeState == "active" && subState == "running" {
			pid := getServiceMainPID(name)
			if pid > 0 {
				svc.MainPID = pid
			}
		}

		services = append(services, svc)
	}

	return services, scanner.Err()
}

// getServiceMainPID gets the main PID of a running service
func getServiceMainPID(serviceName string) int {
	cmd := exec.Command("systemctl", "show", serviceName, "--property=MainPID", "--value")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	pidStr := strings.TrimSpace(string(output))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0
	}

	return pid
}


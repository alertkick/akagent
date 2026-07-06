//go:build linux

package services

import (
	"bufio"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// isCriticalService determines if a service is considered critical
func isCriticalService(name string) bool {
	criticalServices := map[string]bool{
		"sshd.service":             true,
		"ssh.service":              true,
		"systemd-journald.service": true,
		"systemd-udevd.service":    true,
		"systemd-logind.service":   true,
		"cron.service":             true,
		"rsyslog.service":          true,
		"dbus.service":             true,
		"NetworkManager.service":   true,
		"docker.service":           true,
		"containerd.service":       true,
		"kubelet.service":          true,
	}
	return criticalServices[name]
}

// GetRunningServices returns all systemd services on the system
func GetRunningServices() ([]ServiceInfo, error) {
	// Use systemctl to list all services with their status
	cmd := exec.Command("systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain", "--no-legend")
	output, err := cmd.Output()
	if err != nil {
		// Fallback: try without --plain flag for older systemd versions
		cmd = exec.Command("systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend")
		output, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to run systemctl: %w", err)
		}
	}

	var services []ServiceInfo
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

		// Get more details for active services
		svc := ServiceInfo{
			Name:        name,
			LoadState:   loadState,
			ActiveState: activeState,
			SubState:    subState,
			Status:      activeState,
		}

		// Try to get PID for running services
		if activeState == "active" && subState == "running" {
			pid := getServicePID(name)
			if pid > 0 {
				svc.MainPID = pid
			}
		}

		services = append(services, svc)
	}

	return services, scanner.Err()
}

// getServicePID gets the main PID of a running service
func getServicePID(serviceName string) int {
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

// GetAllServicesForSystemInfo returns a simplified list of services for system info
// This is used by the periodic system info collection, not the check monitoring
func GetAllServicesForSystemInfo() ([]ServiceInfo, error) {
	return GetRunningServices()
}

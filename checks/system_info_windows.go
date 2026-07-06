//go:build windows

package checks

import (
	"strconv"
	"strings"

	gopsnet "github.com/shirou/gopsutil/net"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// GetSystemListeningPorts returns all listening ports for system info
// collection. Same source as checks/ports on Windows (GetExtendedTcp/
// UdpTable via gopsutil); duplicated here because the checks package
// cannot import its own sub-packages.
func GetSystemListeningPorts() ([]SystemPortInfo, error) {
	conns, err := gopsnet.Connections("inet")
	if err != nil {
		return nil, err
	}

	var ports []SystemPortInfo
	for _, conn := range conns {
		isTCP := conn.Type == 1 // SOCK_STREAM
		if isTCP && conn.Status != "LISTEN" {
			continue
		}
		if !isTCP {
			if conn.Raddr.IP != "" && conn.Raddr.IP != "0.0.0.0" && conn.Raddr.IP != "::" {
				continue
			}
		}

		protocol := "tcp"
		if !isTCP {
			protocol = "udp"
		}
		if strings.Contains(conn.Laddr.IP, ":") {
			protocol += "6"
		}

		ports = append(ports, SystemPortInfo{
			Port:     uint16(conn.Laddr.Port),
			Protocol: protocol,
			Address:  conn.Laddr.IP,
			Inode:    strconv.Itoa(int(conn.Pid)),
		})
	}
	return ports, nil
}

// GetSystemServices enumerates Windows services via the SCM, mapped onto
// the systemd-flavoured state fields the endpoint expects.
func GetSystemServices() ([]SystemServiceInfo, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	defer m.Disconnect()

	names, err := m.ListServices()
	if err != nil {
		return nil, err
	}

	var services []SystemServiceInfo
	for _, name := range names {
		s, err := m.OpenService(name)
		if err != nil {
			continue
		}

		info := SystemServiceInfo{
			Name:      name,
			LoadState: "loaded",
		}
		if status, err := s.Query(); err == nil {
			switch status.State {
			case svc.Running:
				info.ActiveState, info.SubState = "active", "running"
				if status.ProcessId > 0 {
					info.MainPID = int(status.ProcessId)
				}
			case svc.Stopped:
				info.ActiveState, info.SubState = "inactive", "dead"
			case svc.StartPending:
				info.ActiveState, info.SubState = "activating", "start"
			case svc.StopPending:
				info.ActiveState, info.SubState = "deactivating", "stop"
			default:
				info.ActiveState, info.SubState = "inactive", "unknown"
			}
			info.Status = info.ActiveState
		}
		s.Close()

		services = append(services, info)
	}
	return services, nil
}

// GetInstalledPackages reads installed software from the registry
// Uninstall keys (both native and WOW6432Node views).
func GetInstalledPackages() ([]PackageInfo, error) {
	roots := []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	}

	seen := make(map[string]bool)
	var packages []PackageInfo

	for _, root := range roots {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, root, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}

		subkeys, err := key.ReadSubKeyNames(-1)
		if err != nil {
			key.Close()
			continue
		}

		for _, sub := range subkeys {
			entry, err := registry.OpenKey(registry.LOCAL_MACHINE, root+`\`+sub, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			name, _, err := entry.GetStringValue("DisplayName")
			if err != nil || name == "" {
				entry.Close()
				continue
			}
			if sysComp, _, err := entry.GetIntegerValue("SystemComponent"); err == nil && sysComp == 1 {
				entry.Close()
				continue
			}
			version, _, _ := entry.GetStringValue("DisplayVersion")
			entry.Close()

			if seen[name] {
				continue
			}
			seen[name] = true
			packages = append(packages, PackageInfo{Name: name, Version: version})
		}
		key.Close()
	}
	return packages, nil
}

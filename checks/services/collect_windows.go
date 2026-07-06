//go:build windows

package services

import (
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// isCriticalService determines if a service is considered critical
func isCriticalService(name string) bool {
	criticalServices := map[string]bool{
		"WinDefend":      true, // Microsoft Defender
		"MpsSvc":         true, // Windows Firewall
		"EventLog":       true, // Windows Event Log
		"Dnscache":       true, // DNS client
		"LanmanServer":   true, // SMB server
		"TermService":    true, // Remote Desktop
		"Schedule":       true, // Task Scheduler
		"wuauserv":       true, // Windows Update
		"W32Time":        true, // Time sync
		"CryptSvc":       true, // Cryptographic services
		"AlertKickAgent": true,
	}
	return criticalServices[name]
}

// GetRunningServices enumerates all services via the Service Control
// Manager and maps their states onto the systemd-flavoured fields the
// endpoint already understands (active/inactive + running/dead).
func GetRunningServices() ([]ServiceInfo, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	defer m.Disconnect()

	names, err := m.ListServices()
	if err != nil {
		return nil, err
	}

	var services []ServiceInfo
	for _, name := range names {
		s, err := m.OpenService(name)
		if err != nil {
			continue // access denied on some protected services — skip
		}

		info := ServiceInfo{
			Name:      name,
			LoadState: "loaded",
		}

		if status, err := s.Query(); err == nil {
			info.ActiveState, info.SubState = mapServiceState(status.State)
			info.Status = info.ActiveState
			if status.State == svc.Running && status.ProcessId > 0 {
				info.MainPID = int(status.ProcessId)
			}
		}
		if cfg, err := s.Config(); err == nil {
			info.DisplayName = cfg.DisplayName
			info.Type = mapStartType(cfg.StartType)
		}
		s.Close()

		services = append(services, info)
	}
	return services, nil
}

// mapServiceState translates SCM states onto the active_state/sub_state
// pairs the change detector and endpoint expect.
func mapServiceState(state svc.State) (activeState, subState string) {
	switch state {
	case svc.Running:
		return "active", "running"
	case svc.Stopped:
		return "inactive", "dead"
	case svc.StartPending:
		return "activating", "start"
	case svc.StopPending:
		return "deactivating", "stop"
	case svc.Paused, svc.PausePending, svc.ContinuePending:
		return "inactive", "paused"
	default:
		return "inactive", "unknown"
	}
}

func mapStartType(startType uint32) string {
	switch startType {
	case mgr.StartAutomatic:
		return "automatic"
	case mgr.StartManual:
		return "manual"
	case mgr.StartDisabled:
		return "disabled"
	default:
		return "other"
	}
}

// GetAllServicesForSystemInfo returns a simplified list of services for system info
// This is used by the periodic system info collection, not the check monitoring
func GetAllServicesForSystemInfo() ([]ServiceInfo, error) {
	return GetRunningServices()
}

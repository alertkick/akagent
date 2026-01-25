package checks

import (
	"apagent/config"
	"encoding/json"
)

func (p SystemData) String() string {
	s, _ := json.Marshal(p)
	return string(s)
}

func (p SystemInfo) String() string {
	s, _ := json.Marshal(p)
	return string(s)

}

func (p HostData) String() string {
	s, _ := json.Marshal(p)
	return string(s)
}

// SystemInfo - Stuck for System and Host info.
type SystemInfo struct {
	AgentConfig config.Config `json:"agent_config"`
	System      SystemData    `json:"system"`
	Host        HostData      `json:"host"`
}

// HostData - hostdata struct
type HostData struct {
	Hostname    string      `json:"hostname"`
	MachineID   string      `json:"machine_id"`
	ServerKey   string      `json:"server_key"`
	IPAddresses []IPAddress `json:"ip_addresses"`
	InstanceID  string      `json:"instance_id"`
}

// SystemData - collect all system metrics
type SystemData struct {
	Uptime         uint64              `json:"uptime"`
	Packages       []PackageInfo       `json:"packages"`
	Distro         DistroStruct        `json:"distro"`
	Services       []SystemServiceInfo `json:"services,omitempty"`
	ListeningPorts []SystemPortInfo    `json:"listening_ports,omitempty"`
}

// SystemServiceInfo represents a service for system info collection
// This is a simplified version used in the periodic system info, not the monitoring check
type SystemServiceInfo struct {
	Name        string `json:"name"`
	Status      string `json:"status"`       // running, stopped, failed
	ActiveState string `json:"active_state"` // active, inactive, failed
	SubState    string `json:"sub_state"`    // running, dead, exited
	LoadState   string `json:"load_state"`   // loaded, not-found, masked
	MainPID     int    `json:"main_pid,omitempty"`
}

// SystemPortInfo represents a listening port for system info collection
type SystemPortInfo struct {
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"` // tcp, tcp6, udp, udp6
	Address  string `json:"address"`  // IP address binding
	Inode    string `json:"inode,omitempty"`
}

// DistroStruct - returns information about the currently instaled distro
type DistroStruct struct {
	Hostname             string `json:"hostname"`
	Uptime               uint64 `json:"uptime"`
	BootTime             uint64 `json:"boot_time"`
	Procs                uint64 `json:"procs"` // number of processes
	OS                   string `json:"os"`
	Platform             string `json:"platform"`
	PlatformFamily       string `json:"platform_family"`
	PlatformVersion      string `json:"platform_version"`
	KernelVersion        string `json:"kernel_version"`
	KernelArch           string `json:"kernel_arch"`
	VirtualizationSystem string `json:"virtualization_system"`
	VirtualizationRole   string `json:"virtualization_role"`
	HostID               string `json:"host_id"`
}

// PackageInfo represents information about an installed package
type PackageInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type IPAddress struct {
	IPAddress     string `bson:"ip_address" json:"ip_address"`
	Type          string `bson:"type" json:"type"`
	InterfaceName string `bson:"interface_name" json:"interface_name"`
	Netmask       string `bson:"netmask" json:"netmask"`
	HWAddr        string `bson:"hardware_address" json:"hardware_address"`
	CIDR          string `bson:"cidr" json:"cidr"`               // CIDR notation
	SubnetMask    string `bson:"subnet_mask" json:"subnet_mask"` // Subnet mask
}

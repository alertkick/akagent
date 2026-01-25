package checks

import (
	"apagent/config"
	"apagent/internal/api"
	"apagent/logger"
	"context"
	"os"
	"sync"
)

var (
	log = logger.Sublogger("agent.checks")
)

// RegisteredChecks holds all available check implementations by name
var RegisteredChecks = map[string]api.CheckRegistry{}

// RegisteredCheckConfigs holds the configuration for all registered checks
var RegisteredCheckConfigs []api.CheckConfig

// Add registers a new check implementation
func Add(name string, check api.CheckRegistry) {
	log.Debug().Msgf("Adding check: %s", name)
	RegisteredChecks[name] = check
}

// AddConfig adds a check type to the registered configurations
func AddConfig(checkType string) {
	newCheckConfig := api.CheckConfig{CheckType: checkType}
	RegisteredCheckConfigs = append(RegisteredCheckConfigs, newCheckConfig)
}

func BaseConfiguredChecks() []api.ConfiguredCheck {
	var configuredChecks []api.ConfiguredCheck
	for _, c := range RegisteredCheckConfigs {
		checkObj := RegisteredChecks[c.CheckType]

		t := api.ConfiguredCheck{CheckType: c.CheckType, Check: checkObj()}
		configuredChecks = append(configuredChecks, t)
	}
	return configuredChecks
}

// CollectSystemInfo -
func CollectSystemInfo(ctx context.Context) SystemInfo {

	SystemData := CollectSystemData()
	HostData := CollectHostData(ctx)
	AgentConfig := config.GetConfig(log)

	systemInfo := SystemInfo{
		AgentConfig: *AgentConfig,
		System:      SystemData,
		Host:        HostData,
	}

	return systemInfo
}

// CollectHostData gathers host-level information including hostname, machine ID, and IP addresses
func CollectHostData(ctx context.Context) HostData {

	hostname, _ := os.Hostname()

	var machineID string
	var instanceID string
	var ipAddrs []IPAddress

	machineID = GetOrCreateMachineID()
	instanceID = CloudID(ctx)
	ipAddrs = DetectedIpAddresses()

	hostInfo := HostData{
		Hostname:    hostname,
		MachineID:   machineID,
		IPAddresses: ipAddrs,
		InstanceID:  instanceID,
	}
	return hostInfo
}

// CollectSystemData gathers system-level information including uptime, packages, and services
func CollectSystemData() SystemData {
	var UptimeValue uint64
	var installedPackages []PackageInfo
	var distro DistroStruct
	var services []SystemServiceInfo
	var listeningPorts []SystemPortInfo
	var wg sync.WaitGroup
	
	wg.Add(1)
	go func() {
		defer wg.Done()
		UptimeValue = Uptime()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		installedPackages, _ = GetInstalledPackages()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		distro = Distro()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		services, _ = GetSystemServices()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		listeningPorts, _ = GetSystemListeningPorts()
	}()

	wg.Wait()

	log.Debug().Msgf("CollectSystemData: packages=%d, services=%d, ports=%d",
		len(installedPackages), len(services), len(listeningPorts))

	SystemData := SystemData{
		Uptime:         UptimeValue,
		Packages:       installedPackages,
		Distro:         distro,
		Services:       services,
		ListeningPorts: listeningPorts,
	}
	return SystemData
}

package checks

import (
	"apagent/config"
	"apagent/internal/api"
	"apagent/logger"
	"context"
	"os"
	"os/exec"
	"strings"
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

	var dockerAvailable bool
	var dockerVersion string
	var containers []ContainerBasicInfo

	wg.Add(1)
	go func() {
		defer wg.Done()
		dockerAvailable, dockerVersion, containers = detectDocker()
	}()

	wg.Wait()

	log.Debug().Msgf("CollectSystemData: packages=%d, services=%d, ports=%d, docker=%t, containers=%d",
		len(installedPackages), len(services), len(listeningPorts), dockerAvailable, len(containers))

	SystemData := SystemData{
		Uptime:          UptimeValue,
		Packages:        installedPackages,
		Distro:          distro,
		Services:        services,
		ListeningPorts:  listeningPorts,
		DockerAvailable: dockerAvailable,
		DockerVersion:   dockerVersion,
		Containers:      containers,
	}
	return SystemData
}

// detectDocker performs a quick Docker detection for system info collection.
// Returns availability, version, and a basic container list.
func detectDocker() (bool, string, []ContainerBasicInfo) {
	// Check if Docker is available
	cmd := exec.Command("docker", "info", "--format", "{{.ServerVersion}}")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, "", nil
	}
	version := strings.TrimSpace(string(output))
	if version == "" {
		return false, "", nil
	}

	// List containers
	format := "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.State}}\t{{.Ports}}\t{{.Networks}}\t{{.Labels}}"
	cmd = exec.Command("docker", "ps", "-a", "--no-trunc", "--format", format)
	output, err = cmd.Output()
	if err != nil {
		// Docker is available but ps failed — still report docker as available
		return true, version, nil
	}

	var containers []ContainerBasicInfo
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 8)
		if len(fields) < 8 {
			continue
		}

		name := strings.TrimPrefix(fields[1], "/")
		labels := fields[7]

		ct := ContainerBasicInfo{
			ID:       fields[0],
			Name:     name,
			Image:    fields[2],
			Status:   fields[3],
			State:    fields[4],
			Ports:    fields[5],
			Networks: fields[6],
		}

		// Extract Compose labels
		for _, label := range strings.Split(labels, ",") {
			kv := strings.SplitN(label, "=", 2)
			if len(kv) != 2 {
				continue
			}
			switch kv[0] {
			case "com.docker.compose.project":
				ct.ComposeProject = kv[1]
			case "com.docker.compose.service":
				ct.ComposeService = kv[1]
			}
		}

		containers = append(containers, ct)
	}

	return true, version, containers
}

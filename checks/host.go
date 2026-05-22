package checks

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	pshost "github.com/shirou/gopsutil/host"
)

// conversion units
const (
	MINUTE = 60
	HOUR   = MINUTE * 60
	DAY    = HOUR * 24
)

// Uptime - returns uptime string
// uptime = "{0} days {1} hours {2} minutes".format(days, hours, minutes)
func Uptime() uint64 {
	boot, _ := pshost.BootTime()
	secondsFromBoot := uint64(time.Now().Unix()) - boot

	// days := secondsFromBoot / DAY
	// hours := (secondsFromBoot % DAY) / HOUR
	// minutes := (secondsFromBoot % HOUR) / MINUTE

	// s := fmt.Sprintf("%v days %v hours %v minutes", days, hours, minutes)

	return secondsFromBoot
}

// // IPAddress - returns machine IP
// func IPAddress() string {
// 	c1, _ := exec.Command("hostname", "-I").Output()
// 	ipOutput := string(c1)
// 	ipList := strings.Split(ipOutput, " ")
// 	if len(ipList) > 0 {
// 		return ipList[0]
// 	}
// 	return ""
// }

// DetectedIpAddresses - returns an []IPAddress object
func DetectedIpAddresses() []IPAddress {
	var ipAddresses []IPAddress
	interfaces, _ := net.Interfaces()
	for _, i := range interfaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			ip, _, _ := net.ParseCIDR(addr.String())
			if ip.IsLoopback() {
				continue
			}
			ipv4 := ip.To4()
			var ipType string
			var subnetMask string
			if ipv4 != nil {
				ipType = "ipv4"
				subnetMask = ipv4.DefaultMask().String()
			} else if ip.To16() != nil {
				ipType = "ipv6"
				subnetMask = "N/A" // IPv6 doesn't use subnet masks in the same way
			} else {
				continue
			}
			ipAddresses = append(ipAddresses, IPAddress{
				IPAddress:     ip.String(),
				InterfaceName: i.Name,
				Type:          ipType,
				HWAddr:        i.HardwareAddr.String(),
				Netmask:       addr.String(),
				CIDR:          addr.String(),
				SubnetMask:    subnetMask,
			})
		}
	}
	return ipAddresses
}

func (p DistroStruct) String() string {
	s, _ := json.Marshal(p)
	return string(s)
}

// Distro - gets distro info
// {'version': '14.04', 'name': 'Ubuntu'}
func Distro() DistroStruct {
	host, _ := pshost.Info()

	d := DistroStruct{
		Hostname:             host.Hostname,
		Uptime:               host.Uptime,
		BootTime:             host.BootTime,
		Procs:                host.Procs,
		OS:                   host.OS,
		Platform:             host.Platform,
		PlatformFamily:       host.PlatformFamily,
		PlatformVersion:      host.PlatformVersion,
		KernelVersion:        host.KernelVersion,
		KernelArch:           host.KernelArch,
		VirtualizationSystem: host.VirtualizationSystem,
		VirtualizationRole:   host.VirtualizationRole,
		HostID:               host.HostID,
	}

	return d
}

// GetMetadataURL - Get metadata URL
func GetMetadataURL(pctx context.Context, provider string, url string) string {
	transport := &http.Transport{DisableKeepAlives: true}
	timeout := 2 * time.Second

	req, RequestErr := http.NewRequest("GET", url, nil)
	if provider == "google" {
		req.Header.Set("Metadata-Flavor", "Google")
	}
	if RequestErr != nil {
		return ""
	}

	client := &http.Client{Transport: transport}

	ctx, cancel := context.WithTimeout(pctx, timeout)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 209 {
		return ""
	}

	data, bodyErr := io.ReadAll(resp.Body)
	if bodyErr != nil {
		return ""
	}

	id := string(data)

	return id
}

// CloudID - Get the instance id
func CloudID(ctx context.Context) string {
	deadline := time.Now().Add(1500 * time.Millisecond)
	ctx, cancelCtx := context.WithDeadline(ctx, deadline)
	defer cancelCtx()

	MetadataURLs := map[string]string{
		"google":       "http://169.254.169.254/computeMetadata/v1/instance/id",
		"amazon":       "http://169.254.169.254/latest/meta-data/instance-id",
		"digitalocean": "http://169.254.169.254/metadata/v1/id",
	}
	var CloudID string
	wg := sync.WaitGroup{}
	for provider, url := range MetadataURLs {
		wg.Add(1)

		go func(provider string, url string) {
			defer wg.Done()
			response := GetMetadataURL(ctx, provider, url)
			if len(response) > 0 {
				CloudID = response
			}

		}(provider, url)

	}

	wg.Wait()

	return CloudID
}

// GetOrCreateMachineID - Generates a machine id for the host
func GetOrCreateMachineID() string {
	// Default machine id path, generated on first install
	var machineidPath = "machine-id"
	var MachineID string
	// First run, generate and save
	if _, err := os.Stat(machineidPath); os.IsNotExist(err) {
		MachineID = GenerateMachineID()
		f, fileError := os.Create(machineidPath)
		if fileError != nil {
			log.Error().Err(fileError).Msg(fileError.Error())
		}
		_, writeMachineidErr := io.WriteString(f, MachineID)
		if writeMachineidErr != nil {
			log.Error().Err(writeMachineidErr).Msg(writeMachineidErr.Error())
		}

		defer f.Close()

	} else {
		file, err := os.Open(machineidPath)
		if err != nil {
			log.Error().Err(err).Msg(err.Error())
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}

		if len(lines) > 0 {
			MachineID = lines[0]
		}
	}

	return MachineID
}

// Hostname - Returns system hostname
func Hostname() string {
	host, _ := os.Hostname()
	return host
}

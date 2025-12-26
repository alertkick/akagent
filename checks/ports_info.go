package checks

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
)

// GetSystemListeningPorts returns all listening ports for system info collection
// This is separate from the monitoring check to avoid circular dependencies
func GetSystemListeningPorts() ([]SystemPortInfo, error) {
	var ports []SystemPortInfo

	// Read TCP ports
	tcpPorts, err := readNetFileForSystemInfo("/proc/net/tcp", "tcp")
	if err == nil {
		ports = append(ports, tcpPorts...)
	}

	// Read TCP6 ports
	tcp6Ports, err := readNetFileForSystemInfo("/proc/net/tcp6", "tcp6")
	if err == nil {
		ports = append(ports, tcp6Ports...)
	}

	// Read UDP ports
	udpPorts, err := readNetFileForSystemInfo("/proc/net/udp", "udp")
	if err == nil {
		ports = append(ports, udpPorts...)
	}

	// Read UDP6 ports
	udp6Ports, err := readNetFileForSystemInfo("/proc/net/udp6", "udp6")
	if err == nil {
		ports = append(ports, udp6Ports...)
	}

	return ports, nil
}

// readNetFileForSystemInfo reads /proc/net/{tcp,tcp6,udp,udp6} and extracts listening ports
func readNetFileForSystemInfo(path string, protocol string) ([]SystemPortInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ports []SystemPortInfo
	scanner := bufio.NewScanner(file)

	// Skip header line
	if !scanner.Scan() {
		return nil, nil
	}

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) < 10 {
			continue
		}

		// Parse local address (field 1)
		localAddr := fields[1]

		// Parse state (field 3) - 0A = LISTEN for TCP, UDP doesn't have LISTEN state
		state := fields[3]

		// For TCP, only include listening sockets (state 0A)
		// For UDP, all bound sockets are considered "listening"
		if strings.HasPrefix(protocol, "tcp") && state != "0A" {
			continue
		}

		// Parse the address and port
		addr, port, err := parseNetAddress(localAddr, protocol)
		if err != nil {
			continue
		}

		// Get inode (field 9)
		inode := fields[9]

		ports = append(ports, SystemPortInfo{
			Port:     port,
			Protocol: protocol,
			Address:  addr,
			Inode:    inode,
		})
	}

	return ports, scanner.Err()
}

// parseNetAddress parses the hex-encoded address from /proc/net files
func parseNetAddress(hexAddr string, protocol string) (string, uint16, error) {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid address format: %s", hexAddr)
	}

	// Parse port (big-endian hex)
	portBytes, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", 0, err
	}
	port := binary.BigEndian.Uint16(portBytes)

	// Parse IP address
	ipBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", 0, err
	}

	var ip net.IP
	if len(ipBytes) == 4 {
		// IPv4 - bytes are in little-endian order per 32-bit word
		ip = net.IP{ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0]}
	} else if len(ipBytes) == 16 {
		// IPv6 - bytes are in little-endian order per 32-bit word
		ip = make(net.IP, 16)
		for i := 0; i < 16; i += 4 {
			ip[i] = ipBytes[i+3]
			ip[i+1] = ipBytes[i+2]
			ip[i+2] = ipBytes[i+1]
			ip[i+3] = ipBytes[i]
		}
	} else {
		return "", 0, fmt.Errorf("invalid IP length: %d", len(ipBytes))
	}

	return ip.String(), port, nil
}


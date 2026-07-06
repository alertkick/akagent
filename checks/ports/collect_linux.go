//go:build linux

package ports

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
)

// GetListeningPorts returns all listening ports on the system
func GetListeningPorts() ([]ListeningPort, error) {
	var ports []ListeningPort

	// Read TCP ports
	tcpPorts, err := readNetFile("/proc/net/tcp", "tcp")
	if err != nil {
		log.Warn().Err(err).Msg("ports.GetListeningPorts - error reading TCP ports")
	} else {
		ports = append(ports, tcpPorts...)
	}

	// Read TCP6 ports
	tcp6Ports, err := readNetFile("/proc/net/tcp6", "tcp6")
	if err != nil {
		log.Warn().Err(err).Msg("ports.GetListeningPorts - error reading TCP6 ports")
	} else {
		ports = append(ports, tcp6Ports...)
	}

	// Read UDP ports
	udpPorts, err := readNetFile("/proc/net/udp", "udp")
	if err != nil {
		log.Warn().Err(err).Msg("ports.GetListeningPorts - error reading UDP ports")
	} else {
		ports = append(ports, udpPorts...)
	}

	// Read UDP6 ports
	udp6Ports, err := readNetFile("/proc/net/udp6", "udp6")
	if err != nil {
		log.Warn().Err(err).Msg("ports.GetListeningPorts - error reading UDP6 ports")
	} else {
		ports = append(ports, udp6Ports...)
	}

	return ports, nil
}

// readNetFile reads /proc/net/{tcp,tcp6,udp,udp6} and extracts listening ports
func readNetFile(path string, protocol string) ([]ListeningPort, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ports []ListeningPort
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

		// Parse local address (field 1), remote address (field 2), state (field 3)
		localAddr := fields[1]
		remoteAddr := fields[2]
		state := fields[3]

		// For TCP, only include listening sockets (state 0A = LISTEN)
		if strings.HasPrefix(protocol, "tcp") && state != "0A" {
			continue
		}

		// For UDP, filter out ephemeral outgoing connections:
		// State 07 = unconnected (listening), 01 = established (outgoing)
		// A listening socket has remote address 00000000:0000 (not connected to a peer)
		if strings.HasPrefix(protocol, "udp") {
			if state != "07" {
				continue
			}
			remoteHex := strings.ReplaceAll(remoteAddr, ":", "")
			isZero := true
			for _, c := range remoteHex {
				if c != '0' {
					isZero = false
					break
				}
			}
			if !isZero {
				continue
			}
		}

		// Parse the address and port
		addr, port, err := parseAddress(localAddr, protocol)
		if err != nil {
			continue
		}

		// Get inode (field 9)
		inode := fields[9]

		ports = append(ports, ListeningPort{
			Port:     port,
			Protocol: protocol,
			Address:  addr,
			Inode:    inode,
		})
	}

	return ports, scanner.Err()
}

// parseAddress parses the hex-encoded address from /proc/net files
func parseAddress(hexAddr string, protocol string) (string, uint16, error) {
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

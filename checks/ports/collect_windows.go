//go:build windows

package ports

import (
	"strconv"
	"strings"

	gopsnet "github.com/shirou/gopsutil/net"
)

// GetListeningPorts returns all listening ports on the system, via
// GetExtendedTcpTable/GetExtendedUdpTable (gopsutil). TCP sockets are
// included only in LISTEN state; UDP sockets are all bound sockets.
// Windows has no socket inode; the owning PID is reported instead and
// Inode carries the PID string so port identity keys stay stable.
func GetListeningPorts() ([]ListeningPort, error) {
	conns, err := gopsnet.Connections("inet")
	if err != nil {
		return nil, err
	}

	var ports []ListeningPort
	for _, conn := range conns {
		isTCP := conn.Type == 1 // SOCK_STREAM
		if isTCP && conn.Status != "LISTEN" {
			continue
		}
		if !isTCP {
			// UDP: only unconnected (listening) sockets
			if conn.Raddr.IP != "" && conn.Raddr.IP != "0.0.0.0" && conn.Raddr.IP != "::" {
				continue
			}
		}

		v6 := strings.Contains(conn.Laddr.IP, ":")
		protocol := "tcp"
		if !isTCP {
			protocol = "udp"
		}
		if v6 {
			protocol += "6"
		}

		ports = append(ports, ListeningPort{
			Port:     uint16(conn.Laddr.Port),
			Protocol: protocol,
			Address:  conn.Laddr.IP,
			PID:      int(conn.Pid),
			Inode:    strconv.Itoa(int(conn.Pid)),
		})
	}
	return ports, nil
}

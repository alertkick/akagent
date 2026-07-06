//go:build linux || windows

package ports

import (
	"akagent/checks"
	"akagent/internal/api"
	"akagent/logger"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	log = logger.Sublogger("host.monitor_ports")
)

func init() {
	checks.Add("host.monitor_ports", func() api.Check {
		return &PortsCheck{
			UUID:          "host.monitor_ports",
			Name:          "host.monitor_ports",
			Label:         "host.monitor_ports",
			CheckType:     "host.monitor_ports",
			interval:      60, // Check every 60 seconds by default
			previousPorts: make(map[string]ListeningPort),
			firstRun:      true,
		}
	})
	checks.AddConfig("host.monitor_ports")
}

// ListeningPort represents a port that is listening on the system
type ListeningPort struct {
	Port        uint16 `json:"port"`
	Protocol    string `json:"protocol"` // tcp, tcp6, udp, udp6
	Address     string `json:"address"`  // IP address binding
	ProcessName string `json:"process_name,omitempty"`
	PID         int    `json:"pid,omitempty"`
	Inode       string `json:"inode"`
}

// PortKey creates a unique key for a listening port
func (p ListeningPort) PortKey() string {
	return fmt.Sprintf("%s:%d:%s", p.Protocol, p.Port, p.Address)
}

// String returns a human-readable description
func (p ListeningPort) String() string {
	return fmt.Sprintf("%s/%d on %s", p.Protocol, p.Port, p.Address)
}

// PortChangeEvent represents a change in listening ports
type PortChangeEvent struct {
	Timestamp   int64         `json:"timestamp"`
	EventType   string        `json:"event_type"` // "port_opened" or "port_closed"
	Port        ListeningPort `json:"port"`
	Description string        `json:"description"`
}

// PortsCheck monitors listening ports on the system
type PortsCheck struct {
	UUID        string
	Name        string
	Label       string
	CheckType   string
	resultsChan chan api.CheckMetricParams
	// goroutine management
	lock          sync.Mutex
	debug         bool
	interval      int
	previousPorts map[string]ListeningPort
	firstRun      bool
}

func (c *PortsCheck) Init(resultsQueue chan api.CheckMetricParams, agentCheck api.AgentCheck) error {
	c.resultsChan = resultsQueue
	c.Label = agentCheck.Label
	if agentCheck.Period != 0 {
		c.interval = agentCheck.Period
	}
	return nil
}

func (c *PortsCheck) Start(stopCtx context.Context, debug bool) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	log.Debug().Msgf("ports.Start - %s monitor started with %d seconds interval", c.Name, c.interval)

	ticker := time.NewTicker(time.Duration(c.interval) * time.Second)
	defer ticker.Stop()

	for {
		if err := c.RunAndSend(); err != nil {
			log.Info().Msgf("ports.Start - can not collect and send metrics, exiting: %s\n", err.Error())
		}
		select {
		case <-stopCtx.Done():
			log.Info().Msgf("ports.Start - %s monitor stopped", c.Name)
			return nil
		case <-ticker.C:
			continue
		}
	}
}

func (c *PortsCheck) Stop() error {
	return nil
}

func (c *PortsCheck) RunAndSend() error {
	log.Debug().Msg("ports.RunAndSend - started collecting listening ports")

	// Get current listening ports
	currentPorts, err := GetListeningPorts()
	if err != nil {
		log.Err(err).Msg("ports.RunAndSend - error getting listening ports")
		return err
	}

	// Create a map for quick lookup
	currentPortsMap := make(map[string]ListeningPort)
	for _, port := range currentPorts {
		currentPortsMap[port.PortKey()] = port
	}

	// Detect changes (only after first run)
	if !c.firstRun {
		changes := c.detectChanges(currentPortsMap)
		for _, change := range changes {
			c.sendSecurityEvent(change)
		}
	}

	// Update previous state
	c.previousPorts = currentPortsMap
	c.firstRun = false

	// Send regular check result with current port inventory
	c.sendPortInventory(currentPorts)

	return nil
}

// detectChanges compares current ports with previous state and returns changes
func (c *PortsCheck) detectChanges(currentPorts map[string]ListeningPort) []PortChangeEvent {
	var changes []PortChangeEvent
	now := time.Now().UnixNano() / int64(time.Millisecond)

	// Check for new ports (opened)
	for key, port := range currentPorts {
		if _, exists := c.previousPorts[key]; !exists {
			changes = append(changes, PortChangeEvent{
				Timestamp:   now,
				EventType:   "port_opened",
				Port:        port,
				Description: fmt.Sprintf("New listening port detected: %s", port.String()),
			})
			log.Info().Msgf("ports.detectChanges - new port opened: %s", port.String())
		}
	}

	// Check for closed ports
	for key, port := range c.previousPorts {
		if _, exists := currentPorts[key]; !exists {
			changes = append(changes, PortChangeEvent{
				Timestamp:   now,
				EventType:   "port_closed",
				Port:        port,
				Description: fmt.Sprintf("Listening port closed: %s", port.String()),
			})
			log.Info().Msgf("ports.detectChanges - port closed: %s", port.String())
		}
	}

	return changes
}

// sendSecurityEvent sends a security event for port changes
func (c *PortsCheck) sendSecurityEvent(event PortChangeEvent) {
	log.Debug().Msgf("ports.sendSecurityEvent - sending security event: %s", event.EventType)

	// Determine priority based on event type and port
	priority := "NOTICE"
	if isHighRiskPort(event.Port.Port) {
		priority = "WARNING"
	}

	// Create metrics for the security event
	metrics := make(map[string]api.Metric)
	metrics["event_type"] = api.Metric{Type: "event_type", Value: event.EventType, Unit: "string"}
	metrics["port"] = api.Metric{Type: "port", Value: strconv.Itoa(int(event.Port.Port)), Unit: "int"}
	metrics["protocol"] = api.Metric{Type: "protocol", Value: event.Port.Protocol, Unit: "string"}
	metrics["address"] = api.Metric{Type: "address", Value: event.Port.Address, Unit: "string"}
	metrics["inode"] = api.Metric{Type: "inode", Value: event.Port.Inode, Unit: "string"}
	metrics["description"] = api.Metric{Type: "description", Value: event.Description, Unit: "string"}
	metrics["priority"] = api.Metric{Type: "priority", Value: priority, Unit: "string"}

	securityEventGroup := api.MetricGroup{
		Prefix:  "security_event",
		Metrics: metrics,
	}

	result := api.CheckMetricParams{
		Timestamp:      event.Timestamp,
		CheckID:        "security.port_change",
		CheckType:      "security.port_change",
		State:          event.EventType,
		Status:         priority,
		MinCheckPeriod: int64(c.interval),
		MetricGroups: []api.MetricGroup{
			securityEventGroup,
		},
	}

	log.Debug().Msgf("ports.sendSecurityEvent - submitting security event: %v", result)
	c.resultsChan <- result
}

// PortsInventory is the inventory data structure sent to endpoint
type PortsInventory struct {
	Ports []ListeningPort `json:"listening_ports"`
}

// sendPortInventory sends the current port inventory as a regular check result
func (c *PortsCheck) sendPortInventory(ports []ListeningPort) {
	metrics := make(map[string]api.Metric)

	// Count ports by protocol
	tcpCount := 0
	tcp6Count := 0
	udpCount := 0
	udp6Count := 0

	// Build port list string
	var portList []string
	for _, port := range ports {
		portList = append(portList, fmt.Sprintf("%d/%s", port.Port, port.Protocol))
		switch port.Protocol {
		case "tcp":
			tcpCount++
		case "tcp6":
			tcp6Count++
		case "udp":
			udpCount++
		case "udp6":
			udp6Count++
		}
	}

	sort.Strings(portList)

	metrics["total_count"] = api.Metric{Type: "total_count", Value: strconv.Itoa(len(ports)), Unit: "int"}
	metrics["tcp_count"] = api.Metric{Type: "tcp_count", Value: strconv.Itoa(tcpCount), Unit: "int"}
	metrics["tcp6_count"] = api.Metric{Type: "tcp6_count", Value: strconv.Itoa(tcp6Count), Unit: "int"}
	metrics["udp_count"] = api.Metric{Type: "udp_count", Value: strconv.Itoa(udpCount), Unit: "int"}
	metrics["udp6_count"] = api.Metric{Type: "udp6_count", Value: strconv.Itoa(udp6Count), Unit: "int"}
	metrics["port_list"] = api.Metric{Type: "port_list", Value: strings.Join(portList, ","), Unit: "string"}

	portMetricsGroup := api.MetricGroup{
		Prefix:  "ports",
		Metrics: metrics,
	}

	// Serialize full inventory data for host_info update
	inventory := PortsInventory{Ports: ports}
	inventoryData, err := json.Marshal(inventory)
	if err != nil {
		log.Warn().Err(err).Msg("failed to marshal ports inventory")
		inventoryData = nil
	}

	result := api.CheckMetricParams{
		Timestamp:      time.Now().UnixNano() / int64(time.Millisecond),
		CheckID:        "host.monitor_ports",
		CheckType:      "host.monitor_ports",
		State:          "ok",
		Status:         "ok",
		MinCheckPeriod: int64(c.interval),
		MetricGroups: []api.MetricGroup{
			portMetricsGroup,
		},
		InventoryData: inventoryData,
	}

	log.Debug().Msgf("ports.sendPortInventory - submitting: %s, total ports: %d", c.Label, len(ports))
	c.resultsChan <- result
}

// isHighRiskPort determines if a port is considered high risk
func isHighRiskPort(port uint16) bool {
	highRiskPorts := map[uint16]bool{
		21:    true, // FTP
		22:    true, // SSH
		23:    true, // Telnet
		25:    true, // SMTP
		53:    true, // DNS
		110:   true, // POP3
		135:   true, // MSRPC
		139:   true, // NetBIOS
		143:   true, // IMAP
		443:   true, // HTTPS
		445:   true, // SMB
		993:   true, // IMAPS
		995:   true, // POP3S
		1433:  true, // MSSQL
		1521:  true, // Oracle
		3306:  true, // MySQL
		3389:  true, // RDP
		5432:  true, // PostgreSQL
		5900:  true, // VNC
		6379:  true, // Redis
		8080:  true, // HTTP Proxy
		27017: true, // MongoDB
	}
	return highRiskPorts[port]
}

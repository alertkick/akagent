package services

import (
	"apagent/checks"
	"apagent/internal/api"
	"apagent/logger"
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	log = logger.Sublogger("host.monitor_services")
)

func init() {
	checks.Add("host.monitor_services", func() api.Check {
		return &ServicesCheck{
			UUID:             "host.monitor_services",
			Name:             "host.monitor_services",
			Label:            "host.monitor_services",
			CheckType:        "host.monitor_services",
			interval:         60, // Check every 60 seconds by default
			previousServices: make(map[string]ServiceInfo),
			firstRun:         true,
		}
	})
	checks.AddConfig("host.monitor_services")
}

// ServiceInfo represents a running service on the system
type ServiceInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Status      string `json:"status"`      // running, stopped, failed, etc.
	Type        string `json:"type"`        // simple, forking, oneshot, etc.
	MainPID     int    `json:"main_pid,omitempty"`
	LoadState   string `json:"load_state"`   // loaded, not-found, masked
	ActiveState string `json:"active_state"` // active, inactive, failed, activating, deactivating
	SubState    string `json:"sub_state"`    // running, dead, exited, etc.
}

// ServiceKey creates a unique key for a service
func (s ServiceInfo) ServiceKey() string {
	return s.Name
}

// String returns a human-readable description
func (s ServiceInfo) String() string {
	return fmt.Sprintf("%s (%s)", s.Name, s.ActiveState)
}

// ServiceChangeEvent represents a change in services
type ServiceChangeEvent struct {
	Timestamp   int64       `json:"timestamp"`
	EventType   string      `json:"event_type"` // "service_started", "service_stopped", "service_failed"
	Service     ServiceInfo `json:"service"`
	Description string      `json:"description"`
}

// ServicesCheck monitors running services on the system
type ServicesCheck struct {
	UUID        string
	Name        string
	Label       string
	CheckType   string
	resultsChan chan api.CheckMetricParams
	// goroutine management
	lock             sync.Mutex
	debug            bool
	interval         int
	previousServices map[string]ServiceInfo
	firstRun         bool
}

func (c *ServicesCheck) Init(resultsQueue chan api.CheckMetricParams, agentCheck api.AgentCheck) error {
	c.resultsChan = resultsQueue
	c.Label = agentCheck.Label
	if agentCheck.Period != 0 {
		c.interval = agentCheck.Period
	}
	return nil
}

func (c *ServicesCheck) Start(stopCtx context.Context, debug bool) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	log.Debug().Msgf("services.Start - %s monitor started with %d seconds interval", c.Name, c.interval)

	ticker := time.NewTicker(time.Duration(c.interval) * time.Second)
	defer ticker.Stop()

	for {
		if err := c.RunAndSend(); err != nil {
			log.Info().Msgf("services.Start - can not collect and send metrics, exiting: %s\n", err.Error())
		}
		select {
		case <-stopCtx.Done():
			log.Info().Msgf("services.Start - %s monitor stopped", c.Name)
			return nil
		case <-ticker.C:
			continue
		}
	}
}

func (c *ServicesCheck) Stop() error {
	return nil
}

func (c *ServicesCheck) RunAndSend() error {
	log.Debug().Msg("services.RunAndSend - started collecting services")

	// Get current services
	currentServices, err := GetRunningServices()
	if err != nil {
		log.Err(err).Msg("services.RunAndSend - error getting services")
		return err
	}

	// Create a map for quick lookup
	currentServicesMap := make(map[string]ServiceInfo)
	for _, svc := range currentServices {
		currentServicesMap[svc.ServiceKey()] = svc
	}

	// Detect changes (only after first run)
	if !c.firstRun {
		changes := c.detectChanges(currentServicesMap)
		for _, change := range changes {
			c.sendHostEvent(change)
		}
	}

	// Update previous state
	c.previousServices = currentServicesMap
	c.firstRun = false

	// Send regular check result with current service inventory
	c.sendServiceInventory(currentServices)

	return nil
}

// detectChanges compares current services with previous state and returns changes
func (c *ServicesCheck) detectChanges(currentServices map[string]ServiceInfo) []ServiceChangeEvent {
	var changes []ServiceChangeEvent
	now := time.Now().UnixNano() / int64(time.Millisecond)

	// Check for new services or state changes
	for key, svc := range currentServices {
		prevSvc, exists := c.previousServices[key]
		if !exists {
			// New service detected
			if svc.ActiveState == "active" {
				changes = append(changes, ServiceChangeEvent{
					Timestamp:   now,
					EventType:   "service_started",
					Service:     svc,
					Description: fmt.Sprintf("New service started: %s", svc.String()),
				})
				log.Info().Msgf("services.detectChanges - new service started: %s", svc.String())
			}
		} else if prevSvc.ActiveState != svc.ActiveState {
			// State changed
			var eventType string
			switch svc.ActiveState {
			case "active":
				eventType = "service_started"
			case "inactive":
				eventType = "service_stopped"
			case "failed":
				eventType = "service_failed"
			default:
				eventType = "service_changed"
			}
			changes = append(changes, ServiceChangeEvent{
				Timestamp:   now,
				EventType:   eventType,
				Service:     svc,
				Description: fmt.Sprintf("Service %s changed from %s to %s", svc.Name, prevSvc.ActiveState, svc.ActiveState),
			})
			log.Info().Msgf("services.detectChanges - service state changed: %s (%s -> %s)", svc.Name, prevSvc.ActiveState, svc.ActiveState)
		}
	}

	// Check for stopped services (removed from list)
	for key, prevSvc := range c.previousServices {
		if _, exists := currentServices[key]; !exists {
			if prevSvc.ActiveState == "active" {
				changes = append(changes, ServiceChangeEvent{
					Timestamp:   now,
					EventType:   "service_stopped",
					Service:     prevSvc,
					Description: fmt.Sprintf("Service stopped: %s", prevSvc.String()),
				})
				log.Info().Msgf("services.detectChanges - service stopped: %s", prevSvc.String())
			}
		}
	}

	return changes
}

// sendHostEvent sends a host event for service changes
func (c *ServicesCheck) sendHostEvent(event ServiceChangeEvent) {
	log.Debug().Msgf("services.sendHostEvent - sending host event: %s", event.EventType)

	// Determine priority based on event type
	priority := "NOTICE"
	if event.EventType == "service_failed" {
		priority = "WARNING"
	}
	if isCriticalService(event.Service.Name) && event.EventType != "service_started" {
		priority = "CRITICAL"
	}

	// Create metrics for the host event
	metrics := make(map[string]api.Metric)
	metrics["event_type"] = api.Metric{Type: "event_type", Value: event.EventType, Unit: "string"}
	metrics["service_name"] = api.Metric{Type: "service_name", Value: event.Service.Name, Unit: "string"}
	metrics["active_state"] = api.Metric{Type: "active_state", Value: event.Service.ActiveState, Unit: "string"}
	metrics["sub_state"] = api.Metric{Type: "sub_state", Value: event.Service.SubState, Unit: "string"}
	metrics["description"] = api.Metric{Type: "description", Value: event.Description, Unit: "string"}
	metrics["priority"] = api.Metric{Type: "priority", Value: priority, Unit: "string"}
	if event.Service.MainPID > 0 {
		metrics["main_pid"] = api.Metric{Type: "main_pid", Value: strconv.Itoa(event.Service.MainPID), Unit: "int"}
	}

	hostEventGroup := api.MetricGroup{
		Prefix:  "host_event",
		Metrics: metrics,
	}

	result := api.CheckMetricParams{
		Timestamp:      event.Timestamp,
		CheckID:        "host.service_change",
		CheckType:      "host.service_change",
		State:          event.EventType,
		Status:         priority,
		MinCheckPeriod: int64(c.interval),
		MetricGroups: []api.MetricGroup{
			hostEventGroup,
		},
	}

	log.Debug().Msgf("services.sendHostEvent - submitting host event: %v", result)
	c.resultsChan <- result
}

// ServicesInventory is the inventory data structure sent to endpoint
type ServicesInventory struct {
	Services []ServiceInfo `json:"services"`
}

// sendServiceInventory sends the current service inventory as a regular check result
func (c *ServicesCheck) sendServiceInventory(services []ServiceInfo) {
	metrics := make(map[string]api.Metric)

	// Count services by state
	activeCount := 0
	inactiveCount := 0
	failedCount := 0

	// Build service lists
	var activeServices []string
	var failedServices []string

	for _, svc := range services {
		switch svc.ActiveState {
		case "active":
			activeCount++
			activeServices = append(activeServices, svc.Name)
		case "inactive":
			inactiveCount++
		case "failed":
			failedCount++
			failedServices = append(failedServices, svc.Name)
		}
	}

	sort.Strings(activeServices)
	sort.Strings(failedServices)

	metrics["total_count"] = api.Metric{Type: "total_count", Value: strconv.Itoa(len(services)), Unit: "int"}
	metrics["active_count"] = api.Metric{Type: "active_count", Value: strconv.Itoa(activeCount), Unit: "int"}
	metrics["inactive_count"] = api.Metric{Type: "inactive_count", Value: strconv.Itoa(inactiveCount), Unit: "int"}
	metrics["failed_count"] = api.Metric{Type: "failed_count", Value: strconv.Itoa(failedCount), Unit: "int"}
	
	// Limit list sizes to avoid very long messages
	if len(activeServices) > 50 {
		activeServices = activeServices[:50]
	}
	if len(failedServices) > 20 {
		failedServices = failedServices[:20]
	}
	
	metrics["active_services"] = api.Metric{Type: "active_services", Value: strings.Join(activeServices, ","), Unit: "string"}
	metrics["failed_services"] = api.Metric{Type: "failed_services", Value: strings.Join(failedServices, ","), Unit: "string"}

	serviceMetricsGroup := api.MetricGroup{
		Prefix:  "services",
		Metrics: metrics,
	}

	// Serialize full inventory data for host_info update
	inventory := ServicesInventory{Services: services}
	inventoryData, err := json.Marshal(inventory)
	if err != nil {
		log.Warn().Err(err).Msg("failed to marshal services inventory")
		inventoryData = nil
	}

	result := api.CheckMetricParams{
		Timestamp:      time.Now().UnixNano() / int64(time.Millisecond),
		CheckID:        "host.monitor_services",
		CheckType:      "host.monitor_services",
		State:          "ok",
		Status:         "ok",
		MinCheckPeriod: int64(c.interval),
		MetricGroups: []api.MetricGroup{
			serviceMetricsGroup,
		},
		InventoryData: inventoryData,
	}

	log.Debug().Msgf("services.sendServiceInventory - submitting: %s, total services: %d", c.Label, len(services))
	c.resultsChan <- result
}

// isCriticalService determines if a service is considered critical
func isCriticalService(name string) bool {
	criticalServices := map[string]bool{
		"sshd.service":       true,
		"ssh.service":        true,
		"systemd-journald.service": true,
		"systemd-udevd.service":    true,
		"systemd-logind.service":   true,
		"cron.service":       true,
		"rsyslog.service":    true,
		"dbus.service":       true,
		"NetworkManager.service":   true,
		"docker.service":     true,
		"containerd.service": true,
		"kubelet.service":    true,
	}
	return criticalServices[name]
}

// GetRunningServices returns all systemd services on the system
func GetRunningServices() ([]ServiceInfo, error) {
	// Use systemctl to list all services with their status
	cmd := exec.Command("systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain", "--no-legend")
	output, err := cmd.Output()
	if err != nil {
		// Fallback: try without --plain flag for older systemd versions
		cmd = exec.Command("systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend")
		output, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to run systemctl: %w", err)
		}
	}

	var services []ServiceInfo
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Parse line: UNIT LOAD ACTIVE SUB DESCRIPTION
		// Example: ssh.service loaded active running OpenBSD Secure Shell server
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		name := fields[0]
		loadState := fields[1]
		activeState := fields[2]
		subState := fields[3]

		// Only include actual service units (not templates)
		if !strings.HasSuffix(name, ".service") {
			continue
		}

		// Get more details for active services
		svc := ServiceInfo{
			Name:        name,
			LoadState:   loadState,
			ActiveState: activeState,
			SubState:    subState,
			Status:      activeState,
		}

		// Try to get PID for running services
		if activeState == "active" && subState == "running" {
			pid := getServicePID(name)
			if pid > 0 {
				svc.MainPID = pid
			}
		}

		services = append(services, svc)
	}

	return services, scanner.Err()
}

// getServicePID gets the main PID of a running service
func getServicePID(serviceName string) int {
	cmd := exec.Command("systemctl", "show", serviceName, "--property=MainPID", "--value")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	pidStr := strings.TrimSpace(string(output))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0
	}

	return pid
}

// GetAllServicesForSystemInfo returns a simplified list of services for system info
// This is used by the periodic system info collection, not the check monitoring
func GetAllServicesForSystemInfo() ([]ServiceInfo, error) {
	return GetRunningServices()
}


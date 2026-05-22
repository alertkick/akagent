//go:build linux

package docker

import (
	"akagent/checks"
	"akagent/internal/api"
	"akagent/logger"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	log = logger.Sublogger("host.monitor_docker")
)

func init() {
	checks.Add("host.monitor_docker", func() api.Check {
		return &DockerCheck{
			UUID:               "host.monitor_docker",
			Name:               "host.monitor_docker",
			Label:              "host.monitor_docker",
			CheckType:          "host.monitor_docker",
			interval:           30,
			previousContainers: make(map[string]ContainerInfo),
			firstRun:           true,
		}
	})
	checks.AddConfig("host.monitor_docker")
}

// ContainerInfo represents a Docker container
type ContainerInfo struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Image          string `json:"image"`
	Status         string `json:"status"`           // e.g. "Up 3 hours", "Exited (0) 5 minutes ago"
	State          string `json:"state"`            // running, exited, paused, dead, created, restarting
	Ports          string `json:"ports"`
	Networks       string `json:"networks"`
	ComposeProject string `json:"compose_project"`
	ComposeService string `json:"compose_service"`
	HealthStatus   string `json:"health_status"`    // healthy, unhealthy, starting, none
	CreatedAt      string `json:"created_at"`
	// Stats (only for running containers)
	CPUPercent   float64 `json:"cpu_percent"`
	MemoryUsage  uint64  `json:"memory_usage"`
	MemoryLimit  uint64  `json:"memory_limit"`
	MemoryPercent float64 `json:"memory_percent"`
}

// DockerInventory is the inventory data sent to the endpoint
type DockerInventory struct {
	DockerAvailable bool            `json:"docker_available"`
	DockerVersion   string          `json:"docker_version"`
	Containers      []ContainerInfo `json:"containers"`
}

// DockerCheckDetails represents the check's configuration from Details field
type DockerCheckDetails struct {
	RequiredContainers []string `json:"required_containers"`
}

// DockerCheck monitors Docker containers
type DockerCheck struct {
	UUID        string
	Name        string
	Label       string
	CheckType   string
	resultsChan chan api.CheckMetricParams
	lock             sync.Mutex
	debug            bool
	interval         int
	previousContainers map[string]ContainerInfo
	firstRun           bool
	requiredContainers []string

	// Docker availability caching
	dockerAvailable     bool
	dockerVersion       string
	lastAvailCheck      time.Time
	availCheckInterval  time.Duration
}

func (c *DockerCheck) Init(resultsQueue chan api.CheckMetricParams, agentCheck api.AgentCheck) error {
	c.resultsChan = resultsQueue
	c.Label = agentCheck.Label
	if agentCheck.Period != 0 {
		c.interval = agentCheck.Period
	}
	c.availCheckInterval = 5 * time.Minute

	// Parse required containers from check details
	if len(agentCheck.Details) > 0 {
		var details DockerCheckDetails
		if err := json.Unmarshal(agentCheck.Details, &details); err == nil {
			c.requiredContainers = details.RequiredContainers
		}
	}

	return nil
}

func (c *DockerCheck) Start(stopCtx context.Context, debug bool) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	log.Debug().Msgf("docker.Start - monitor started with %ds interval", c.interval)

	ticker := time.NewTicker(time.Duration(c.interval) * time.Second)
	defer ticker.Stop()

	for {
		if err := c.RunAndSend(); err != nil {
			log.Info().Msgf("docker.Start - error: %s", err.Error())
		}
		select {
		case <-stopCtx.Done():
			log.Info().Msg("docker.Start - monitor stopped")
			return nil
		case <-ticker.C:
			continue
		}
	}
}

func (c *DockerCheck) Stop() error {
	return nil
}

func (c *DockerCheck) RunAndSend() error {
	log.Debug().Msg("docker.RunAndSend - collecting container data")

	// Check Docker availability (with caching)
	if time.Since(c.lastAvailCheck) > c.availCheckInterval || c.lastAvailCheck.IsZero() {
		c.checkDockerAvailability()
		c.lastAvailCheck = time.Now()
	}

	if !c.dockerAvailable {
		c.sendInventory(DockerInventory{DockerAvailable: false})
		return nil
	}

	// Get all containers
	containers, err := c.getContainers()
	if err != nil {
		log.Err(err).Msg("docker.RunAndSend - error listing containers")
		return err
	}

	// Get stats for running containers
	c.enrichWithStats(containers)

	// Get health status
	c.enrichWithHealth(containers)

	// Build current map
	currentMap := make(map[string]ContainerInfo)
	for _, ct := range containers {
		currentMap[ct.Name] = ct
	}

	// Detect changes (skip first run)
	if !c.firstRun {
		changes := c.detectChanges(currentMap)
		for _, change := range changes {
			c.sendContainerEvent(change)
		}

		// Check required containers
		c.checkRequiredContainers(currentMap)
	}

	c.previousContainers = currentMap
	c.firstRun = false

	// Send inventory + metrics
	inventory := DockerInventory{
		DockerAvailable: true,
		DockerVersion:   c.dockerVersion,
		Containers:      containers,
	}
	c.sendInventory(inventory)
	c.sendMetrics(containers)

	return nil
}

func (c *DockerCheck) checkDockerAvailability() {
	cmd := exec.Command("docker", "info", "--format", "{{.ServerVersion}}")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Info().Err(err).Msgf("docker.checkAvailability - Docker not available: %s", strings.TrimSpace(string(output)))
		c.dockerAvailable = false
		c.dockerVersion = ""
		return
	}
	c.dockerAvailable = true
	c.dockerVersion = strings.TrimSpace(string(output))
	log.Debug().Msgf("docker.checkAvailability - Docker %s available", c.dockerVersion)
}

func (c *DockerCheck) getContainers() ([]ContainerInfo, error) {
	format := "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.State}}\t{{.Ports}}\t{{.Networks}}\t{{.Labels}}\t{{.CreatedAt}}"
	cmd := exec.Command("docker", "ps", "-a", "--no-trunc", "--format", format)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker ps failed: %w", err)
	}

	var containers []ContainerInfo
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 9)
		if len(fields) < 9 {
			continue
		}

		name := strings.TrimPrefix(fields[1], "/")
		labels := fields[7]

		ct := ContainerInfo{
			ID:        fields[0],
			Name:      name,
			Image:     fields[2],
			Status:    fields[3],
			State:     fields[4],
			Ports:     fields[5],
			Networks:  fields[6],
			CreatedAt: fields[8],
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

	return containers, nil
}

func (c *DockerCheck) enrichWithStats(containers []ContainerInfo) {
	// Collect IDs of running containers
	var runningIDs []string
	idxMap := make(map[string]int)
	for i, ct := range containers {
		if ct.State == "running" {
			runningIDs = append(runningIDs, ct.ID)
			idxMap[ct.ID] = i
		}
	}

	if len(runningIDs) == 0 {
		return
	}

	format := "{{.ID}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}"
	args := append([]string{"stats", "--no-stream", "--no-trunc", "--format", format}, runningIDs...)
	cmd := exec.Command("docker", args...)
	output, err := cmd.Output()
	if err != nil {
		log.Debug().Err(err).Msg("docker stats failed")
		return
	}

	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 4)
		if len(fields) < 4 {
			continue
		}
		id := fields[0]
		idx, ok := idxMap[id]
		if !ok {
			continue
		}

		// Parse CPU percent (e.g. "0.15%")
		cpuStr := strings.TrimSuffix(strings.TrimSpace(fields[1]), "%")
		cpu, _ := strconv.ParseFloat(cpuStr, 64)
		containers[idx].CPUPercent = cpu

		// Parse memory usage (e.g. "128MiB / 8GiB")
		memParts := strings.SplitN(fields[2], " / ", 2)
		if len(memParts) == 2 {
			containers[idx].MemoryUsage = parseMemoryValue(strings.TrimSpace(memParts[0]))
			containers[idx].MemoryLimit = parseMemoryValue(strings.TrimSpace(memParts[1]))
		}

		// Parse memory percent
		memPctStr := strings.TrimSuffix(strings.TrimSpace(fields[3]), "%")
		memPct, _ := strconv.ParseFloat(memPctStr, 64)
		containers[idx].MemoryPercent = memPct
	}
}

func (c *DockerCheck) enrichWithHealth(containers []ContainerInfo) {
	var ids []string
	idxMap := make(map[string]int)
	for i, ct := range containers {
		ids = append(ids, ct.ID)
		idxMap[ct.ID] = i
	}

	if len(ids) == 0 {
		return
	}

	for _, ct := range containers {
		idx := idxMap[ct.ID]
		cmd := exec.Command("docker", "inspect", "--format", "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}", ct.ID)
		output, err := cmd.Output()
		if err != nil {
			containers[idx].HealthStatus = "none"
			continue
		}
		containers[idx].HealthStatus = strings.TrimSpace(string(output))
	}
}

// ContainerChangeEvent represents a Docker container state change
type ContainerChangeEvent struct {
	Timestamp   int64  `json:"timestamp"`
	EventType   string `json:"event_type"`
	Name        string `json:"container_name"`
	Image       string `json:"image"`
	Description string `json:"description"`
	Priority    string `json:"priority"`
}

func (c *DockerCheck) detectChanges(current map[string]ContainerInfo) []ContainerChangeEvent {
	var changes []ContainerChangeEvent
	now := time.Now().UnixNano() / int64(time.Millisecond)

	// Check for state changes and new containers
	for name, ct := range current {
		prev, exists := c.previousContainers[name]
		if !exists {
			if ct.State == "running" {
				changes = append(changes, ContainerChangeEvent{
					Timestamp:   now,
					EventType:   "container_started",
					Name:        name,
					Image:       ct.Image,
					Description: fmt.Sprintf("Container started: %s (%s)", name, ct.Image),
					Priority:    "NOTICE",
				})
			}
		} else if prev.State != ct.State {
			var eventType, priority string
			switch ct.State {
			case "running":
				eventType = "container_started"
				priority = "NOTICE"
			case "exited":
				eventType = "container_stopped"
				priority = "WARNING"
			case "dead":
				eventType = "container_died"
				priority = "CRITICAL"
			default:
				eventType = "container_changed"
				priority = "NOTICE"
			}
			changes = append(changes, ContainerChangeEvent{
				Timestamp:   now,
				EventType:   eventType,
				Name:        name,
				Image:       ct.Image,
				Description: fmt.Sprintf("Container %s changed from %s to %s", name, prev.State, ct.State),
				Priority:    priority,
			})
		}
	}

	// Check for removed containers
	for name, prev := range c.previousContainers {
		if _, exists := current[name]; !exists {
			if prev.State == "running" {
				changes = append(changes, ContainerChangeEvent{
					Timestamp:   now,
					EventType:   "container_stopped",
					Name:        name,
					Image:       prev.Image,
					Description: fmt.Sprintf("Container removed: %s (%s)", name, prev.Image),
					Priority:    "WARNING",
				})
			}
		}
	}

	return changes
}

func (c *DockerCheck) checkRequiredContainers(current map[string]ContainerInfo) {
	now := time.Now().UnixNano() / int64(time.Millisecond)
	for _, reqName := range c.requiredContainers {
		ct, exists := current[reqName]
		if !exists || ct.State != "running" {
			c.sendContainerEvent(ContainerChangeEvent{
				Timestamp:   now,
				EventType:   "required_container_stopped",
				Name:        reqName,
				Image:       ct.Image,
				Description: fmt.Sprintf("Required container not running: %s", reqName),
				Priority:    "CRITICAL",
			})
		}
	}
}

func (c *DockerCheck) sendContainerEvent(event ContainerChangeEvent) {
	metrics := make(map[string]api.Metric)
	metrics["event_type"] = api.Metric{Type: "event_type", Value: event.EventType, Unit: "string"}
	metrics["container_name"] = api.Metric{Type: "container_name", Value: event.Name, Unit: "string"}
	metrics["image"] = api.Metric{Type: "image", Value: event.Image, Unit: "string"}
	metrics["description"] = api.Metric{Type: "description", Value: event.Description, Unit: "string"}
	metrics["priority"] = api.Metric{Type: "priority", Value: event.Priority, Unit: "string"}

	eventGroup := api.MetricGroup{
		Prefix:  "host_event",
		Metrics: metrics,
	}

	result := api.CheckMetricParams{
		Timestamp:      event.Timestamp,
		CheckID:        "host.docker_change",
		CheckType:      "host.docker_change",
		State:          event.EventType,
		Status:         event.Priority,
		MinCheckPeriod: int64(c.interval),
		MetricGroups:   []api.MetricGroup{eventGroup},
	}

	c.resultsChan <- result
}

func (c *DockerCheck) sendInventory(inventory DockerInventory) {
	inventoryData, err := json.Marshal(inventory)
	if err != nil {
		log.Warn().Err(err).Msg("failed to marshal docker inventory")
		return
	}

	result := api.CheckMetricParams{
		Timestamp:      time.Now().UnixNano() / int64(time.Millisecond),
		CheckID:        "host.monitor_docker",
		CheckType:      "host.monitor_docker",
		State:          "ok",
		Status:         "ok",
		MinCheckPeriod: int64(c.interval),
		InventoryData:  inventoryData,
	}

	c.resultsChan <- result
}

func (c *DockerCheck) sendMetrics(containers []ContainerInfo) {
	metrics := make(map[string]api.Metric)

	runningCount := 0
	stoppedCount := 0
	healthyCount := 0
	unhealthyCount := 0

	for _, ct := range containers {
		switch ct.State {
		case "running":
			runningCount++
		default:
			stoppedCount++
		}
		switch ct.HealthStatus {
		case "healthy":
			healthyCount++
		case "unhealthy":
			unhealthyCount++
		}
	}

	metrics["total_count"] = api.Metric{Type: "total_count", Value: strconv.Itoa(len(containers)), Unit: "int"}
	metrics["running_count"] = api.Metric{Type: "running_count", Value: strconv.Itoa(runningCount), Unit: "int"}
	metrics["stopped_count"] = api.Metric{Type: "stopped_count", Value: strconv.Itoa(stoppedCount), Unit: "int"}
	metrics["healthy_count"] = api.Metric{Type: "healthy_count", Value: strconv.Itoa(healthyCount), Unit: "int"}
	metrics["unhealthy_count"] = api.Metric{Type: "unhealthy_count", Value: strconv.Itoa(unhealthyCount), Unit: "int"}

	summaryGroup := api.MetricGroup{
		Prefix:  "docker",
		Metrics: metrics,
	}

	// Per-container metrics
	var perContainerGroups []api.MetricGroup
	for _, ct := range containers {
		if ct.State != "running" {
			continue
		}
		sanitized := sanitizeContainerName(ct.Name)
		ctMetrics := make(map[string]api.Metric)
		ctMetrics["cpu_percent"] = api.Metric{Type: "cpu_percent", Value: fmt.Sprintf("%.2f", ct.CPUPercent), Unit: "percent"}
		ctMetrics["memory_usage"] = api.Metric{Type: "memory_usage", Value: strconv.FormatUint(ct.MemoryUsage, 10), Unit: "bytes"}
		ctMetrics["memory_limit"] = api.Metric{Type: "memory_limit", Value: strconv.FormatUint(ct.MemoryLimit, 10), Unit: "bytes"}
		ctMetrics["memory_percent"] = api.Metric{Type: "memory_percent", Value: fmt.Sprintf("%.2f", ct.MemoryPercent), Unit: "percent"}

		perContainerGroups = append(perContainerGroups, api.MetricGroup{
			Prefix:  "docker.container." + sanitized,
			Metrics: ctMetrics,
		})
	}

	allGroups := []api.MetricGroup{summaryGroup}
	allGroups = append(allGroups, perContainerGroups...)

	result := api.CheckMetricParams{
		Timestamp:      time.Now().UnixNano() / int64(time.Millisecond),
		CheckID:        "host.monitor_docker",
		CheckType:      "host.monitor_docker",
		State:          "ok",
		Status:         "ok",
		MinCheckPeriod: int64(c.interval),
		MetricGroups:   allGroups,
	}

	c.resultsChan <- result
}

// sanitizeContainerName makes a container name safe for metric paths
func sanitizeContainerName(name string) string {
	name = strings.TrimPrefix(name, "/")
	name = strings.ReplaceAll(name, ".", "-")
	return name
}

// parseMemoryValue parses Docker memory strings like "128MiB", "2.5GiB", "512KiB"
func parseMemoryValue(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}

	multiplier := uint64(1)
	numStr := s

	if strings.HasSuffix(s, "GiB") {
		multiplier = 1024 * 1024 * 1024
		numStr = strings.TrimSuffix(s, "GiB")
	} else if strings.HasSuffix(s, "MiB") {
		multiplier = 1024 * 1024
		numStr = strings.TrimSuffix(s, "MiB")
	} else if strings.HasSuffix(s, "KiB") {
		multiplier = 1024
		numStr = strings.TrimSuffix(s, "KiB")
	} else if strings.HasSuffix(s, "B") {
		numStr = strings.TrimSuffix(s, "B")
	}

	val, err := strconv.ParseFloat(strings.TrimSpace(numStr), 64)
	if err != nil {
		return 0
	}

	return uint64(val * float64(multiplier))
}

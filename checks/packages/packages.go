//go:build linux || windows

package packages

import (
	"akagent/checks"
	"akagent/internal/api"
	"akagent/logger"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"
)

var (
	log = logger.Sublogger("host.monitor_packages")
)

func init() {
	checks.Add("host.monitor_packages", func() api.Check {
		return &PackagesCheck{
			UUID:             "host.monitor_packages",
			Name:             "host.monitor_packages",
			Label:            "host.monitor_packages",
			CheckType:        "host.monitor_packages",
			interval:         300, // Check every 5 minutes by default (packages change less frequently)
			previousPackages: make(map[string]PackageInfo),
			firstRun:         true,
		}
	})
	checks.AddConfig("host.monitor_packages")
}

// PackageInfo represents an installed package on the system
type PackageInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// PackageKey creates a unique key for a package
func (p PackageInfo) PackageKey() string {
	return p.Name
}

// String returns a human-readable description
func (p PackageInfo) String() string {
	return fmt.Sprintf("%s (%s)", p.Name, p.Version)
}

// PackageChangeEvent represents a change in packages
type PackageChangeEvent struct {
	Timestamp   int64       `json:"timestamp"`
	EventType   string      `json:"event_type"` // "package_installed", "package_removed", "package_upgraded"
	Package     PackageInfo `json:"package"`
	OldVersion  string      `json:"old_version,omitempty"`
	Description string      `json:"description"`
}

// PackagesCheck monitors installed packages on the system
type PackagesCheck struct {
	UUID        string
	Name        string
	Label       string
	CheckType   string
	resultsChan chan api.CheckMetricParams
	// goroutine management
	lock             sync.Mutex
	debug            bool
	interval         int
	previousPackages map[string]PackageInfo
	firstRun         bool
}

func (c *PackagesCheck) Init(resultsQueue chan api.CheckMetricParams, agentCheck api.AgentCheck) error {
	c.resultsChan = resultsQueue
	c.Label = agentCheck.Label
	if agentCheck.Period != 0 {
		c.interval = agentCheck.Period
	}
	return nil
}

func (c *PackagesCheck) Start(stopCtx context.Context, debug bool) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	log.Debug().Msgf("packages.Start - %s monitor started with %d seconds interval", c.Name, c.interval)

	ticker := time.NewTicker(time.Duration(c.interval) * time.Second)
	defer ticker.Stop()

	for {
		if err := c.RunAndSend(); err != nil {
			log.Info().Msgf("packages.Start - can not collect and send metrics, exiting: %s\n", err.Error())
		}
		select {
		case <-stopCtx.Done():
			log.Info().Msgf("packages.Start - %s monitor stopped", c.Name)
			return nil
		case <-ticker.C:
			continue
		}
	}
}

func (c *PackagesCheck) Stop() error {
	return nil
}

func (c *PackagesCheck) RunAndSend() error {
	log.Debug().Msg("packages.RunAndSend - started collecting packages")

	// Get current packages
	currentPackages, err := GetInstalledPackages()
	if err != nil {
		log.Err(err).Msg("packages.RunAndSend - error getting packages")
		return err
	}

	// Create a map for quick lookup
	currentPackagesMap := make(map[string]PackageInfo)
	for _, pkg := range currentPackages {
		currentPackagesMap[pkg.PackageKey()] = pkg
	}

	// Detect changes (only after first run)
	if !c.firstRun {
		changes := c.detectChanges(currentPackagesMap)
		for _, change := range changes {
			c.sendHostEvent(change)
		}
	}

	// Update previous state
	c.previousPackages = currentPackagesMap
	c.firstRun = false

	// Send regular check result with current package inventory
	c.sendPackageInventory(currentPackages)

	return nil
}

// detectChanges compares current packages with previous state and returns changes
func (c *PackagesCheck) detectChanges(currentPackages map[string]PackageInfo) []PackageChangeEvent {
	var changes []PackageChangeEvent
	now := time.Now().UnixNano() / int64(time.Millisecond)

	// Check for new packages or version changes (upgrades)
	for key, pkg := range currentPackages {
		prevPkg, exists := c.previousPackages[key]
		if !exists {
			// New package installed
			changes = append(changes, PackageChangeEvent{
				Timestamp:   now,
				EventType:   "package_installed",
				Package:     pkg,
				Description: fmt.Sprintf("Package installed: %s version %s", pkg.Name, pkg.Version),
			})
			log.Info().Msgf("packages.detectChanges - package installed: %s", pkg.String())
		} else if prevPkg.Version != pkg.Version {
			// Package upgraded
			changes = append(changes, PackageChangeEvent{
				Timestamp:   now,
				EventType:   "package_upgraded",
				Package:     pkg,
				OldVersion:  prevPkg.Version,
				Description: fmt.Sprintf("Package upgraded: %s from %s to %s", pkg.Name, prevPkg.Version, pkg.Version),
			})
			log.Info().Msgf("packages.detectChanges - package upgraded: %s (%s -> %s)", pkg.Name, prevPkg.Version, pkg.Version)
		}
	}

	// Check for removed packages
	for key, prevPkg := range c.previousPackages {
		if _, exists := currentPackages[key]; !exists {
			changes = append(changes, PackageChangeEvent{
				Timestamp:   now,
				EventType:   "package_removed",
				Package:     prevPkg,
				Description: fmt.Sprintf("Package removed: %s version %s", prevPkg.Name, prevPkg.Version),
			})
			log.Info().Msgf("packages.detectChanges - package removed: %s", prevPkg.String())
		}
	}

	return changes
}

// sendHostEvent sends a host event for package changes
func (c *PackagesCheck) sendHostEvent(event PackageChangeEvent) {
	log.Debug().Msgf("packages.sendHostEvent - sending host event: %s", event.EventType)

	// Determine priority based on event type and package criticality
	priority := "NOTICE"
	if isCriticalPackage(event.Package.Name) {
		priority = "WARNING"
	}
	if isSecurityPackage(event.Package.Name) && event.EventType == "package_removed" {
		priority = "CRITICAL"
	}

	// Create metrics for the host event
	metrics := make(map[string]api.Metric)
	metrics["event_type"] = api.Metric{Type: "event_type", Value: event.EventType, Unit: "string"}
	metrics["package_name"] = api.Metric{Type: "package_name", Value: event.Package.Name, Unit: "string"}
	metrics["package_version"] = api.Metric{Type: "package_version", Value: event.Package.Version, Unit: "string"}
	metrics["description"] = api.Metric{Type: "description", Value: event.Description, Unit: "string"}
	metrics["priority"] = api.Metric{Type: "priority", Value: priority, Unit: "string"}
	if event.OldVersion != "" {
		metrics["old_version"] = api.Metric{Type: "old_version", Value: event.OldVersion, Unit: "string"}
	}

	hostEventGroup := api.MetricGroup{
		Prefix:  "host_event",
		Metrics: metrics,
	}

	result := api.CheckMetricParams{
		Timestamp:      event.Timestamp,
		CheckID:        "host.package_change",
		CheckType:      "host.package_change",
		State:          event.EventType,
		Status:         priority,
		MinCheckPeriod: int64(c.interval),
		MetricGroups: []api.MetricGroup{
			hostEventGroup,
		},
	}

	log.Debug().Msgf("packages.sendHostEvent - submitting host event: %v", result)
	c.resultsChan <- result
}

// PackagesInventory is the inventory data structure sent to endpoint
type PackagesInventory struct {
	Packages []PackageInfo `json:"packages"`
}

// sendPackageInventory sends the current package inventory as a regular check result
func (c *PackagesCheck) sendPackageInventory(packages []PackageInfo) {
	metrics := make(map[string]api.Metric)

	// Sort packages by name for consistent output
	sort.Slice(packages, func(i, j int) bool {
		return packages[i].Name < packages[j].Name
	})

	metrics["total_count"] = api.Metric{Type: "total_count", Value: strconv.Itoa(len(packages)), Unit: "int"}

	// Count security-related packages
	securityCount := 0
	for _, pkg := range packages {
		if isSecurityPackage(pkg.Name) {
			securityCount++
		}
	}
	metrics["security_packages_count"] = api.Metric{Type: "security_packages_count", Value: strconv.Itoa(securityCount), Unit: "int"}

	packageMetricsGroup := api.MetricGroup{
		Prefix:  "packages",
		Metrics: metrics,
	}

	// Serialize full inventory data for host_info update
	inventory := PackagesInventory{Packages: packages}
	inventoryData, err := json.Marshal(inventory)
	if err != nil {
		log.Warn().Err(err).Msg("failed to marshal packages inventory")
		inventoryData = nil
	}

	result := api.CheckMetricParams{
		Timestamp:      time.Now().UnixNano() / int64(time.Millisecond),
		CheckID:        "host.monitor_packages",
		CheckType:      "host.monitor_packages",
		State:          "ok",
		Status:         "ok",
		MinCheckPeriod: int64(c.interval),
		MetricGroups: []api.MetricGroup{
			packageMetricsGroup,
		},
		InventoryData: inventoryData,
	}

	log.Debug().Msgf("packages.sendPackageInventory - submitting: %s, total packages: %d", c.Label, len(packages))
	c.resultsChan <- result
}

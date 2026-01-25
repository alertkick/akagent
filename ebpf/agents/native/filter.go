package native

import (
	"strings"
	"sync/atomic"

	"apagent/ebpf"
)

// EventFilter provides efficient filtering of security events
type EventFilter struct {
	config *Config

	// Pre-computed maps for O(1) lookup
	includeUIDs  map[int]struct{}
	excludeUIDs  map[int]struct{}
	includeComms map[string]struct{}
	excludeComms map[string]struct{}

	// Statistics
	totalEvents    uint64
	filteredEvents uint64
}

// NewEventFilter creates a new event filter from the given configuration
func NewEventFilter(config *Config) *EventFilter {
	f := &EventFilter{
		config: config,
	}

	// Build UID lookup maps
	if len(config.FilterUIDs) > 0 {
		f.includeUIDs = make(map[int]struct{}, len(config.FilterUIDs))
		for _, uid := range config.FilterUIDs {
			f.includeUIDs[uid] = struct{}{}
		}
	}
	if len(config.ExcludeUIDs) > 0 {
		f.excludeUIDs = make(map[int]struct{}, len(config.ExcludeUIDs))
		for _, uid := range config.ExcludeUIDs {
			f.excludeUIDs[uid] = struct{}{}
		}
	}

	// Build comm lookup maps
	if len(config.FilterComms) > 0 {
		f.includeComms = make(map[string]struct{}, len(config.FilterComms))
		for _, comm := range config.FilterComms {
			f.includeComms[comm] = struct{}{}
		}
	}
	if len(config.ExcludeComms) > 0 {
		f.excludeComms = make(map[string]struct{}, len(config.ExcludeComms))
		for _, comm := range config.ExcludeComms {
			f.excludeComms[comm] = struct{}{}
		}
	}

	return f
}

// ShouldInclude returns true if the event should be included (not filtered out)
func (f *EventFilter) ShouldInclude(event *ebpf.SecurityEvent) bool {
	atomic.AddUint64(&f.totalEvents, 1)

	// Category filtering
	if !f.categoryEnabled(event.Category) {
		atomic.AddUint64(&f.filteredEvents, 1)
		return false
	}

	// UID filtering
	if !f.uidAllowed(event.Process.UID) {
		atomic.AddUint64(&f.filteredEvents, 1)
		return false
	}

	// Process name filtering
	if !f.commAllowed(event.Process.Name) {
		atomic.AddUint64(&f.filteredEvents, 1)
		return false
	}

	// Path filtering (file events only)
	if event.Category == "file" && f.pathExcluded(event) {
		atomic.AddUint64(&f.filteredEvents, 1)
		return false
	}

	return true
}

// categoryEnabled checks if the event category is enabled
func (f *EventFilter) categoryEnabled(category string) bool {
	switch category {
	case "process":
		return f.config.EnableProcess
	case "file":
		return f.config.EnableFile
	case "network":
		return f.config.EnableNetwork
	case "privilege":
		return f.config.EnablePrivilege
	case "filesystem":
		return f.config.EnableFilesystem
	case "kernel":
		return f.config.EnableKernel
	case "memory":
		return f.config.EnableMemory
	default:
		return true // Unknown categories pass through
	}
}

// uidAllowed checks if the UID passes the filter
func (f *EventFilter) uidAllowed(uid int) bool {
	// Check exclusion list first (blacklist takes precedence)
	if f.excludeUIDs != nil {
		if _, excluded := f.excludeUIDs[uid]; excluded {
			return false
		}
	}

	// Check inclusion list (whitelist)
	if f.includeUIDs != nil {
		_, included := f.includeUIDs[uid]
		return included
	}

	// No whitelist, allow all
	return true
}

// commAllowed checks if the process name passes the filter
func (f *EventFilter) commAllowed(comm string) bool {
	// Check exclusion list first (blacklist takes precedence)
	if f.excludeComms != nil {
		if _, excluded := f.excludeComms[comm]; excluded {
			return false
		}
	}

	// Check inclusion list (whitelist)
	if f.includeComms != nil {
		_, included := f.includeComms[comm]
		return included
	}

	// No whitelist, allow all
	return true
}

// pathExcluded checks if the file path should be excluded
func (f *EventFilter) pathExcluded(event *ebpf.SecurityEvent) bool {
	if len(f.config.ExcludePaths) == 0 {
		return false
	}

	// Check filename in RawFields or Process.ExePath
	var path string
	if filename, ok := event.RawFields["filename"].(string); ok {
		path = filename
	} else if event.Process.ExePath != "" {
		path = event.Process.ExePath
	}

	if path == "" {
		return false
	}

	for _, prefix := range f.config.ExcludePaths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	return false
}

// Stats returns filtering statistics
func (f *EventFilter) Stats() (total, filtered uint64) {
	return atomic.LoadUint64(&f.totalEvents), atomic.LoadUint64(&f.filteredEvents)
}

// ResetStats resets the filtering statistics
func (f *EventFilter) ResetStats() {
	atomic.StoreUint64(&f.totalEvents, 0)
	atomic.StoreUint64(&f.filteredEvents, 0)
}

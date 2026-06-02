//go:build linux

package ebpf

import (
	"path/filepath"
	"strings"
	"sync/atomic"
)

// EventFilter provides efficient filtering of security events
type EventFilter struct {
	config *NativeConfig

	// Pre-computed maps for O(1) lookup
	includeUIDs  map[int]struct{}
	excludeUIDs  map[int]struct{}
	includeComms map[string]struct{}
	excludeComms map[string]struct{}

	// File-event watch-set (allow-list). When active, only write-type ops
	// under writeDirs and any op on readFiles are emitted; other file events
	// are dropped at the source.
	fileScopeActive bool
	writeDirs       []string
	readFiles       []string

	// Signal watch-set. When active, only these signal numbers are emitted.
	signalScopeActive bool
	emitSignals       map[int]struct{}

	// Statistics
	totalEvents    uint64
	filteredEvents uint64
}

// NewEventFilter creates a new event filter from the given configuration
func NewEventFilter(config *NativeConfig) *EventFilter {
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

	// Build comm lookup maps (include whitelist)
	if len(config.FilterComms) > 0 {
		f.includeComms = make(map[string]struct{}, len(config.FilterComms))
		for _, comm := range config.FilterComms {
			f.includeComms[comm] = struct{}{}
		}
	}

	// Build composite exclusion map from user config + native lists
	f.excludeComms = make(map[string]struct{})

	// Add user-configured exclusions first
	for _, comm := range config.ExcludeComms {
		f.excludeComms[comm] = struct{}{}
	}

	// Add native list exclusions based on NativeListConfig
	for comm := range config.NativeLists.BuildExcludeComms() {
		f.excludeComms[comm] = struct{}{}
	}

	// File-event watch-set: active only when at least one list is configured.
	f.writeDirs = config.FileMonitor.WriteDirs
	f.readFiles = config.FileMonitor.ReadFiles
	f.fileScopeActive = len(f.writeDirs) > 0 || len(f.readFiles) > 0

	// Signal watch-set.
	if len(config.SignalMonitor.EmitSignals) > 0 {
		f.signalScopeActive = true
		f.emitSignals = make(map[int]struct{}, len(config.SignalMonitor.EmitSignals))
		for _, s := range config.SignalMonitor.EmitSignals {
			f.emitSignals[s] = struct{}{}
		}
	}

	return f
}

// ShouldInclude returns true if the event should be included (not filtered out)
func (f *EventFilter) ShouldInclude(event *SecurityEvent) bool {
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

	// File-event scoping (allow-list): emit only write-type ops under watched
	// dirs and any access to sensitive read files; drop the rest at the source.
	if f.fileScopeActive && event.Category == "file" && !f.fileEmitAllowed(event) {
		atomic.AddUint64(&f.filteredEvents, 1)
		return false
	}

	// Signal scoping: drop signals outside the consequential set.
	if f.signalScopeActive && event.Category == "process" && event.Rule == "Process Signal" && !f.signalAllowed(event) {
		atomic.AddUint64(&f.filteredEvents, 1)
		return false
	}

	return true
}

// fileEmitAllowed reports whether a file event is in the watch-set: a sensitive
// read file (any operation, including read-only), or a write-type operation
// under a watched directory.
func (f *EventFilter) fileEmitAllowed(event *SecurityEvent) bool {
	path := event.File.Path
	if path == "" {
		if fn, ok := event.RawFields["filename"].(string); ok {
			path = fn
		}
	}
	if path == "" {
		// No path to scope on — treat as noise rather than emit blindly.
		return false
	}
	if fileMatchAny(path, f.readFiles) {
		return true
	}
	if fimWriteish(event) && dirMatchAny(path, f.writeDirs) {
		return true
	}
	return false
}

// signalAllowed reports whether the event's signal number is in the emit set.
// An unparseable signal is allowed through rather than silently dropped.
func (f *EventFilter) signalAllowed(event *SecurityEvent) bool {
	sig, ok := rawFieldInt(event.RawFields, "sig")
	if !ok {
		return true
	}
	_, allowed := f.emitSignals[sig]
	return allowed
}

// dirMatchAny reports whether path falls under any of the directory patterns.
// A plain entry matches the path or any descendant ("/etc" matches "/etc/x").
// A glob entry (e.g. "/home/*/.ssh") matches when it matches the path or any
// of its ancestor directories, so descendants of a glob dir are covered.
func dirMatchAny(path string, patterns []string) bool {
	for _, pat := range patterns {
		if !strings.ContainsAny(pat, "*?[") {
			p := strings.TrimRight(pat, "/")
			if path == p || strings.HasPrefix(path, p+"/") {
				return true
			}
			continue
		}
		for d := path; ; {
			if ok, _ := filepath.Match(pat, d); ok {
				return true
			}
			parent := filepath.Dir(d)
			if parent == d || parent == "/" || parent == "." {
				break
			}
			d = parent
		}
	}
	return false
}

// fileMatchAny reports whether path matches any of the file patterns exactly
// or by shell glob (e.g. "/etc/sudoers.d/*", "/home/*/.ssh/id_*").
func fileMatchAny(path string, patterns []string) bool {
	for _, pat := range patterns {
		if !strings.ContainsAny(pat, "*?[") {
			if path == pat {
				return true
			}
			continue
		}
		if ok, _ := filepath.Match(pat, path); ok {
			return true
		}
	}
	return false
}

// rawFieldInt coerces a RawFields numeric value to int, tolerant of the integer
// type the BPF struct decoded to.
func rawFieldInt(fields map[string]interface{}, key string) (int, bool) {
	v, ok := fields[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return n, true
	case int8:
		return int(n), true
	case int16:
		return int(n), true
	case int32:
		return int(n), true
	case int64:
		return int(n), true
	case uint8:
		return int(n), true
	case uint16:
		return int(n), true
	case uint32:
		return int(n), true
	case uint64:
		return int(n), true
	default:
		return 0, false
	}
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
	// Uses prefix matching to handle truncated comm names and variants
	if f.excludeComms != nil {
		// First check exact match
		if _, excluded := f.excludeComms[comm]; excluded {
			return false
		}
		// Then check prefix match (e.g., "runc" matches "runc:[2:INIT]")
		for excludeComm := range f.excludeComms {
			if strings.HasPrefix(comm, excludeComm) {
				return false
			}
		}
	}

	// Check inclusion list (whitelist) - exact match only
	if f.includeComms != nil {
		_, included := f.includeComms[comm]
		return included
	}

	// No whitelist, allow all
	return true
}

// pathExcluded checks if the file path should be excluded
func (f *EventFilter) pathExcluded(event *SecurityEvent) bool {
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

	// Check user-configured path exclusions
	for _, prefix := range f.config.ExcludePaths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	// Check native list safe path exclusions
	for _, prefix := range f.config.NativeLists.BuildExcludePaths() {
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

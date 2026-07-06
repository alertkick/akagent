//go:build linux

package ebpf

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"

	ciliumebpf "github.com/cilium/ebpf"
)

// DiscarderCategory constants must match discarders.h DISCARD_CAT_* defines
const (
	DiscarderCatGlobal     uint32 = 0
	DiscarderCatProcess    uint32 = 1
	DiscarderCatFile       uint32 = 2
	DiscarderCatNetwork    uint32 = 3
	DiscarderCatPrivilege  uint32 = 4
	DiscarderCatFilesystem uint32 = 5
	DiscarderCatKernel     uint32 = 6
	DiscarderCatMemory     uint32 = 7
	DiscarderCatNamespace  uint32 = 8
	DiscarderCatCaps       uint32 = 9
	DiscarderConfigSize    uint32 = 10
)

// DiscarderManager manages in-kernel discarder BPF maps across all programs.
// Each BPF program has its own copy of the discarder maps (discard_config,
// discard_comms, discard_pids, discard_stats). The manager keeps references
// to all copies and updates them in sync.
type DiscarderManager struct {
	mu sync.RWMutex

	// References to discarder maps from each loaded BPF program.
	// All maps in a slice receive the same updates.
	configMaps []*ciliumebpf.Map // discard_config (ARRAY, category enable/disable)
	commMaps   []*ciliumebpf.Map // discard_comms (HASH, comm name exclusions)
	pidMaps    []*ciliumebpf.Map // discard_pids (HASH, PID exclusions)
	statsMaps  []*ciliumebpf.Map // discard_stats (PERCPU_ARRAY, discard counters)

	// Track current state for config reload
	disabledCategories map[uint32]bool
	excludedComms      map[string]bool
	excludedPIDs       map[uint32]bool

	// Stats
	totalSyncs uint64
}

// NewDiscarderManager creates a new DiscarderManager
func NewDiscarderManager() *DiscarderManager {
	return &DiscarderManager{
		disabledCategories: make(map[uint32]bool),
		excludedComms:      make(map[string]bool),
		excludedPIDs:       make(map[uint32]bool),
	}
}

// RegisterMaps registers the discarder maps from a loaded BPF program.
// Call this after loading each BPF program's objects.
// The map parameters may be nil if the program doesn't have discarder maps
// (e.g., process_cache which should not filter).
func (d *DiscarderManager) RegisterMaps(config, comms, pids, stats *ciliumebpf.Map) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if config != nil {
		// Validate the map is usable by checking its info (requires valid FD)
		if info, err := config.Info(); err != nil {
			nativeLog.Warn().Err(err).Msg("Registering discard_config map with invalid FD")
		} else {
			nativeLog.Debug().Str("map_type", info.Type.String()).Msg("Registering discard_config map")
		}
		d.configMaps = append(d.configMaps, config)
	}
	if comms != nil {
		d.commMaps = append(d.commMaps, comms)
	}
	if pids != nil {
		d.pidMaps = append(d.pidMaps, pids)
	}
	if stats != nil {
		d.statsMaps = append(d.statsMaps, stats)
	}
}

// Reset drops all registered map references and per-map state. Call it on
// Stop/teardown: closing the BPF program objects invalidates these map FDs, so
// the stored references go stale. Without clearing, the next Start re-registers
// on top of the stale entries — doubling the map count (18 → 36) and causing
// "invalid FD" errors when SyncFromConfig validates the (stale) first map.
func (d *DiscarderManager) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.configMaps = nil
	d.commMaps = nil
	d.pidMaps = nil
	d.statsMaps = nil
	d.disabledCategories = make(map[uint32]bool)
	d.excludedComms = make(map[string]bool)
	d.excludedPIDs = make(map[uint32]bool)
}

// SyncFromConfig populates all discarder maps from the current NativeConfig.
// This should be called after loading all BPF programs and registering maps.
func (d *DiscarderManager) SyncFromConfig(config *NativeConfig) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.configMaps) == 0 {
		nativeLog.Warn().Msg("No discarder config maps registered, skipping sync")
		return nil
	}

	// Validate first map FD to detect stale/invalid maps early
	if _, err := d.configMaps[0].Info(); err != nil {
		nativeLog.Error().Err(err).Int("map_count", len(d.configMaps)).
			Msg("Discarder config maps have invalid FDs - binary may need rebuilding with 'go clean -cache && go build'")
		return fmt.Errorf("discarder maps have invalid FDs (stale build?): %w", err)
	}

	var lastErr error

	// 1. Sync category config (disabled categories → discard in kernel)
	d.disabledCategories = make(map[uint32]bool)
	categoryMap := map[uint32]bool{
		DiscarderCatProcess:    config.EnableProcess,
		DiscarderCatFile:       config.EnableFile,
		DiscarderCatNetwork:    config.EnableNetwork,
		DiscarderCatPrivilege:  config.EnablePrivilege,
		DiscarderCatFilesystem: config.EnableFilesystem,
		DiscarderCatKernel:     config.EnableKernel,
		DiscarderCatMemory:     config.EnableMemory,
		DiscarderCatNamespace:  config.EnableNamespace,
		DiscarderCatCaps:       config.EnableCaps,
	}

	// Global is always enabled (0 = allow)
	for _, m := range d.configMaps {
		var globalVal uint8 = 0
		if err := m.Update(DiscarderCatGlobal, globalVal, ciliumebpf.UpdateAny); err != nil {
			lastErr = fmt.Errorf("failed to update global config: %w", err)
			nativeLog.Warn().Err(err).Msg("Failed to update global discarder config")
		}
	}

	for cat, enabled := range categoryMap {
		var val uint8 = 0 // 0 = allow
		if !enabled {
			val = 1 // 1 = discard
			d.disabledCategories[cat] = true
		}
		for _, m := range d.configMaps {
			if err := m.Update(cat, val, ciliumebpf.UpdateAny); err != nil {
				lastErr = fmt.Errorf("failed to update category %d: %w", cat, err)
				nativeLog.Warn().Err(err).Uint32("category", cat).Msg("Failed to update discarder config map")
			}
		}
	}

	// 2. Sync excluded comm names
	d.excludedComms = make(map[string]bool)

	// Clear existing comm maps
	for _, m := range d.commMaps {
		d.clearHashMap(m)
	}

	// Add exclusions from config.ExcludeComms
	for _, comm := range config.ExcludeComms {
		if err := d.addCommDiscarder(comm); err != nil {
			lastErr = err
		}
	}

	// Add exclusions from native lists. The kernel variant excludes the
	// write-capable file tools (cp/mv/touch/sed/vim/...): a kernel discard
	// happens before fimNotify, so keeping them here would blind the
	// file-integrity monitor to their changes.
	for comm := range config.NativeLists.BuildKernelDiscardComms() {
		if err := d.addCommDiscarder(comm); err != nil {
			lastErr = err
		}
	}

	// 3. Add agent self-PID to PID discarders
	d.excludedPIDs = make(map[uint32]bool)

	// Clear existing PID maps
	for _, m := range d.pidMaps {
		d.clearHashMap(m)
	}

	agentPID := uint32(os.Getpid())
	if err := d.addPIDDiscarder(agentPID); err != nil {
		lastErr = err
	}

	atomic.AddUint64(&d.totalSyncs, 1)

	commCount := len(d.excludedComms)
	pidCount := len(d.excludedPIDs)
	disabledCount := len(d.disabledCategories)

	nativeLog.Info().
		Int("disabled_categories", disabledCount).
		Int("excluded_comms", commCount).
		Int("excluded_pids", pidCount).
		Int("program_count", len(d.configMaps)).
		Msg("Synced in-kernel discarder maps from config")

	return lastErr
}

// addCommDiscarder adds a comm name to all discard_comms maps.
// The comm name is truncated/padded to exactly TASK_COMM_LEN (16) bytes.
// Must be called with d.mu held.
func (d *DiscarderManager) addCommDiscarder(comm string) error {
	if comm == "" {
		return nil
	}

	// Build 16-byte key matching kernel's TASK_COMM_LEN
	var key [16]byte
	copy(key[:], comm)

	var val uint8 = 1
	var lastErr error
	for _, m := range d.commMaps {
		if err := m.Update(key, val, ciliumebpf.UpdateAny); err != nil {
			lastErr = fmt.Errorf("failed to add comm discarder %q: %w", comm, err)
		}
	}

	d.excludedComms[comm] = true
	return lastErr
}

// addPIDDiscarder adds a PID to all discard_pids maps.
// Must be called with d.mu held.
func (d *DiscarderManager) addPIDDiscarder(pid uint32) error {
	var val uint8 = 1
	var lastErr error
	for _, m := range d.pidMaps {
		if err := m.Update(pid, val, ciliumebpf.UpdateAny); err != nil {
			lastErr = fmt.Errorf("failed to add PID discarder %d: %w", pid, err)
		}
	}

	d.excludedPIDs[pid] = true
	return lastErr
}

// AddPID dynamically adds a PID to the discarder maps (thread-safe).
func (d *DiscarderManager) AddPID(pid uint32) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.addPIDDiscarder(pid)
}

// RemovePID dynamically removes a PID from the discarder maps (thread-safe).
func (d *DiscarderManager) RemovePID(pid uint32) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var lastErr error
	for _, m := range d.pidMaps {
		if err := m.Delete(pid); err != nil && err != ciliumebpf.ErrKeyNotExist {
			lastErr = fmt.Errorf("failed to remove PID discarder %d: %w", pid, err)
		}
	}

	delete(d.excludedPIDs, pid)
	return lastErr
}

// AddComm dynamically adds a comm name to the discarder maps (thread-safe).
func (d *DiscarderManager) AddComm(comm string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.addCommDiscarder(comm)
}

// RemoveComm dynamically removes a comm name from the discarder maps (thread-safe).
func (d *DiscarderManager) RemoveComm(comm string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var key [16]byte
	copy(key[:], comm)

	var lastErr error
	for _, m := range d.commMaps {
		if err := m.Delete(key); err != nil && err != ciliumebpf.ErrKeyNotExist {
			lastErr = fmt.Errorf("failed to remove comm discarder %q: %w", comm, err)
		}
	}

	delete(d.excludedComms, comm)
	return lastErr
}

// DiscarderStats holds per-category discard statistics from the kernel
type DiscarderStats struct {
	Global     uint64
	Process    uint64
	File       uint64
	Network    uint64
	Privilege  uint64
	Filesystem uint64
	Kernel     uint64
	Memory     uint64
	Namespace  uint64
	Caps       uint64
	Total      uint64
}

// GetStats reads the in-kernel discard statistics from all programs.
// Values are summed across all programs and all CPUs.
func (d *DiscarderManager) GetStats() DiscarderStats {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var stats DiscarderStats
	numCPU := runtime.NumCPU()

	for _, m := range d.statsMaps {
		for cat := uint32(0); cat < DiscarderConfigSize; cat++ {
			// For PERCPU_ARRAY, Lookup returns a slice of values (one per CPU)
			values := make([]uint64, numCPU)
			if err := m.Lookup(cat, &values); err != nil {
				continue
			}

			var sum uint64
			for _, v := range values {
				sum += v
			}

			switch cat {
			case DiscarderCatGlobal:
				stats.Global += sum
			case DiscarderCatProcess:
				stats.Process += sum
			case DiscarderCatFile:
				stats.File += sum
			case DiscarderCatNetwork:
				stats.Network += sum
			case DiscarderCatPrivilege:
				stats.Privilege += sum
			case DiscarderCatFilesystem:
				stats.Filesystem += sum
			case DiscarderCatKernel:
				stats.Kernel += sum
			case DiscarderCatMemory:
				stats.Memory += sum
			case DiscarderCatNamespace:
				stats.Namespace += sum
			case DiscarderCatCaps:
				stats.Caps += sum
			}
		}
	}

	stats.Total = stats.Global + stats.Process + stats.File + stats.Network +
		stats.Privilege + stats.Filesystem + stats.Kernel + stats.Memory +
		stats.Namespace + stats.Caps

	return stats
}

// clearHashMap iterates and deletes all entries from a BPF hash map.
func (d *DiscarderManager) clearHashMap(m *ciliumebpf.Map) {
	if m == nil {
		return
	}

	// Use BatchDelete if available, otherwise iterate
	var key []byte
	iter := m.Iterate()
	var val uint8
	keysToDelete := make([][]byte, 0, 64)

	for iter.Next(&key, &val) {
		k := make([]byte, len(key))
		copy(k, key)
		keysToDelete = append(keysToDelete, k)
	}

	for _, k := range keysToDelete {
		_ = m.Delete(k)
	}
}

// MapCount returns the number of registered program map sets
func (d *DiscarderManager) MapCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.configMaps)
}

// ExcludedCommCount returns the number of excluded comm names
func (d *DiscarderManager) ExcludedCommCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.excludedComms)
}

// SyncCount returns the total number of config syncs performed
func (d *DiscarderManager) SyncCount() uint64 {
	return atomic.LoadUint64(&d.totalSyncs)
}

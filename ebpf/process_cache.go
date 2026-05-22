//go:build linux

package ebpf

import (
	"sync"
	"time"

	"akagent/ebpf/bpfgen"
	"akagent/logger"

	"github.com/cilium/ebpf"
)

var procCacheLog = logger.Sublogger("process-cache")

// ProcessCacheEntry holds userspace-cached process context from the BPF process_cache map.
type ProcessCacheEntry struct {
	PID             uint32
	PPID            uint32
	UID             uint32
	GID             uint32
	StartTimeNS     uint64
	Comm            string
	Exe             string
	Cmdline         string
	ParentPID       uint32
	ParentComm      string
	ParentExe       string
	GrandparentPID  uint32
	GrandparentComm string
	ContainerID     string
	CgroupID        uint64
	Flags           uint32
	LastSeen        time.Time
}

// ProcessCache is a Go-side LRU cache backed by a BPF hash map.
// On cache miss it performs a BPF map lookup and caches the result.
type ProcessCache struct {
	mu      sync.RWMutex
	cache   map[uint32]*ProcessCacheEntry
	maxSize int
	bpfMap  *ebpf.Map
	enabled bool
}

// NewProcessCache creates a new ProcessCache backed by the given BPF map.
func NewProcessCache(bpfMap *ebpf.Map, maxSize int) *ProcessCache {
	if maxSize <= 0 {
		maxSize = 32768
	}
	return &ProcessCache{
		cache:   make(map[uint32]*ProcessCacheEntry, maxSize/4),
		maxSize: maxSize,
		bpfMap:  bpfMap,
		enabled: true,
	}
}

// Lookup returns a ProcessCacheEntry for the given PID.
// It checks the Go cache first, then falls back to BPF map lookup.
func (pc *ProcessCache) Lookup(pid uint32) *ProcessCacheEntry {
	if !pc.enabled || pid == 0 {
		return nil
	}

	// Fast path: check Go cache
	pc.mu.RLock()
	entry, ok := pc.cache[pid]
	pc.mu.RUnlock()
	if ok {
		return entry
	}

	// Slow path: BPF map lookup
	entry = pc.lookupBPFMap(pid)
	if entry == nil {
		return nil
	}

	// Cache the result
	pc.mu.Lock()
	// Evict random entries if at capacity (simple eviction — not true LRU,
	// but sufficient since BPF map is the source of truth).
	if len(pc.cache) >= pc.maxSize {
		evicted := 0
		for k := range pc.cache {
			delete(pc.cache, k)
			evicted++
			if evicted >= pc.maxSize/8 {
				break
			}
		}
	}
	pc.cache[pid] = entry
	pc.mu.Unlock()

	return entry
}

// Enrich fills empty fields in a SecurityEvent with data from the process cache.
// Fields that were already set by the BPF event parser are not overwritten.
func (pc *ProcessCache) Enrich(event *SecurityEvent) {
	if !pc.enabled {
		return
	}

	entry := pc.Lookup(uint32(event.Process.PID))
	if entry == nil {
		return
	}

	if event.Process.ExePath == "" {
		event.Process.ExePath = entry.Exe
	}
	if event.Process.Cmdline == "" {
		event.Process.Cmdline = entry.Cmdline
	}
	if event.Process.ParentName == "" {
		event.Process.ParentName = entry.ParentComm
	}
	if event.Process.ParentExe == "" {
		event.Process.ParentExe = entry.ParentExe
	}
	if entry.GrandparentPID != 0 {
		event.Process.GrandparentPID = int(entry.GrandparentPID)
		event.Process.GrandparentName = entry.GrandparentComm
	}
	if entry.ContainerID != "" && event.Container.ID == "" {
		event.Container.ID = entry.ContainerID
	}
}

// Evict marks an entry for delayed removal (keeps it for 30s for out-of-order events).
func (pc *ProcessCache) Evict(pid uint32) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if entry, ok := pc.cache[pid]; ok {
		entry.LastSeen = time.Now()
	}
}

// Cleanup removes expired entries from the Go cache.
// Entries with a LastSeen older than 30s are evicted.
func (pc *ProcessCache) Cleanup() {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	cutoff := time.Now().Add(-30 * time.Second)
	evicted := 0
	for pid, entry := range pc.cache {
		if !entry.LastSeen.IsZero() && entry.LastSeen.Before(cutoff) {
			delete(pc.cache, pid)
			evicted++
		}
	}
	if evicted > 0 && logger.IsSectionEnabled(logger.SectionEBPF) {
		procCacheLog.Debug().Int("evicted", evicted).Int("remaining", len(pc.cache)).Msg("Process cache cleanup")
	}
}

// CacheSize returns the number of entries in the Go cache.
func (pc *ProcessCache) CacheSize() int {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	return len(pc.cache)
}

// lookupBPFMap reads a process entry directly from the kernel BPF map.
func (pc *ProcessCache) lookupBPFMap(pid uint32) *ProcessCacheEntry {
	if pc.bpfMap == nil {
		return nil
	}

	var info bpfgen.ProcesscacheProcessInfo
	if err := pc.bpfMap.Lookup(pid, &info); err != nil {
		return nil
	}

	return convertProcessInfo(&info, pid)
}

// convertProcessInfo converts a BPF ProcesscacheProcessInfo struct to a Go ProcessCacheEntry.
func convertProcessInfo(info *bpfgen.ProcesscacheProcessInfo, pid uint32) *ProcessCacheEntry {
	return &ProcessCacheEntry{
		PID:             pid,
		PPID:            info.Ppid,
		UID:             info.Uid,
		GID:             info.Gid,
		StartTimeNS:     info.StartTimeNs,
		Comm:            int8ArrayToString(info.Comm[:]),
		Exe:             int8ArrayToString(info.Exe[:]),
		Cmdline:         int8ArrayToString(info.Cmdline[:]),
		ParentPID:       info.ParentPid,
		ParentComm:      int8ArrayToString(info.ParentComm[:]),
		ParentExe:       int8ArrayToString(info.ParentExe[:]),
		GrandparentPID:  info.GrandparentPid,
		GrandparentComm: int8ArrayToString(info.GrandparentComm[:]),
		ContainerID:     int8ArrayToString(info.ContainerId[:]),
		CgroupID:        info.CgroupId,
		Flags:           info.Flags,
		LastSeen:        time.Now(),
	}
}


package native

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"apagent/ebpf"
)

// EventEnricher provides enrichment of security events with container, cgroup, and namespace info
type EventEnricher struct {
	mu sync.RWMutex

	// Cache for container IDs (PID -> container info)
	containerCache     map[int]*ContainerInfo
	containerCacheTTL  time.Duration
	containerCacheTime map[int]time.Time

	// Cache for namespace info
	namespaceCache     map[int]*NamespaceInfo
	namespaceCacheTTL  time.Duration
	namespaceCacheTime map[int]time.Time

	// Enable flags
	enabled bool
}

// ContainerInfo holds container-related information
type ContainerInfo struct {
	ContainerID   string // Container ID (docker/podman/containerd)
	ContainerName string // Container name if available
	Runtime       string // Container runtime (docker, containerd, cri-o, podman)
	CgroupPath    string // Full cgroup path
	CgroupID      string // Cgroup ID
}

// NamespaceInfo holds namespace-related information
type NamespaceInfo struct {
	PIDNamespace    uint64 // PID namespace inode
	MountNamespace  uint64 // Mount namespace inode
	NetNamespace    uint64 // Network namespace inode
	UserNamespace   uint64 // User namespace inode
	UTSNamespace    uint64 // UTS namespace inode
	IPCNamespace    uint64 // IPC namespace inode
	CgroupNamespace uint64 // Cgroup namespace inode
}

// Container ID extraction patterns for various runtimes
var (
	// Docker: /docker/<container_id> or /system.slice/docker-<container_id>.scope
	dockerPattern = regexp.MustCompile(`/docker[/-]([a-f0-9]{64})`)
	// Containerd: /system.slice/containerd-<container_id>.scope
	containerdPattern = regexp.MustCompile(`/containerd[/-]([a-f0-9]{64})`)
	// CRI-O: /crio-<container_id>
	crioPattern = regexp.MustCompile(`/crio[/-]([a-f0-9]{64})`)
	// Podman: /libpod-<container_id>
	podmanPattern = regexp.MustCompile(`/libpod[/-]([a-f0-9]{64})`)
	// Kubernetes pod pattern
	k8sPodPattern = regexp.MustCompile(`/kubepods[^/]*/[^/]*/pod([a-f0-9-]+)/([a-f0-9]{64})`)
)

// NewEventEnricher creates a new event enricher with default settings
func NewEventEnricher() *EventEnricher {
	return NewEventEnricherWithTTL(30 * time.Second)
}

// NewEventEnricherWithTTL creates a new event enricher with custom cache TTL
func NewEventEnricherWithTTL(cacheTTL time.Duration) *EventEnricher {
	return &EventEnricher{
		containerCache:     make(map[int]*ContainerInfo),
		containerCacheTTL:  cacheTTL,
		containerCacheTime: make(map[int]time.Time),
		namespaceCache:     make(map[int]*NamespaceInfo),
		namespaceCacheTTL:  cacheTTL,
		namespaceCacheTime: make(map[int]time.Time),
		enabled:            true,
	}
}

// SetEnabled enables or disables enrichment
func (e *EventEnricher) SetEnabled(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enabled = enabled
}

// IsEnabled returns whether enrichment is enabled
func (e *EventEnricher) IsEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enabled
}

// Enrich adds container, cgroup, and namespace information to an event
func (e *EventEnricher) Enrich(event *ebpf.SecurityEvent) {
	if !e.IsEnabled() {
		return
	}

	pid := event.Process.PID
	if pid <= 0 {
		return
	}

	// Get container info
	containerInfo := e.getContainerInfo(pid)
	if containerInfo != nil {
		event.Container = ebpf.ContainerInfo{
			ID:      containerInfo.ContainerID,
			Name:    containerInfo.ContainerName,
			Runtime: containerInfo.Runtime,
		}
		if event.RawFields == nil {
			event.RawFields = make(map[string]interface{})
		}
		event.RawFields["cgroup_path"] = containerInfo.CgroupPath
		event.RawFields["cgroup_id"] = containerInfo.CgroupID
	}

	// Get namespace info
	namespaceInfo := e.getNamespaceInfo(pid)
	if namespaceInfo != nil {
		if event.RawFields == nil {
			event.RawFields = make(map[string]interface{})
		}
		event.RawFields["ns_pid"] = namespaceInfo.PIDNamespace
		event.RawFields["ns_mnt"] = namespaceInfo.MountNamespace
		event.RawFields["ns_net"] = namespaceInfo.NetNamespace
		event.RawFields["ns_user"] = namespaceInfo.UserNamespace
		event.RawFields["ns_uts"] = namespaceInfo.UTSNamespace
		event.RawFields["ns_ipc"] = namespaceInfo.IPCNamespace
		event.RawFields["ns_cgroup"] = namespaceInfo.CgroupNamespace
	}
}

// getContainerInfo gets container info for a PID, using cache
func (e *EventEnricher) getContainerInfo(pid int) *ContainerInfo {
	e.mu.RLock()
	if info, ok := e.containerCache[pid]; ok {
		if time.Since(e.containerCacheTime[pid]) < e.containerCacheTTL {
			e.mu.RUnlock()
			return info
		}
	}
	e.mu.RUnlock()

	// Cache miss or expired, look up
	info := e.lookupContainerInfo(pid)

	e.mu.Lock()
	e.containerCache[pid] = info
	e.containerCacheTime[pid] = time.Now()
	e.mu.Unlock()

	return info
}

// lookupContainerInfo reads container info from /proc/<pid>/cgroup
func (e *EventEnricher) lookupContainerInfo(pid int) *ContainerInfo {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return nil
	}

	info := &ContainerInfo{}

	// Parse cgroup file
	// Format: hierarchy-ID:controller-list:cgroup-path
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}

		path := parts[2]
		if info.CgroupPath == "" {
			info.CgroupPath = path
		}

		// Try to extract container ID from cgroup path
		containerID, runtime := extractContainerID(path)
		if containerID != "" {
			info.ContainerID = containerID
			info.Runtime = runtime
			// Use short container ID (first 12 chars) as cgroup ID
			if len(containerID) >= 12 {
				info.CgroupID = containerID[:12]
			} else {
				info.CgroupID = containerID
			}
			break
		}
	}

	// If we found a container, try to get the name (only for Docker for now)
	if info.ContainerID != "" && info.Runtime == "docker" {
		info.ContainerName = e.lookupDockerContainerName(info.ContainerID)
	}

	return info
}

// extractContainerID extracts container ID and runtime from a cgroup path
func extractContainerID(path string) (string, string) {
	// Check Kubernetes pod pattern first (most specific)
	if matches := k8sPodPattern.FindStringSubmatch(path); len(matches) >= 3 {
		return matches[2], "kubernetes"
	}

	// Docker
	if matches := dockerPattern.FindStringSubmatch(path); len(matches) >= 2 {
		return matches[1], "docker"
	}

	// Containerd
	if matches := containerdPattern.FindStringSubmatch(path); len(matches) >= 2 {
		return matches[1], "containerd"
	}

	// CRI-O
	if matches := crioPattern.FindStringSubmatch(path); len(matches) >= 2 {
		return matches[1], "cri-o"
	}

	// Podman
	if matches := podmanPattern.FindStringSubmatch(path); len(matches) >= 2 {
		return matches[1], "podman"
	}

	return "", ""
}

// lookupDockerContainerName attempts to get container name from Docker
// This is best-effort and may not always succeed
func (e *EventEnricher) lookupDockerContainerName(containerID string) string {
	// Try to read hostname from container's UTS namespace
	// This is a simple heuristic - container name is often set as hostname
	hostnamePath := fmt.Sprintf("/proc/1/root/var/lib/docker/containers/%s/hostname", containerID)
	data, err := os.ReadFile(hostnamePath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// getNamespaceInfo gets namespace info for a PID, using cache
func (e *EventEnricher) getNamespaceInfo(pid int) *NamespaceInfo {
	e.mu.RLock()
	if info, ok := e.namespaceCache[pid]; ok {
		if time.Since(e.namespaceCacheTime[pid]) < e.namespaceCacheTTL {
			e.mu.RUnlock()
			return info
		}
	}
	e.mu.RUnlock()

	// Cache miss or expired, look up
	info := e.lookupNamespaceInfo(pid)

	e.mu.Lock()
	e.namespaceCache[pid] = info
	e.namespaceCacheTime[pid] = time.Now()
	e.mu.Unlock()

	return info
}

// lookupNamespaceInfo reads namespace info from /proc/<pid>/ns/
func (e *EventEnricher) lookupNamespaceInfo(pid int) *NamespaceInfo {
	nsDir := fmt.Sprintf("/proc/%d/ns", pid)

	info := &NamespaceInfo{}

	// Read each namespace inode
	namespaces := map[string]*uint64{
		"pid":    &info.PIDNamespace,
		"mnt":    &info.MountNamespace,
		"net":    &info.NetNamespace,
		"user":   &info.UserNamespace,
		"uts":    &info.UTSNamespace,
		"ipc":    &info.IPCNamespace,
		"cgroup": &info.CgroupNamespace,
	}

	for name, target := range namespaces {
		nsPath := filepath.Join(nsDir, name)
		link, err := os.Readlink(nsPath)
		if err != nil {
			continue
		}

		// Link format: namespace:[inode]
		// Example: pid:[4026531836]
		if idx := strings.Index(link, ":["); idx != -1 {
			inodeStr := strings.TrimSuffix(link[idx+2:], "]")
			if inode, err := strconv.ParseUint(inodeStr, 10, 64); err == nil {
				*target = inode
			}
		}
	}

	return info
}

// CleanupCache removes stale entries from the cache
func (e *EventEnricher) CleanupCache() {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()

	// Clean container cache
	for pid, cacheTime := range e.containerCacheTime {
		if now.Sub(cacheTime) > e.containerCacheTTL*2 {
			delete(e.containerCache, pid)
			delete(e.containerCacheTime, pid)
		}
	}

	// Clean namespace cache
	for pid, cacheTime := range e.namespaceCacheTime {
		if now.Sub(cacheTime) > e.namespaceCacheTTL*2 {
			delete(e.namespaceCache, pid)
			delete(e.namespaceCacheTime, pid)
		}
	}
}

// CacheSize returns the current cache sizes
func (e *EventEnricher) CacheSize() (containers, namespaces int) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.containerCache), len(e.namespaceCache)
}

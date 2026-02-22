//go:build linux

package ebpf

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// EventEnricher provides enrichment of security events with container, cgroup, and namespace info
type EventEnricher struct {
	mu sync.RWMutex

	// Cache for container IDs (PID -> container info)
	containerCache     map[int]*ContainerCacheEntry
	containerCacheTTL  time.Duration
	containerCacheTime map[int]time.Time

	// Cache for namespace info
	namespaceCache     map[int]*NamespaceInfo
	namespaceCacheTTL  time.Duration
	namespaceCacheTime map[int]time.Time

	// Enable flags
	enabled bool
}

// ContainerCacheEntry holds container-related information for caching
type ContainerCacheEntry struct {
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
		containerCache:     make(map[int]*ContainerCacheEntry),
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
func (e *EventEnricher) Enrich(event *SecurityEvent) {
	if !e.IsEnabled() {
		return
	}

	pid := event.Process.PID
	if pid <= 0 {
		return
	}

	// Get container info
	containerEntry := e.getContainerInfo(pid)
	if containerEntry != nil {
		event.Container = ContainerInfo{
			ID:      containerEntry.ContainerID,
			Name:    containerEntry.ContainerName,
			Runtime: containerEntry.Runtime,
		}
		if event.RawFields == nil {
			event.RawFields = make(map[string]interface{})
		}
		event.RawFields["cgroup_path"] = containerEntry.CgroupPath
		event.RawFields["cgroup_id"] = containerEntry.CgroupID
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
func (e *EventEnricher) getContainerInfo(pid int) *ContainerCacheEntry {
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
func (e *EventEnricher) lookupContainerInfo(pid int) *ContainerCacheEntry {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return nil
	}

	info := &ContainerCacheEntry{}

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

// EnrichProcessInfo adds detailed process context from /proc filesystem
// This enriches the ProcessInfo with cmdline, exe path, parent info, cwd, and username
func EnrichProcessInfo(proc *ProcessInfo) {
	if proc.PID <= 0 {
		return
	}

	pid := proc.PID
	procPath := fmt.Sprintf("/proc/%d", pid)

	// Read command line
	if proc.Cmdline == "" {
		if cmdline, err := os.ReadFile(filepath.Join(procPath, "cmdline")); err == nil {
			// cmdline is null-separated
			proc.Cmdline = strings.ReplaceAll(string(cmdline), "\x00", " ")
			proc.Cmdline = strings.TrimSpace(proc.Cmdline)
		}
	}

	// Read executable path
	if proc.ExePath == "" {
		if exePath, err := os.Readlink(filepath.Join(procPath, "exe")); err == nil {
			proc.ExePath = exePath
		}
	}

	// Read current working directory
	if proc.Cwd == "" {
		if cwd, err := os.Readlink(filepath.Join(procPath, "cwd")); err == nil {
			proc.Cwd = cwd
		}
	}

	// Lookup username from UID
	if proc.Username == "" && proc.UID >= 0 {
		if u, err := lookupUsername(proc.UID); err == nil {
			proc.Username = u
		}
	}

	// Enrich parent process info
	if proc.PPID > 0 {
		pprocPath := fmt.Sprintf("/proc/%d", proc.PPID)

		// Read parent process name
		if proc.ParentName == "" {
			if comm, err := os.ReadFile(filepath.Join(pprocPath, "comm")); err == nil {
				proc.ParentName = strings.TrimSpace(string(comm))
			}
		}

		// Read parent executable path
		if proc.ParentExe == "" {
			if exePath, err := os.Readlink(filepath.Join(pprocPath, "exe")); err == nil {
				proc.ParentExe = exePath
			}
		}
	}
}

// lookupUsername looks up username from UID
func lookupUsername(uid int) (string, error) {
	// Read /etc/passwd to find username
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return "", err
	}

	uidStr := strconv.Itoa(uid)
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) >= 3 && parts[2] == uidStr {
			return parts[0], nil
		}
	}

	// Fallback to UID string
	return uidStr, nil
}

// GetProcessContext returns a formatted string with full process context
func GetProcessContext(proc *ProcessInfo) string {
	var parts []string

	if proc.Name != "" {
		parts = append(parts, fmt.Sprintf("name=%s", proc.Name))
	}
	if proc.ExePath != "" {
		parts = append(parts, fmt.Sprintf("exe=%s", proc.ExePath))
	}
	if proc.Cmdline != "" {
		// Truncate long cmdlines
		cmdline := proc.Cmdline
		if len(cmdline) > 200 {
			cmdline = cmdline[:200] + "..."
		}
		parts = append(parts, fmt.Sprintf("cmdline='%s'", cmdline))
	}
	if proc.Username != "" {
		parts = append(parts, fmt.Sprintf("user=%s", proc.Username))
	} else if proc.UID >= 0 {
		parts = append(parts, fmt.Sprintf("uid=%d", proc.UID))
	}
	if proc.Cwd != "" {
		parts = append(parts, fmt.Sprintf("cwd=%s", proc.Cwd))
	}
	if proc.ParentName != "" {
		parts = append(parts, fmt.Sprintf("parent=%s", proc.ParentName))
	}
	if proc.ParentExe != "" {
		parts = append(parts, fmt.Sprintf("parent_exe=%s", proc.ParentExe))
	}

	return strings.Join(parts, ", ")
}

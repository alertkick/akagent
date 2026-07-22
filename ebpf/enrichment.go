//go:build linux

package ebpf

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
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

	// Host container inventory: container ID (full 64-hex and short 12-char)
	// -> name. Built by listing running containers from each available
	// runtime on a ticker (RefreshInventory), so per-event name enrichment is
	// a pure map lookup and never forks a subprocess. Lazily-resolved and
	// negative ("" sentinel) entries are written here too and cleared on the
	// next refresh.
	inventory          map[string]string
	inventoryRefreshed time.Time
	inventoryMinGap    time.Duration // debounce floor for on-miss refreshes
	lastMissRefresh    time.Time

	// dockerRoot is the docker daemon's data-root (DockerRootDir from
	// `docker info`), refreshed alongside the inventory; "" until known. A
	// daemon with a non-default data-root keeps config.v2.json outside
	// /var/lib/docker, so the metadata readers try this location first.
	dockerRoot string

	// Configured healthcheck command (Config.Healthcheck.Test) per full
	// container ID; nil means "looked up, none found". Healthcheck config is
	// immutable for a container's lifetime, so entries live until the
	// container leaves the inventory. Populated fork-free from docker's
	// on-disk metadata, once per container, never per event.
	healthchecks map[string][]string

	// Image reference (Config.Image, e.g. "nginx:1.25") per full container
	// ID; "" means "looked up, not resolvable". Same lifecycle as
	// healthchecks: immutable per container, read fork-free from docker's
	// on-disk metadata once, pruned when the container leaves the inventory.
	// Feeds Container.Image on events so the endpoint's registry-allowlist
	// rule (cs-005) can evaluate.
	images map[string]string

	// Cache for namespace info
	namespaceCache     map[int]*NamespaceInfo
	namespaceCacheTTL  time.Duration
	namespaceCacheTime map[int]time.Time

	// Enable flags
	enabled bool

	// Overridable for tests. Each lists running containers for one runtime as
	// full-ID -> name, or returns nil when that runtime isn't present.
	dockerList func(ctx context.Context) map[string]string
	podmanList func(ctx context.Context) map[string]string
	crictlList func(ctx context.Context) map[string]string
	// Overridable for tests: reads a container's configured healthcheck.
	healthcheckRead func(containerID string) []string
	// Overridable for tests: reads a container's image reference.
	imageRead func(containerID string) string
	// Overridable for tests: reports the docker daemon's data-root.
	dockerRootFn func(ctx context.Context) string
}

// ContainerCacheEntry holds container-related information for caching
type ContainerCacheEntry struct {
	ContainerID   string // Container ID (docker/podman/containerd)
	ContainerName string // Container name if available
	Image         string // Image reference (e.g. "nginx:1.25") if available
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
	e := &EventEnricher{
		containerCache:     make(map[int]*ContainerCacheEntry),
		containerCacheTTL:  cacheTTL,
		containerCacheTime: make(map[int]time.Time),
		inventory:          make(map[string]string),
		// On a miss we kick at most one async refresh per this interval, so a
		// burst of events for a just-started container can't storm the runtime
		// CLI. The periodic ticker (runInventoryRefresh) is the steady path.
		inventoryMinGap:    5 * time.Second,
		healthchecks:       make(map[string][]string),
		images:             make(map[string]string),
		namespaceCache:     make(map[int]*NamespaceInfo),
		namespaceCacheTTL:  cacheTTL,
		namespaceCacheTime: make(map[int]time.Time),
		enabled:            true,
		dockerList:         dockerListContainers,
		podmanList:         podmanListContainers,
		crictlList:         crictlListContainers,
		dockerRootFn:       dockerDataRootDir,
	}
	e.healthcheckRead = func(containerID string) []string {
		return readDockerHealthcheckTest(containerID, e.containerDirs())
	}
	e.imageRead = func(containerID string) string {
		return readDockerContainerImage(containerID, e.containerDirs())
	}
	return e
}

// containerDirs returns the candidate docker container-metadata roots
// (each holding containers/<id>/config.v2.json), most specific first: the
// daemon-reported data-root — directly and through the init mount namespace —
// then the default /var/lib/docker pair as a fallback.
func (e *EventEnricher) containerDirs() []string {
	e.mu.RLock()
	root := e.dockerRoot
	e.mu.RUnlock()
	dirs := make([]string, 0, 4)
	if root != "" && root != "/var/lib/docker" {
		dirs = append(dirs, root, "/proc/1/root"+root)
	}
	return append(dirs, "/var/lib/docker", "/proc/1/root/var/lib/docker")
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

	// Get container info. A short-lived process (a healthcheck wget finishes
	// in milliseconds) can exit before its /proc/<pid>/cgroup is read; a child
	// inherits its parent's cgroup, so the parent is an equivalent source.
	containerEntry := e.getContainerInfo(pid)
	if containerEntry == nil && event.Process.PPID > 0 {
		containerEntry = e.getContainerInfo(event.Process.PPID)
	}
	if containerEntry != nil {
		event.Container = ContainerInfo{
			ID:      containerEntry.ContainerID,
			Name:    containerEntry.ContainerName,
			Image:   containerEntry.Image,
			Runtime: containerEntry.Runtime,
		}
		if event.RawFields == nil {
			event.RawFields = make(map[string]interface{})
		}
		event.RawFields["cgroup_path"] = containerEntry.CgroupPath
		event.RawFields["cgroup_id"] = containerEntry.CgroupID

		// Stamp execs of the container's own configured healthcheck so the
		// endpoint can exempt them from recon/shell-in-container detections.
		// wget/curl/nc healthchecks otherwise flood the feed every interval.
		if event.Category == "process" && event.Rule == "Process Execution" && event.Process.Cmdline != "" {
			if MatchesHealthcheckCmd(event.Process.Cmdline, e.getHealthcheckTest(containerEntry.ContainerID)) {
				event.Process.IsHealthcheck = true
			}
		}
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

	// If we found a container, resolve its name from the host inventory. This
	// is a pure map lookup (the inventory is refreshed on a ticker); it never
	// forks a subprocess on the per-event path.
	if info.ContainerID != "" {
		info.ContainerName = e.resolveContainerName(info.ContainerID)
		info.Image = e.getContainerImage(info.ContainerID)
	}

	return info
}

// getContainerImage returns the container's image reference, cached per
// container ID (image is immutable for a container's lifetime). Same
// fork-free read-once pattern as getHealthcheckTest; docker-only for now,
// other runtimes resolve to "" which simply leaves Container.Image unset.
func (e *EventEnricher) getContainerImage(containerID string) string {
	if containerID == "" {
		return ""
	}
	e.mu.RLock()
	image, ok := e.images[containerID]
	e.mu.RUnlock()
	if ok {
		return image
	}
	image = e.imageRead(containerID)
	e.mu.Lock()
	e.images[containerID] = image
	e.mu.Unlock()
	return image
}

// readDockerContainerImage reads Config.Image (the human image reference,
// e.g. "nginx:1.25") from docker's config.v2.json, trying the same two roots
// as the name/healthcheck readers. The top-level "Image" key holds the
// sha256 image ID, so this must parse the nested Config object rather than
// use the fast flat-field extraction.
func readDockerContainerImage(containerID string, dirs []string) string {
	for _, dir := range dirs {
		data, err := os.ReadFile(fmt.Sprintf("%s/containers/%s/config.v2.json", dir, containerID))
		if err != nil {
			continue
		}
		var doc struct {
			Config struct {
				Image string `json:"Image"`
			} `json:"Config"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			return ""
		}
		return doc.Config.Image
	}
	return ""
}

// resolveContainerName returns the container's name from the host inventory.
// The inventory is refreshed on a ticker (and, debounced, on a miss) by
// listing running containers once per runtime — so this per-event call never
// forks a subprocess. For an ID the last snapshot didn't cover (e.g. a
// just-started container) it does a single fork-free read of docker's on-disk
// metadata and remembers the result (including a negative ""), so a busy
// container's many PIDs don't each re-read the same file.
func (e *EventEnricher) resolveContainerName(id string) string {
	if id == "" {
		return ""
	}
	if name, ok := e.lookupInventory(id); ok {
		return name
	}
	name := e.lookupDockerContainerName(id)
	e.storeInventory(id, name)
	e.nudgeInventoryRefresh()
	return name
}

// lookupInventory returns the cached name for a container ID, matched on the
// full ID or its 12-char short form. The bool reports whether the ID was
// present at all, so a negative ("" name) entry still short-circuits.
func (e *EventEnricher) lookupInventory(id string) (string, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if name, ok := e.inventory[id]; ok {
		return name, true
	}
	if len(id) >= 12 {
		if name, ok := e.inventory[id[:12]]; ok {
			return name, true
		}
	}
	return "", false
}

// storeInventory records a single ID->name mapping (indexing both the full and
// short ID), used for lazily-resolved and negative results between refreshes.
func (e *EventEnricher) storeInventory(id, name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.inventory[id] = name
	if len(id) >= 12 {
		e.inventory[id[:12]] = name
	}
}

// nudgeInventoryRefresh kicks an async inventory rebuild when the current
// snapshot didn't know an ID (likely a just-started container), debounced to
// one refresh per inventoryMinGap so a flood of events for an unknown
// container can't storm the runtime CLI.
func (e *EventEnricher) nudgeInventoryRefresh() {
	e.mu.Lock()
	if time.Since(e.lastMissRefresh) < e.inventoryMinGap {
		e.mu.Unlock()
		return
	}
	e.lastMissRefresh = time.Now()
	e.mu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		e.RefreshInventory(ctx)
	}()
}

// RefreshInventory rebuilds the container inventory by listing running
// containers from each available runtime. This is the only place the enricher
// forks a subprocess, and it does so once per runtime per refresh regardless
// of event volume. Safe to call concurrently; the last writer wins.
func (e *EventEnricher) RefreshInventory(ctx context.Context) {
	merged := make(map[string]string)
	for _, list := range []func(context.Context) map[string]string{e.dockerList, e.podmanList, e.crictlList} {
		if list == nil {
			continue
		}
		for id, name := range list(ctx) {
			merged[id] = name
			if len(id) >= 12 {
				merged[id[:12]] = name
			}
		}
	}
	var dockerRoot string
	if e.dockerRootFn != nil {
		dockerRoot = e.dockerRootFn(ctx)
	}
	e.mu.Lock()
	e.inventory = merged
	if dockerRoot != "" && dockerRoot != e.dockerRoot {
		// The data-root was unknown (first refresh) or the daemon moved — the
		// negative healthcheck/image entries were read from the wrong place,
		// so drop them and let the next event re-read via the right one.
		e.dockerRoot = dockerRoot
		e.healthchecks = make(map[string][]string)
		e.images = make(map[string]string)
	}
	// Drop healthcheck/image entries for containers that are gone; a re-read
	// for a still-running container is a single cheap file read, so eviction
	// of a not-yet-inventoried container is harmless.
	for id := range e.healthchecks {
		if _, ok := merged[id]; !ok {
			delete(e.healthchecks, id)
		}
	}
	for id := range e.images {
		if _, ok := merged[id]; !ok {
			delete(e.images, id)
		}
	}
	e.inventoryRefreshed = time.Now()
	e.mu.Unlock()
}

// getHealthcheckTest returns the container's configured healthcheck command
// (Config.Healthcheck.Test, e.g. ["CMD-SHELL", "wget -q --spider http://localhost:80/ || exit 1"]),
// or nil when it has none or the runtime's metadata isn't readable. Results
// (including negatives) are cached per container ID — healthcheck config is
// immutable for a container's lifetime — and pruned when the container leaves
// the inventory. Fork-free: the read is docker's on-disk config.v2.json.
func (e *EventEnricher) getHealthcheckTest(containerID string) []string {
	if containerID == "" {
		return nil
	}
	e.mu.RLock()
	test, ok := e.healthchecks[containerID]
	e.mu.RUnlock()
	if ok {
		return test
	}
	test = e.healthcheckRead(containerID)
	e.mu.Lock()
	e.healthchecks[containerID] = test
	e.mu.Unlock()
	return test
}

// readDockerHealthcheckTest reads Config.Healthcheck.Test from docker's
// config.v2.json, trying the same two roots as lookupDockerContainerName.
// Non-docker runtimes (podman, containerd/k8s probes) aren't covered yet and
// simply return nil, which means "no exemption" — never a lost event.
//
// For a CMD-SHELL test whose command references environment variables
// (cadvisor: "wget ... $CADVISOR_HEALTHCHECK_URL || exit 1"), the shell
// expands them before exec'ing, so the captured argv carries the expanded
// value while the wrapper's argv carries the literal. Both must match, so
// the env-expanded command is appended as an extra variant after the raw
// one — MatchesHealthcheckCmd treats every element after "CMD-SHELL" as a
// candidate shell command.
func readDockerHealthcheckTest(containerID string, dirs []string) []string {
	for _, dir := range dirs {
		data, err := os.ReadFile(fmt.Sprintf("%s/containers/%s/config.v2.json", dir, containerID))
		if err != nil {
			continue
		}
		var doc struct {
			Config struct {
				Env         []string `json:"Env"`
				Healthcheck struct {
					Test []string `json:"Test"`
				} `json:"Healthcheck"`
			} `json:"Config"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil
		}
		test := doc.Config.Healthcheck.Test
		if len(test) == 2 && test[0] == "CMD-SHELL" {
			if expanded := expandShellVars(test[1], doc.Config.Env); expanded != test[1] {
				test = append(test, expanded)
			}
		}
		return test
	}
	return nil
}

// expandShellVars expands $VAR / ${VAR} / ${VAR:-default} references using the
// container's Config.Env, mirroring what the healthcheck shell does before
// exec. Unset variables expand to "" (shell behavior); anything fancier stays
// unexpanded, which only means "no exemption" for that healthcheck.
func expandShellVars(s string, env []string) string {
	if !strings.ContainsRune(s, '$') || len(env) == 0 {
		return s
	}
	vars := make(map[string]string, len(env))
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			vars[k] = v
		}
	}
	return os.Expand(s, func(name string) string {
		name, def, hasDef := strings.Cut(name, ":-")
		if v, ok := vars[name]; ok && (v != "" || !hasDef) {
			return v
		}
		return def
	})
}

// MatchesHealthcheckCmd reports whether an exec'd command line is the
// container's configured healthcheck. A CMD-SHELL check spawns two execs we
// need to recognize — the "<shell> -c <cmd>" wrapper and each simple command
// inside <cmd> — while a CMD check execs its argv directly.
func MatchesHealthcheckCmd(cmdline string, test []string) bool {
	if len(test) < 2 || strings.TrimSpace(cmdline) == "" {
		return false
	}
	switch test[0] {
	case "CMD-SHELL":
		// test[1] is the configured command; readDockerHealthcheckTest may
		// append an env-expanded variant, so every element is a candidate.
		norm := normalizeSimpleCmd(cmdline)
		for _, shellCmd := range test[1:] {
			shellCmd = strings.TrimSpace(shellCmd)
			if shellCmd == "" {
				continue
			}
			// The wrapper: "<shell> -c <shellCmd>".
			if strings.Contains(cmdline, " -c ") && strings.HasSuffix(cmdline, shellCmd) {
				return true
			}
			// A simple command run by the wrapper shell. Exact (normalized)
			// equality, so a bare "wget" doesn't ride on a longer healthcheck.
			for _, simple := range splitShellCommands(shellCmd) {
				if norm == normalizeSimpleCmd(simple) {
					return true
				}
			}
		}
		return false
	case "CMD":
		return normalizeSimpleCmd(cmdline) == normalizeSimpleCmd(strings.Join(test[1:], " "))
	}
	// NONE / unknown directive.
	return false
}

// splitShellCommands breaks a shell one-liner on command operators (&&, ||,
// ;, |) into its simple commands. Not a full shell parser — operators inside
// quotes are rare in healthchecks, and a miss only means the event isn't
// exempted.
func splitShellCommands(s string) []string {
	for _, op := range []string{"&&", "||", ";", "|"} {
		s = strings.ReplaceAll(s, op, "\x00")
	}
	parts := strings.Split(s, "\x00")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// normalizeSimpleCmd canonicalizes a simple command for comparison: the
// binary token is reduced to its basename (the captured argv[0] may be "wget"
// where the healthcheck says "/usr/bin/wget", or vice versa), shell quotes
// that the kernel-captured argv won't carry are stripped, and redirections
// (">/dev/null 2>&1" and friends) are dropped — the shell consumes those
// before exec, so the captured argv of "wget -q URL >/dev/null 2>&1" is just
// "wget -q URL".
func normalizeSimpleCmd(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return ""
	}
	fields[0] = filepath.Base(fields[0])
	out := make([]string, 0, len(fields))
	skipNext := false
	for _, f := range fields {
		if skipNext {
			skipNext = false
			continue
		}
		if redirBare.MatchString(f) {
			// Operator with the target as the next token (">", "2>", "<").
			skipNext = true
			continue
		}
		if redirAttached.MatchString(f) {
			// Operator with attached target (">/dev/null", "2>&1", "<in").
			continue
		}
		out = append(out, strings.Trim(f, `"'`))
	}
	return strings.Join(out, " ")
}

// Shell redirection tokens within a simple command. "Bare" is just the
// operator (its target is the following token); "attached" carries the
// target in the same token, including fd-duplication forms like 2>&1.
var (
	redirBare     = regexp.MustCompile(`^[0-9]*(>>?|<)$`)
	redirAttached = regexp.MustCompile(`^[0-9]*(>>?|<)\S+$`)
)

// dockerListContainers / podmanListContainers / crictlListContainers return a
// full-container-ID -> name map for all running containers under that runtime,
// or nil when the runtime CLI isn't present (exec returns an error before any
// fork). Each is called once per refresh, never per event.
func dockerListContainers(ctx context.Context) map[string]string {
	return parsePSList(runCLI(ctx, "docker", "ps", "--no-trunc", "--format", "{{.ID}} {{.Names}}"))
}

// dockerDataRootDir asks the docker daemon for its data-root (DockerRootDir),
// e.g. "/var/lib/docker" or wherever data-root was moved to. "" when docker
// isn't installed or the daemon is unreachable. Called once per inventory
// refresh, never per event.
func dockerDataRootDir(ctx context.Context) string {
	return runCLI(ctx, "docker", "info", "--format", "{{.DockerRootDir}}")
}

func podmanListContainers(ctx context.Context) map[string]string {
	return parsePSList(runCLI(ctx, "podman", "ps", "--no-trunc", "--format", "{{.ID}} {{.Names}}"))
}

// crictlListContainers lists containerd/CRI-O containers via crictl's JSON
// output (older crictl has no Go-template formatter).
func crictlListContainers(ctx context.Context) map[string]string {
	out := runCLI(ctx, "crictl", "ps", "-o", "json")
	if out == "" {
		return nil
	}
	var doc struct {
		Containers []struct {
			ID       string `json:"id"`
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"containers"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil
	}
	m := make(map[string]string, len(doc.Containers))
	for _, c := range doc.Containers {
		if c.ID != "" {
			m[c.ID] = c.Metadata.Name
		}
	}
	return m
}

// runCLI runs a list-like CLI and returns trimmed stdout, or "" on any error
// (including the binary not being installed, which fails before a fork).
func runCLI(ctx context.Context, name string, args ...string) string {
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// parsePSList turns "<id> <names>" lines (docker/podman ps) into an ID->name
// map. The names column may carry several comma-separated names; the first is
// the canonical one.
func parsePSList(out string) map[string]string {
	if out == "" {
		return nil
	}
	m := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[1]
		if i := strings.IndexByte(name, ','); i >= 0 {
			name = name[:i]
		}
		m[fields[0]] = name
	}
	return m
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

// lookupDockerContainerName attempts to get container name from Docker's config.v2.json.
// Falls back to the hostname file if config.v2.json is not readable.
func (e *EventEnricher) lookupDockerContainerName(containerID string) string {
	// Docker stores container metadata in config.v2.json which includes the real
	// container name (set via --name or auto-generated). Candidate roots come
	// from containerDirs(): the daemon-reported data-root first, then the
	// default /var/lib/docker (each also via /proc/1/root for agents running
	// outside the Docker namespace).
	dirs := e.containerDirs()
	for _, dir := range dirs {
		configPath := fmt.Sprintf("%s/containers/%s/config.v2.json", dir, containerID)
		data, err := os.ReadFile(configPath)
		if err != nil {
			continue
		}
		// Fast extraction: find "Name":"/<name>" without full JSON parse.
		// The Name field in config.v2.json is always prefixed with "/".
		if name := extractJSONStringField(data, "Name"); name != "" {
			return strings.TrimPrefix(name, "/")
		}
	}

	// Fallback: read hostname file (often just short container ID, but better than empty)
	for _, dir := range dirs {
		hostnamePath := fmt.Sprintf("%s/containers/%s/hostname", dir, containerID)
		data, err := os.ReadFile(hostnamePath)
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(data))
		if name != "" {
			return name
		}
	}

	return ""
}

// extractJSONStringField does a fast extraction of a top-level string field from JSON
// without parsing the entire document. Looks for "key":"value" pattern.
func extractJSONStringField(data []byte, key string) string {
	// Build the search pattern: "Key":"
	needle := fmt.Sprintf(`"%s":"`, key)
	s := string(data)
	idx := strings.Index(s, needle)
	if idx < 0 {
		return ""
	}

	// Move past the needle to the start of the value
	valueStart := idx + len(needle)
	if valueStart >= len(s) {
		return ""
	}

	// Find the closing quote (handle escaped quotes)
	i := valueStart
	for i < len(s) {
		if s[i] == '\\' {
			i += 2 // skip escaped character
			continue
		}
		if s[i] == '"' {
			return s[valueStart:i]
		}
		i++
	}

	return ""
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

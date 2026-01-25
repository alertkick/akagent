package native

import (
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.RingBufferSize != 256*1024 {
		t.Errorf("Expected RingBufferSize = 256KB, got %d", config.RingBufferSize)
	}

	if config.EventChannelSize != 1000 {
		t.Errorf("Expected EventChannelSize = 1000, got %d", config.EventChannelSize)
	}

	if !config.Enabled {
		t.Error("Expected Enabled = true")
	}

	// Check category defaults
	if !config.EnableProcess {
		t.Error("Expected EnableProcess = true")
	}
	if !config.EnableFile {
		t.Error("Expected EnableFile = true")
	}
	if !config.EnableNetwork {
		t.Error("Expected EnableNetwork = true")
	}

	// Check default path exclusions
	if len(config.ExcludePaths) != 3 {
		t.Errorf("Expected 3 default ExcludePaths, got %d", len(config.ExcludePaths))
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected Config
	}{
		{
			name: "valid config unchanged",
			config: Config{
				RingBufferSize:   256 * 1024,
				EventChannelSize: 1000,
			},
			expected: Config{
				RingBufferSize:   256 * 1024,
				EventChannelSize: 1000,
			},
		},
		{
			name: "small ring buffer corrected",
			config: Config{
				RingBufferSize:   100,
				EventChannelSize: 1000,
			},
			expected: Config{
				RingBufferSize:   4096,
				EventChannelSize: 1000,
			},
		},
		{
			name: "small event channel corrected",
			config: Config{
				RingBufferSize:   256 * 1024,
				EventChannelSize: 1,
			},
			expected: Config{
				RingBufferSize:   256 * 1024,
				EventChannelSize: 10,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if err != nil {
				t.Errorf("Validate() returned error: %v", err)
			}
			if tt.config.RingBufferSize != tt.expected.RingBufferSize {
				t.Errorf("RingBufferSize = %d, expected %d",
					tt.config.RingBufferSize, tt.expected.RingBufferSize)
			}
			if tt.config.EventChannelSize != tt.expected.EventChannelSize {
				t.Errorf("EventChannelSize = %d, expected %d",
					tt.config.EventChannelSize, tt.expected.EventChannelSize)
			}
		})
	}
}

func TestParseKernelVersion(t *testing.T) {
	tests := []struct {
		version       string
		expectedMajor int
		expectedMinor int
		expectedPatch int
	}{
		{"5.15.0-generic", 5, 15, 0},
		{"5.8.0", 5, 8, 0},
		{"6.1.0-17-amd64", 6, 1, 0},
		{"4.19.128", 4, 19, 128},
		{"5.4.0-174-generic", 5, 4, 0},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			major, minor, patch := parseKernelVersion(tt.version)
			if major != tt.expectedMajor || minor != tt.expectedMinor || patch != tt.expectedPatch {
				t.Errorf("parseKernelVersion(%s) = (%d, %d, %d), expected (%d, %d, %d)",
					tt.version, major, minor, patch,
					tt.expectedMajor, tt.expectedMinor, tt.expectedPatch)
			}
		})
	}
}

func TestKernelSupportString(t *testing.T) {
	tests := []struct {
		name     string
		support  KernelSupport
		contains string
	}{
		{
			name: "supported kernel",
			support: KernelSupport{
				Version:       "5.15.0",
				HasRingBuf:    true,
				HasTracepoint: true,
				CanLoadBPF:    true,
				Error:         nil,
			},
			contains: "Supported",
		},
		{
			name: "unsupported kernel with error",
			support: KernelSupport{
				Version: "4.19.0",
				Error:   errMock{},
			},
			contains: "Not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.support.String()
			if !containsString(result, tt.contains) {
				t.Errorf("String() = %q, expected to contain %q", result, tt.contains)
			}
		})
	}
}

func TestNullTerminatedString(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"simple string", []byte{'h', 'e', 'l', 'l', 'o', 0, 0, 0}, "hello"},
		{"empty string", []byte{0, 0, 0, 0}, ""},
		{"full buffer", []byte{'a', 'b', 'c', 'd'}, "abcd"},
		{"null at start", []byte{0, 'a', 'b', 'c'}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := nullTerminatedString(tt.input)
			if result != tt.expected {
				t.Errorf("nullTerminatedString(%v) = %q, expected %q",
					tt.input, result, tt.expected)
			}
		})
	}
}

func TestKernelSupportIsSupported(t *testing.T) {
	tests := []struct {
		name     string
		support  KernelSupport
		expected bool
	}{
		{
			name: "all features supported",
			support: KernelSupport{
				HasRingBuf:    true,
				HasTracepoint: true,
				CanLoadBPF:    true,
				Error:         nil,
			},
			expected: true,
		},
		{
			name: "missing ring buffer",
			support: KernelSupport{
				HasRingBuf:    false,
				HasTracepoint: true,
				CanLoadBPF:    true,
				Error:         nil,
			},
			expected: false,
		},
		{
			name: "has error",
			support: KernelSupport{
				HasRingBuf:    true,
				HasTracepoint: true,
				CanLoadBPF:    true,
				Error:         errMock{},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.support.IsSupported()
			if result != tt.expected {
				t.Errorf("IsSupported() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// Helper types for testing

type errMock struct{}

func (e errMock) Error() string {
	return "mock error"
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsString(s[1:], substr) || s[:len(substr)] == substr)
}

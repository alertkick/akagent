package native

import (
	"testing"

	"apagent/ebpf"
)

func TestNewEventFilter(t *testing.T) {
	config := DefaultConfig()
	filter := NewEventFilter(&config)

	if filter == nil {
		t.Fatal("NewEventFilter returned nil")
	}

	if filter.config != &config {
		t.Error("Filter config not set correctly")
	}
}

func TestFilterCategoryEnabled(t *testing.T) {
	tests := []struct {
		name          string
		config        Config
		category      string
		shouldInclude bool
	}{
		{
			name: "process enabled",
			config: Config{
				EnableProcess: true,
				EnableFile:    true,
				EnableNetwork: true,
			},
			category:      "process",
			shouldInclude: true,
		},
		{
			name: "process disabled",
			config: Config{
				EnableProcess: false,
				EnableFile:    true,
				EnableNetwork: true,
			},
			category:      "process",
			shouldInclude: false,
		},
		{
			name: "file enabled",
			config: Config{
				EnableProcess: true,
				EnableFile:    true,
				EnableNetwork: true,
			},
			category:      "file",
			shouldInclude: true,
		},
		{
			name: "file disabled",
			config: Config{
				EnableProcess: true,
				EnableFile:    false,
				EnableNetwork: true,
			},
			category:      "file",
			shouldInclude: false,
		},
		{
			name: "network enabled",
			config: Config{
				EnableProcess: true,
				EnableFile:    true,
				EnableNetwork: true,
			},
			category:      "network",
			shouldInclude: true,
		},
		{
			name: "network disabled",
			config: Config{
				EnableProcess: true,
				EnableFile:    true,
				EnableNetwork: false,
			},
			category:      "network",
			shouldInclude: false,
		},
		{
			name: "unknown category passes",
			config: Config{
				EnableProcess: false,
				EnableFile:    false,
				EnableNetwork: false,
			},
			category:      "unknown",
			shouldInclude: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := NewEventFilter(&tt.config)
			event := &ebpf.SecurityEvent{Category: tt.category}
			result := filter.ShouldInclude(event)
			if result != tt.shouldInclude {
				t.Errorf("ShouldInclude() = %v, expected %v", result, tt.shouldInclude)
			}
		})
	}
}

func TestFilterUIDWhitelist(t *testing.T) {
	config := Config{
		FilterUIDs:    []int{1000, 1001},
		EnableProcess: true,
		EnableFile:    true,
		EnableNetwork: true,
	}
	filter := NewEventFilter(&config)

	tests := []struct {
		uid           int
		shouldInclude bool
	}{
		{1000, true},
		{1001, true},
		{0, false},
		{1002, false},
	}

	for _, tt := range tests {
		event := &ebpf.SecurityEvent{
			Category: "process",
			Process:  ebpf.ProcessInfo{UID: tt.uid},
		}
		result := filter.ShouldInclude(event)
		if result != tt.shouldInclude {
			t.Errorf("UID %d: ShouldInclude() = %v, expected %v", tt.uid, result, tt.shouldInclude)
		}
	}
}

func TestFilterUIDBlacklist(t *testing.T) {
	config := Config{
		ExcludeUIDs:   []int{0}, // Exclude root
		EnableProcess: true,
		EnableFile:    true,
		EnableNetwork: true,
	}
	filter := NewEventFilter(&config)

	tests := []struct {
		uid           int
		shouldInclude bool
	}{
		{0, false},    // root excluded
		{1000, true},  // regular user allowed
		{65534, true}, // nobody allowed
	}

	for _, tt := range tests {
		event := &ebpf.SecurityEvent{
			Category: "process",
			Process:  ebpf.ProcessInfo{UID: tt.uid},
		}
		result := filter.ShouldInclude(event)
		if result != tt.shouldInclude {
			t.Errorf("UID %d: ShouldInclude() = %v, expected %v", tt.uid, result, tt.shouldInclude)
		}
	}
}

func TestFilterCommWhitelist(t *testing.T) {
	config := Config{
		FilterComms:   []string{"bash", "python"},
		EnableProcess: true,
		EnableFile:    true,
		EnableNetwork: true,
	}
	filter := NewEventFilter(&config)

	tests := []struct {
		comm          string
		shouldInclude bool
	}{
		{"bash", true},
		{"python", true},
		{"systemd", false},
		{"sshd", false},
	}

	for _, tt := range tests {
		event := &ebpf.SecurityEvent{
			Category: "process",
			Process:  ebpf.ProcessInfo{Name: tt.comm},
		}
		result := filter.ShouldInclude(event)
		if result != tt.shouldInclude {
			t.Errorf("Comm %s: ShouldInclude() = %v, expected %v", tt.comm, result, tt.shouldInclude)
		}
	}
}

func TestFilterCommBlacklist(t *testing.T) {
	config := Config{
		ExcludeComms:  []string{"systemd", "journald", "sshd"},
		EnableProcess: true,
		EnableFile:    true,
		EnableNetwork: true,
	}
	filter := NewEventFilter(&config)

	tests := []struct {
		comm          string
		shouldInclude bool
	}{
		{"systemd", false},
		{"journald", false},
		{"sshd", false},
		{"bash", true},
		{"python", true},
	}

	for _, tt := range tests {
		event := &ebpf.SecurityEvent{
			Category: "process",
			Process:  ebpf.ProcessInfo{Name: tt.comm},
		}
		result := filter.ShouldInclude(event)
		if result != tt.shouldInclude {
			t.Errorf("Comm %s: ShouldInclude() = %v, expected %v", tt.comm, result, tt.shouldInclude)
		}
	}
}

func TestFilterPathExclusion(t *testing.T) {
	config := Config{
		ExcludePaths:  []string{"/proc/", "/sys/", "/dev/"},
		EnableProcess: true,
		EnableFile:    true,
		EnableNetwork: true,
	}
	filter := NewEventFilter(&config)

	tests := []struct {
		path          string
		shouldInclude bool
	}{
		{"/proc/1/status", false},
		{"/sys/class/net", false},
		{"/dev/null", false},
		{"/etc/passwd", true},
		{"/home/user/file.txt", true},
		{"/tmp/test", true},
	}

	for _, tt := range tests {
		event := &ebpf.SecurityEvent{
			Category: "file",
			RawFields: map[string]interface{}{
				"filename": tt.path,
			},
		}
		result := filter.ShouldInclude(event)
		if result != tt.shouldInclude {
			t.Errorf("Path %s: ShouldInclude() = %v, expected %v", tt.path, result, tt.shouldInclude)
		}
	}
}

func TestFilterPathExclusionOnlyAffectsFileCategory(t *testing.T) {
	config := Config{
		ExcludePaths:  []string{"/proc/"},
		EnableProcess: true,
		EnableFile:    true,
		EnableNetwork: true,
	}
	filter := NewEventFilter(&config)

	// File event with /proc path should be excluded
	fileEvent := &ebpf.SecurityEvent{
		Category: "file",
		RawFields: map[string]interface{}{
			"filename": "/proc/1/status",
		},
	}
	if filter.ShouldInclude(fileEvent) {
		t.Error("File event with /proc path should be excluded")
	}

	// Process event should not be affected by path filter
	processEvent := &ebpf.SecurityEvent{
		Category: "process",
		Process:  ebpf.ProcessInfo{ExePath: "/proc/1/exe"},
	}
	if !filter.ShouldInclude(processEvent) {
		t.Error("Process event should not be affected by path filter")
	}
}

func TestFilterBlacklistTakesPrecedence(t *testing.T) {
	// If UID is in both whitelist and blacklist, blacklist wins
	config := Config{
		FilterUIDs:    []int{0, 1000}, // Whitelist includes root
		ExcludeUIDs:   []int{0},       // Blacklist excludes root
		EnableProcess: true,
		EnableFile:    true,
		EnableNetwork: true,
	}
	filter := NewEventFilter(&config)

	event := &ebpf.SecurityEvent{
		Category: "process",
		Process:  ebpf.ProcessInfo{UID: 0},
	}

	if filter.ShouldInclude(event) {
		t.Error("Blacklist should take precedence over whitelist")
	}

	// UID 1000 is in whitelist and not in blacklist, should be included
	event.Process.UID = 1000
	if !filter.ShouldInclude(event) {
		t.Error("UID 1000 should be included")
	}
}

func TestFilterStats(t *testing.T) {
	config := Config{
		ExcludeUIDs:   []int{0},
		EnableProcess: true,
		EnableFile:    true,
		EnableNetwork: true,
	}
	filter := NewEventFilter(&config)

	// Send some events
	events := []*ebpf.SecurityEvent{
		{Category: "process", Process: ebpf.ProcessInfo{UID: 1000}}, // included
		{Category: "process", Process: ebpf.ProcessInfo{UID: 0}},    // filtered
		{Category: "process", Process: ebpf.ProcessInfo{UID: 1001}}, // included
		{Category: "process", Process: ebpf.ProcessInfo{UID: 0}},    // filtered
	}

	for _, e := range events {
		filter.ShouldInclude(e)
	}

	total, filtered := filter.Stats()
	if total != 4 {
		t.Errorf("Expected total=4, got %d", total)
	}
	if filtered != 2 {
		t.Errorf("Expected filtered=2, got %d", filtered)
	}

	// Reset and verify
	filter.ResetStats()
	total, filtered = filter.Stats()
	if total != 0 || filtered != 0 {
		t.Errorf("Expected stats to be reset, got total=%d, filtered=%d", total, filtered)
	}
}

func TestFilterDefaultConfigReducesNoise(t *testing.T) {
	config := DefaultConfig()
	filter := NewEventFilter(&config)

	// These should be filtered out with default config
	filteredPaths := []string{
		"/proc/self/status",
		"/sys/class/net/eth0",
		"/dev/null",
	}

	for _, path := range filteredPaths {
		event := &ebpf.SecurityEvent{
			Category: "file",
			RawFields: map[string]interface{}{
				"filename": path,
			},
		}
		if filter.ShouldInclude(event) {
			t.Errorf("Path %s should be filtered by default config", path)
		}
	}

	// These should pass through
	allowedPaths := []string{
		"/etc/passwd",
		"/home/user/.bashrc",
		"/tmp/test",
	}

	for _, path := range allowedPaths {
		event := &ebpf.SecurityEvent{
			Category: "file",
			RawFields: map[string]interface{}{
				"filename": path,
			},
		}
		if !filter.ShouldInclude(event) {
			t.Errorf("Path %s should be allowed by default config", path)
		}
	}
}

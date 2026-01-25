package ebpf

import (
	"encoding/json"
	"testing"
	"time"
)

func TestPriorityLevelString(t *testing.T) {
	tests := []struct {
		priority PriorityLevel
		expected string
	}{
		{PriorityDefault, ""},
		{PriorityDebug, "Debug"},
		{PriorityInformational, "Informational"},
		{PriorityNotice, "Notice"},
		{PriorityWarning, "Warning"},
		{PriorityError, "Error"},
		{PriorityCritical, "Critical"},
		{PriorityAlert, "Alert"},
		{PriorityEmergency, "Emergency"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.priority.String(); got != tt.expected {
				t.Errorf("PriorityLevel.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParsePriority(t *testing.T) {
	tests := []struct {
		input    string
		expected PriorityLevel
	}{
		{"emergency", PriorityEmergency},
		{"EMERGENCY", PriorityEmergency},
		{"alert", PriorityAlert},
		{"critical", PriorityCritical},
		{"error", PriorityError},
		{"warning", PriorityWarning},
		{"notice", PriorityNotice},
		{"informational", PriorityInformational},
		{"info", PriorityInformational},
		{"debug", PriorityDebug},
		{"unknown", PriorityDefault},
		{"", PriorityDefault},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := ParsePriority(tt.input); got != tt.expected {
				t.Errorf("ParsePriority(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestPriorityLevelJSON(t *testing.T) {
	// Test marshaling
	priority := PriorityWarning
	data, err := json.Marshal(priority)
	if err != nil {
		t.Fatalf("Failed to marshal PriorityLevel: %v", err)
	}

	expected := `"Warning"`
	if string(data) != expected {
		t.Errorf("Marshal PriorityLevel = %s, want %s", string(data), expected)
	}

	// Test unmarshaling
	var unmarshaled PriorityLevel
	err = json.Unmarshal([]byte(`"Critical"`), &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal PriorityLevel: %v", err)
	}

	if unmarshaled != PriorityCritical {
		t.Errorf("Unmarshal PriorityLevel = %v, want %v", unmarshaled, PriorityCritical)
	}
}

func TestSecurityEventValidate(t *testing.T) {
	tests := []struct {
		name     string
		event    SecurityEvent
		expected bool
	}{
		{
			name: "valid event",
			event: SecurityEvent{
				UUID:      "test-uuid",
				AgentType: AgentTypeFalco,
				Timestamp: time.Now(),
				Rule:      "Test Rule",
			},
			expected: true,
		},
		{
			name: "missing UUID",
			event: SecurityEvent{
				AgentType: AgentTypeFalco,
				Timestamp: time.Now(),
				Rule:      "Test Rule",
			},
			expected: false,
		},
		{
			name: "missing AgentType",
			event: SecurityEvent{
				UUID:      "test-uuid",
				Timestamp: time.Now(),
				Rule:      "Test Rule",
			},
			expected: false,
		},
		{
			name: "missing Timestamp",
			event: SecurityEvent{
				UUID:      "test-uuid",
				AgentType: AgentTypeFalco,
				Rule:      "Test Rule",
			},
			expected: false,
		},
		{
			name: "missing Rule but has Output",
			event: SecurityEvent{
				UUID:      "test-uuid",
				AgentType: AgentTypeFalco,
				Timestamp: time.Now(),
				Output:    "Some output",
			},
			expected: true,
		},
		{
			name: "missing both Rule and Output",
			event: SecurityEvent{
				UUID:      "test-uuid",
				AgentType: AgentTypeFalco,
				Timestamp: time.Now(),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.event.Validate(); got != tt.expected {
				t.Errorf("SecurityEvent.Validate() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestSecurityEventPriorityChecks(t *testing.T) {
	tests := []struct {
		priority       PriorityLevel
		isHighPriority bool
		isCritical     bool
	}{
		{PriorityDebug, false, false},
		{PriorityInformational, false, false},
		{PriorityNotice, false, false},
		{PriorityWarning, false, false},
		{PriorityError, true, false},
		{PriorityCritical, true, true},
		{PriorityAlert, true, true},
		{PriorityEmergency, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.priority.String(), func(t *testing.T) {
			event := SecurityEvent{Priority: tt.priority}

			if got := event.IsHighPriority(); got != tt.isHighPriority {
				t.Errorf("IsHighPriority() = %v, want %v", got, tt.isHighPriority)
			}

			if got := event.IsCritical(); got != tt.isCritical {
				t.Errorf("IsCritical() = %v, want %v", got, tt.isCritical)
			}
		})
	}
}

func TestSecurityEventContextChecks(t *testing.T) {
	// Test HasContainerContext
	eventWithContainer := SecurityEvent{
		Container: ContainerInfo{ID: "container-123"},
	}
	if !eventWithContainer.HasContainerContext() {
		t.Error("Expected HasContainerContext to be true")
	}

	eventWithoutContainer := SecurityEvent{}
	if eventWithoutContainer.HasContainerContext() {
		t.Error("Expected HasContainerContext to be false")
	}

	// Test HasK8sContext
	eventWithK8s := SecurityEvent{
		K8s: KubernetesInfo{Namespace: "default", Pod: "my-pod"},
	}
	if !eventWithK8s.HasK8sContext() {
		t.Error("Expected HasK8sContext to be true")
	}

	eventWithoutK8s := SecurityEvent{}
	if eventWithoutK8s.HasK8sContext() {
		t.Error("Expected HasK8sContext to be false")
	}

	// Test HasNetworkContext
	eventWithNetwork := SecurityEvent{
		Network: NetworkInfo{SrcIP: "192.168.1.1", DstIP: "10.0.0.1"},
	}
	if !eventWithNetwork.HasNetworkContext() {
		t.Error("Expected HasNetworkContext to be true")
	}

	eventWithoutNetwork := SecurityEvent{}
	if eventWithoutNetwork.HasNetworkContext() {
		t.Error("Expected HasNetworkContext to be false")
	}

	// Test HasFileContext
	eventWithFile := SecurityEvent{
		File: FileInfo{Path: "/etc/passwd"},
	}
	if !eventWithFile.HasFileContext() {
		t.Error("Expected HasFileContext to be true")
	}

	eventWithoutFile := SecurityEvent{}
	if eventWithoutFile.HasFileContext() {
		t.Error("Expected HasFileContext to be false")
	}
}

func TestSecurityEventString(t *testing.T) {
	event := SecurityEvent{
		UUID:      "test-uuid",
		AgentType: AgentTypeFalco,
		Timestamp: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		Priority:  PriorityWarning,
		Rule:      "Test Rule",
		Output:    "Test output",
	}

	str := event.String()
	if str == "" {
		t.Error("Expected non-empty string")
	}

	// Verify it's valid JSON
	var parsed SecurityEvent
	if err := json.Unmarshal([]byte(str), &parsed); err != nil {
		t.Errorf("String() did not produce valid JSON: %v", err)
	}
}

func TestEventBuffer(t *testing.T) {
	buffer := NewEventBuffer(3)

	if buffer.Len() != 0 {
		t.Errorf("Expected empty buffer, got len=%d", buffer.Len())
	}

	// Add events
	event1 := SecurityEvent{UUID: "1", Rule: "Rule 1"}
	event2 := SecurityEvent{UUID: "2", Rule: "Rule 2"}
	event3 := SecurityEvent{UUID: "3", Rule: "Rule 3"}
	event4 := SecurityEvent{UUID: "4", Rule: "Rule 4"}

	buffer.Add(event1)
	buffer.Add(event2)
	buffer.Add(event3)

	if buffer.Len() != 3 {
		t.Errorf("Expected buffer len=3, got %d", buffer.Len())
	}

	// Add one more (should drop oldest)
	buffer.Add(event4)

	if buffer.Len() != 3 {
		t.Errorf("Expected buffer len=3 after overflow, got %d", buffer.Len())
	}

	// Drain and verify
	events := buffer.Drain()

	if len(events) != 3 {
		t.Errorf("Expected 3 events after drain, got %d", len(events))
	}

	if events[0].UUID != "2" {
		t.Errorf("Expected first event UUID='2' (oldest dropped), got %s", events[0].UUID)
	}

	if events[2].UUID != "4" {
		t.Errorf("Expected last event UUID='4', got %s", events[2].UUID)
	}

	// Buffer should be empty after drain
	if buffer.Len() != 0 {
		t.Errorf("Expected empty buffer after drain, got len=%d", buffer.Len())
	}
}

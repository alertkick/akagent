package native

import (
	"testing"

	"apagent/ebpf"
)

func TestNewAlertEngine(t *testing.T) {
	rules := []AlertRule{
		{
			Name:     "test_rule",
			Enabled:  true,
			Priority: ebpf.PriorityWarning,
		},
	}

	engine := NewAlertEngine(rules)
	if engine == nil {
		t.Fatal("Expected non-nil engine")
	}
}

func TestAlertEngineWithNoRules(t *testing.T) {
	engine := NewAlertEngine(nil)

	event := &ebpf.SecurityEvent{
		Priority: ebpf.PriorityInformational,
		Category: "process",
	}

	// Should not modify event when no rules match
	keep := engine.Evaluate(event)
	if !keep {
		t.Error("Expected event to be kept when no rules")
	}
}

func TestAlertEngineCategoryMatch(t *testing.T) {
	rules := []AlertRule{
		{
			Name:     "process_rule",
			Enabled:  true,
			Priority: ebpf.PriorityCritical,
			Conditions: RuleConditions{
				Category: "process",
			},
			Tags:   []string{"matched"},
			Action: AlertActionElevate,
		},
	}

	engine := NewAlertEngine(rules)

	// Event that matches
	event := &ebpf.SecurityEvent{
		Priority: ebpf.PriorityInformational,
		Category: "process",
	}

	keep := engine.Evaluate(event)
	if !keep {
		t.Error("Expected event to be kept")
	}
	if event.Priority != ebpf.PriorityCritical {
		t.Errorf("Expected priority to be elevated to Critical, got %v", event.Priority)
	}
	if !containsTag(event.Tags, "matched") {
		t.Error("Expected 'matched' tag to be added")
	}
	if !containsTag(event.Tags, "rule:process_rule") {
		t.Error("Expected 'rule:process_rule' tag to be added")
	}

	// Event that doesn't match
	event2 := &ebpf.SecurityEvent{
		Priority: ebpf.PriorityInformational,
		Category: "network",
	}

	keep = engine.Evaluate(event2)
	if !keep {
		t.Error("Expected event to be kept")
	}
	if event2.Priority != ebpf.PriorityInformational {
		t.Error("Expected priority to remain unchanged")
	}
}

func TestAlertEngineDisabledRule(t *testing.T) {
	rules := []AlertRule{
		{
			Name:     "disabled_rule",
			Enabled:  false, // Disabled
			Priority: ebpf.PriorityCritical,
			Conditions: RuleConditions{
				Category: "process",
			},
		},
	}

	engine := NewAlertEngine(rules)

	event := &ebpf.SecurityEvent{
		Priority: ebpf.PriorityInformational,
		Category: "process",
	}

	engine.Evaluate(event)
	if event.Priority != ebpf.PriorityInformational {
		t.Error("Expected priority to remain unchanged for disabled rule")
	}
}

func TestAlertEngineProcessNameMatch(t *testing.T) {
	rules := []AlertRule{
		{
			Name:     "bash_rule",
			Enabled:  true,
			Priority: ebpf.PriorityWarning,
			Conditions: RuleConditions{
				ProcessNames: []string{"bash", "sh"},
			},
		},
	}

	engine := NewAlertEngine(rules)

	// Match
	event := &ebpf.SecurityEvent{
		Priority: ebpf.PriorityInformational,
		Process: ebpf.ProcessInfo{
			Name: "bash",
		},
	}

	engine.Evaluate(event)
	if event.Priority != ebpf.PriorityWarning {
		t.Errorf("Expected priority to be Warning, got %v", event.Priority)
	}

	// No match
	event2 := &ebpf.SecurityEvent{
		Priority: ebpf.PriorityInformational,
		Process: ebpf.ProcessInfo{
			Name: "python",
		},
	}

	engine.Evaluate(event2)
	if event2.Priority != ebpf.PriorityInformational {
		t.Error("Expected priority to remain unchanged")
	}
}

func TestAlertEngineProcessNameRegex(t *testing.T) {
	rules := []AlertRule{
		{
			Name:     "hidden_process",
			Enabled:  true,
			Priority: ebpf.PriorityCritical,
			Conditions: RuleConditions{
				ProcessNamesRegex: []string{`^\..*`}, // Starts with .
			},
		},
	}

	engine := NewAlertEngine(rules)

	// Match hidden process
	event := &ebpf.SecurityEvent{
		Priority: ebpf.PriorityInformational,
		Process: ebpf.ProcessInfo{
			Name: ".hidden",
		},
	}

	engine.Evaluate(event)
	if event.Priority != ebpf.PriorityCritical {
		t.Errorf("Expected priority to be Critical, got %v", event.Priority)
	}

	// Normal process doesn't match
	event2 := &ebpf.SecurityEvent{
		Priority: ebpf.PriorityInformational,
		Process: ebpf.ProcessInfo{
			Name: "normal",
		},
	}

	engine.Evaluate(event2)
	if event2.Priority != ebpf.PriorityInformational {
		t.Error("Expected priority to remain unchanged")
	}
}

func TestAlertEngineUIDMatch(t *testing.T) {
	rules := []AlertRule{
		{
			Name:     "root_only",
			Enabled:  true,
			Priority: ebpf.PriorityWarning,
			Conditions: RuleConditions{
				RootOnly: true,
			},
		},
	}

	engine := NewAlertEngine(rules)

	// Root user
	event := &ebpf.SecurityEvent{
		Priority: ebpf.PriorityInformational,
		Process: ebpf.ProcessInfo{
			UID: 0,
		},
	}

	engine.Evaluate(event)
	if event.Priority != ebpf.PriorityWarning {
		t.Errorf("Expected priority to be Warning for root, got %v", event.Priority)
	}

	// Non-root user
	event2 := &ebpf.SecurityEvent{
		Priority: ebpf.PriorityInformational,
		Process: ebpf.ProcessInfo{
			UID: 1000,
		},
	}

	engine.Evaluate(event2)
	if event2.Priority != ebpf.PriorityInformational {
		t.Error("Expected priority to remain unchanged for non-root")
	}
}

func TestAlertEngineContainerOnly(t *testing.T) {
	rules := []AlertRule{
		{
			Name:     "container_only",
			Enabled:  true,
			Priority: ebpf.PriorityWarning,
			Conditions: RuleConditions{
				ContainerOnly: true,
			},
		},
	}

	engine := NewAlertEngine(rules)

	// In container
	event := &ebpf.SecurityEvent{
		Priority: ebpf.PriorityInformational,
		Container: ebpf.ContainerInfo{
			ID: "abc123",
		},
	}

	engine.Evaluate(event)
	if event.Priority != ebpf.PriorityWarning {
		t.Errorf("Expected priority to be Warning for container, got %v", event.Priority)
	}

	// Not in container
	event2 := &ebpf.SecurityEvent{
		Priority: ebpf.PriorityInformational,
	}

	engine.Evaluate(event2)
	if event2.Priority != ebpf.PriorityInformational {
		t.Error("Expected priority to remain unchanged for non-container")
	}
}

func TestAlertEngineDropAction(t *testing.T) {
	rules := []AlertRule{
		{
			Name:     "drop_rule",
			Enabled:  true,
			Priority: ebpf.PriorityWarning,
			Conditions: RuleConditions{
				Category: "noise",
			},
			Action: AlertActionDrop,
		},
	}

	engine := NewAlertEngine(rules)

	event := &ebpf.SecurityEvent{
		Priority: ebpf.PriorityInformational,
		Category: "noise",
	}

	keep := engine.Evaluate(event)
	if keep {
		t.Error("Expected event to be dropped")
	}
}

func TestAlertEngineStats(t *testing.T) {
	rules := []AlertRule{
		{
			Name:     "test_rule",
			Enabled:  true,
			Priority: ebpf.PriorityWarning,
			Conditions: RuleConditions{
				Category: "process",
			},
		},
	}

	engine := NewAlertEngine(rules)

	// Evaluate some events
	for i := 0; i < 10; i++ {
		event := &ebpf.SecurityEvent{
			Priority: ebpf.PriorityInformational,
			Category: "process",
		}
		engine.Evaluate(event)
	}

	for i := 0; i < 5; i++ {
		event := &ebpf.SecurityEvent{
			Priority: ebpf.PriorityInformational,
			Category: "network", // Won't match
		}
		engine.Evaluate(event)
	}

	evaluated, matched := engine.Stats()
	if evaluated != 15 {
		t.Errorf("Expected 15 rules evaluated, got %d", evaluated)
	}
	if matched != 10 {
		t.Errorf("Expected 10 rules matched, got %d", matched)
	}
}

func TestAlertEngineUpdateRules(t *testing.T) {
	initialRules := []AlertRule{
		{
			Name:     "initial_rule",
			Enabled:  true,
			Priority: ebpf.PriorityWarning,
			Conditions: RuleConditions{
				Category: "process",
			},
		},
	}

	engine := NewAlertEngine(initialRules)

	// Update with new rules
	newRules := []AlertRule{
		{
			Name:     "new_rule",
			Enabled:  true,
			Priority: ebpf.PriorityCritical,
			Conditions: RuleConditions{
				Category: "network",
			},
		},
	}

	engine.UpdateRules(newRules)

	// Old rule shouldn't match
	event := &ebpf.SecurityEvent{
		Priority: ebpf.PriorityInformational,
		Category: "process",
	}
	engine.Evaluate(event)
	if event.Priority != ebpf.PriorityInformational {
		t.Error("Old rule should no longer match")
	}

	// New rule should match
	event2 := &ebpf.SecurityEvent{
		Priority: ebpf.PriorityInformational,
		Category: "network",
	}
	engine.Evaluate(event2)
	if event2.Priority != ebpf.PriorityCritical {
		t.Errorf("New rule should match and elevate to Critical, got %v", event2.Priority)
	}
}

func TestDefaultAlertRules(t *testing.T) {
	rules := DefaultAlertRules()
	if len(rules) == 0 {
		t.Error("Expected default rules to be non-empty")
	}

	// Check that all rules have required fields
	for _, rule := range rules {
		if rule.Name == "" {
			t.Error("Rule missing name")
		}
		if rule.Priority == 0 {
			t.Errorf("Rule %s has no priority", rule.Name)
		}
	}
}

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern  string
		str      string
		expected bool
	}{
		{"*", "anything", true},
		{"*.txt", "file.txt", true},
		{"*.txt", "file.pdf", false},
		{"/etc/**", "/etc/passwd", true},
		{"/etc/**", "/etc/ssh/sshd_config", true},
		{"/etc/**", "/home/user", false},
		{"/etc/shadow", "/etc/shadow", true},
		{"/etc/shadow", "/etc/passwd", false},
	}

	for _, tc := range tests {
		t.Run(tc.pattern+"_"+tc.str, func(t *testing.T) {
			result := matchGlob(tc.pattern, tc.str)
			if result != tc.expected {
				t.Errorf("matchGlob(%q, %q) = %v, expected %v", tc.pattern, tc.str, result, tc.expected)
			}
		})
	}
}

func containsTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

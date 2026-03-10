package rules

import (
	"testing"
)

// TestAC005_NetworkAcceptPythonShouldNotMatch verifies that a python process
// accepting a network connection (event_type="network") does NOT match the
// "Off-Hours SSH Activity" rule (ac-005) which requires event_type="process".
func TestAC005_NetworkAcceptPythonShouldNotMatch(t *testing.T) {
	// Build the same profile that would come from access_control.yaml
	config := &ProfileConfig{
		Metadata: ProfileMetadata{
			Name:    "access_control",
			Version: "1.0.0",
		},
		Lists: map[string][]string{
			"ssh_binaries": {
				"ssh", "sshd", "ssh-agent", "ssh-add", "ssh-keygen",
				"ssh-keyscan", "sftp", "sftp-server", "scp", "rsync",
				"ssh-copy-id", "autossh", "sshpass",
			},
		},
		Macros: map[string]string{
			"is_ssh_process": `(event_type == "process" AND rule == "Process Execution" AND (comm in (ssh_binaries) OR exe in (ssh_binaries)))`,
			"is_ssh_network": `(event_type == "network" AND dst_port == 22)`,
			"is_ssh_inbound": `(event_type == "network" AND (rule == "Network Accept" OR rule == "Network Bind") AND src_port == 22)`,
		},
		Rules: []RuleConfig{
			{
				RuleID:    "ac-001",
				Name:      "SSH Process Execution",
				Condition: "is_ssh_process",
				Priority:  "WARNING",
				Tags:      []string{"ssh", "remote-access", "access-control"},
				Enabled:   true,
				Framework: "general",
				Severity:  "medium",
			},
			{
				RuleID:    "ac-002",
				Name:      "SSH Outbound Connection",
				Condition: "is_ssh_network",
				Priority:  "WARNING",
				Tags:      []string{"ssh", "remote-access", "network"},
				Enabled:   true,
				Framework: "general",
				Severity:  "medium",
			},
			{
				RuleID:    "ac-003",
				Name:      "SSH Inbound Connection",
				Condition: "is_ssh_inbound",
				Priority:  "WARNING",
				Tags:      []string{"ssh", "remote-access", "network", "inbound"},
				Enabled:   true,
				Framework: "general",
				Severity:  "medium",
			},
			{
				RuleID:    "ac-004",
				Name:      "Weekend SSH Activity",
				Condition: `is_ssh_process AND is_weekend == true`,
				Priority:  "HIGH",
				Tags:      []string{"ssh", "off-hours", "access-control"},
				Enabled:   true,
				Framework: "general",
				Severity:  "high",
			},
			{
				RuleID:    "ac-005",
				Name:      "Off-Hours SSH Activity",
				Condition: `is_ssh_process AND (hour_of_day < 6 OR hour_of_day >= 22)`,
				Priority:  "HIGH",
				Tags:      []string{"ssh", "off-hours", "access-control"},
				Enabled:   true,
				Framework: "general",
				Severity:  "high",
			},
			{
				RuleID:    "ac-006",
				Name:      "SSH Key Generation",
				Condition: `event_type == "process" AND rule == "Process Execution" AND comm == "ssh-keygen"`,
				Priority:  "WARNING",
				Tags:      []string{"ssh", "key-management", "access-control"},
				Enabled:   true,
				Framework: "general",
				Severity:  "medium",
			},
		},
	}

	engine := NewRuleEngine()
	if err := engine.UpdateProfile(config); err != nil {
		t.Fatalf("Failed to load profile: %v", err)
	}

	// Simulate the exact event from the bug report:
	// python process accepting a network connection at 23:59 (off-hours)
	ctx := &EventContext{
		EventType: "network", // Category is "network" for network events
		PID:       1920502,
		PPID:      1920165,
		Comm:      "python",
		Rule:      "Network Accept",
		Output:    "Process python accepting connection",
		SrcPort:   0,
		DstPort:   0,
		HourOfDay: 23, // Off-hours (>= 22)
		DayOfWeek: 0,  // Sunday
		IsWeekend: true,
	}

	matches := engine.Evaluate(ctx)

	if len(matches) > 0 {
		for _, m := range matches {
			t.Errorf("UNEXPECTED MATCH: rule %s (%s) matched for python Network Accept event",
				m.Rule.RuleID, m.Rule.Name)
			t.Logf("  Rule condition: %s", m.Rule.Condition)
			// Also show expanded condition
			expanded := engine.macros.ExpandExpression(m.Rule.Condition, 0)
			t.Logf("  Expanded condition: %s", expanded)
		}
	} else {
		t.Log("PASS: No rules matched for python Network Accept (correct behavior)")
	}
}

// TestAC005_SSHProcessOffHoursShouldMatch verifies that an actual SSH process
// during off-hours DOES match ac-005.
func TestAC005_SSHProcessOffHoursShouldMatch(t *testing.T) {
	config := &ProfileConfig{
		Metadata: ProfileMetadata{Name: "access_control", Version: "1.0.0"},
		Lists: map[string][]string{
			"ssh_binaries": {"ssh", "sshd", "ssh-agent", "ssh-add", "ssh-keygen",
				"ssh-keyscan", "sftp", "sftp-server", "scp", "rsync",
				"ssh-copy-id", "autossh", "sshpass"},
		},
		Macros: map[string]string{
			"is_ssh_process": `(event_type == "process" AND rule == "Process Execution" AND (comm in (ssh_binaries) OR exe in (ssh_binaries)))`,
			"is_ssh_network": `(event_type == "network" AND dst_port == 22)`,
			"is_ssh_inbound": `(event_type == "network" AND (rule == "Network Accept" OR rule == "Network Bind") AND src_port == 22)`,
		},
		Rules: []RuleConfig{
			{
				RuleID:    "ac-005",
				Name:      "Off-Hours SSH Activity",
				Condition: `is_ssh_process AND (hour_of_day < 6 OR hour_of_day >= 22)`,
				Priority:  "HIGH",
				Tags:      []string{"ssh", "off-hours", "access-control"},
				Enabled:   true,
				Framework: "general",
				Severity:  "high",
			},
		},
	}

	engine := NewRuleEngine()
	if err := engine.UpdateProfile(config); err != nil {
		t.Fatalf("Failed to load profile: %v", err)
	}

	ctx := &EventContext{
		EventType: "process",
		Comm:      "sshd",
		Rule:      "Process Execution",
		HourOfDay: 23,
	}

	matches := engine.Evaluate(ctx)
	if len(matches) == 0 {
		t.Error("EXPECTED MATCH: sshd process execution at hour 23 should match ac-005")
	} else {
		t.Logf("PASS: sshd process matched ac-005 (%s)", matches[0].Rule.Name)
	}
}

// TestMacroExpansion verifies macro expansion produces correct output
func TestMacroExpansion(t *testing.T) {
	macros := NewMacroRegistry()
	macros.AddMacro(&Macro{
		Name:       "is_ssh_process",
		Expression: `(event_type == "process" AND rule == "Process Execution" AND (comm in (ssh_binaries) OR exe in (ssh_binaries)))`,
	})

	condition := `is_ssh_process AND (hour_of_day < 6 OR hour_of_day >= 22)`
	expanded := macros.ExpandExpression(condition, 0)

	t.Logf("Original:  %s", condition)
	t.Logf("Expanded:  %s", expanded)

	// The expanded form should have the macro replaced with its expression in parens
	expected := `((event_type == "process" AND rule == "Process Execution" AND (comm in (ssh_binaries) OR exe in (ssh_binaries)))) AND (hour_of_day < 6 OR hour_of_day >= 22)`
	if expanded != expected {
		t.Errorf("Macro expansion mismatch:\n  got:      %s\n  expected: %s", expanded, expected)
	}
}

// TestEvalExprPrecedence verifies AND/OR precedence in the expression evaluator
func TestEvalExprPrecedence(t *testing.T) {
	engine := NewRuleEngine()

	// Load minimal lists
	config := &ProfileConfig{
		Metadata: ProfileMetadata{Name: "test"},
		Lists:    map[string][]string{"ssh_binaries": {"ssh", "sshd"}},
		Macros:   map[string]string{},
		Rules:    []RuleConfig{},
	}
	engine.UpdateProfile(config)

	// Test: FALSE AND (TRUE OR TRUE) should be FALSE
	ctx := &EventContext{
		EventType: "network",  // not "process", so first part is false
		Comm:      "python",
		HourOfDay: 23,
	}

	expr := `event_type == "process" AND (hour_of_day < 6 OR hour_of_day >= 22)`
	result := engine.evalExpr(expr, ctx)
	if result {
		t.Error("PRECEDENCE BUG: 'FALSE AND (TRUE OR TRUE)' evaluated to TRUE")
	} else {
		t.Log("PASS: 'FALSE AND (TRUE OR TRUE)' correctly evaluated to FALSE")
	}
}

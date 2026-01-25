package native

import (
	"regexp"
	"strings"
	"sync"

	"apagent/ebpf"
)

// AlertRule defines a rule for generating alerts from security events
type AlertRule struct {
	// Name is a unique identifier for the rule
	Name string `yaml:"name"`

	// Description provides context about what the rule detects
	Description string `yaml:"description,omitempty"`

	// Enabled controls whether this rule is active
	Enabled bool `yaml:"enabled"`

	// Priority to assign when this rule matches
	Priority ebpf.PriorityLevel `yaml:"priority"`

	// Conditions that must be met for the rule to match
	Conditions RuleConditions `yaml:"conditions"`

	// Tags to add to matching events
	Tags []string `yaml:"tags,omitempty"`

	// Action to take when rule matches
	Action AlertAction `yaml:"action,omitempty"`
}

// RuleConditions defines the conditions for a rule to match
type RuleConditions struct {
	// Category matches the event category (process, file, network, privilege, etc.)
	Category string `yaml:"category,omitempty"`

	// EventTypes is a list of event type constants to match
	EventTypes []int `yaml:"event_types,omitempty"`

	// ProcessNames matches against the process name (comm)
	ProcessNames []string `yaml:"process_names,omitempty"`

	// ProcessNamesRegex matches process name against regex patterns
	ProcessNamesRegex []string `yaml:"process_names_regex,omitempty"`

	// UIDs matches specific user IDs
	UIDs []int `yaml:"uids,omitempty"`

	// RootOnly matches events from UID 0
	RootOnly bool `yaml:"root_only,omitempty"`

	// PathPatterns matches file paths against patterns
	PathPatterns []string `yaml:"path_patterns,omitempty"`

	// ContainerOnly matches only containerized processes
	ContainerOnly bool `yaml:"container_only,omitempty"`

	// PrivilegeEscalation matches privilege escalation to specific UIDs
	PrivilegeEscalationToRoot bool `yaml:"privilege_escalation_to_root,omitempty"`
}

// AlertAction defines what happens when a rule matches
type AlertAction string

const (
	// AlertActionTag adds tags but keeps the event
	AlertActionTag AlertAction = "tag"

	// AlertActionElevate elevates the priority
	AlertActionElevate AlertAction = "elevate"

	// AlertActionDrop drops the event (not recommended for security)
	AlertActionDrop AlertAction = "drop"
)

// AlertEngine evaluates security events against alert rules
type AlertEngine struct {
	mu    sync.RWMutex
	rules []AlertRule

	// Pre-compiled regex patterns
	processRegexes map[string]*regexp.Regexp

	// Statistics
	rulesEvaluated uint64
	rulesMatched   uint64
}

// NewAlertEngine creates a new alert engine with the given rules
func NewAlertEngine(rules []AlertRule) *AlertEngine {
	engine := &AlertEngine{
		rules:          rules,
		processRegexes: make(map[string]*regexp.Regexp),
	}

	// Pre-compile regex patterns
	for _, rule := range rules {
		for _, pattern := range rule.Conditions.ProcessNamesRegex {
			if _, ok := engine.processRegexes[pattern]; !ok {
				re, err := regexp.Compile(pattern)
				if err == nil {
					engine.processRegexes[pattern] = re
				}
			}
		}
	}

	return engine
}

// Evaluate checks an event against all rules and modifies it if rules match
// Returns true if the event should be kept, false if it should be dropped
func (e *AlertEngine) Evaluate(event *ebpf.SecurityEvent) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}

		e.rulesEvaluated++

		if e.ruleMatches(&rule, event) {
			e.rulesMatched++
			e.applyRule(&rule, event)

			if rule.Action == AlertActionDrop {
				return false
			}
		}
	}

	return true
}

// ruleMatches checks if a rule's conditions match an event
func (e *AlertEngine) ruleMatches(rule *AlertRule, event *ebpf.SecurityEvent) bool {
	cond := rule.Conditions

	// Check category
	if cond.Category != "" && event.Category != cond.Category {
		return false
	}

	// Check event types
	if len(cond.EventTypes) > 0 {
		eventType := e.getEventType(event)
		found := false
		for _, et := range cond.EventTypes {
			if et == eventType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check process names
	if len(cond.ProcessNames) > 0 {
		found := false
		for _, name := range cond.ProcessNames {
			if event.Process.Name == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check process name regex
	if len(cond.ProcessNamesRegex) > 0 {
		found := false
		for _, pattern := range cond.ProcessNamesRegex {
			if re, ok := e.processRegexes[pattern]; ok {
				if re.MatchString(event.Process.Name) {
					found = true
					break
				}
			}
		}
		if !found {
			return false
		}
	}

	// Check UIDs
	if len(cond.UIDs) > 0 {
		found := false
		for _, uid := range cond.UIDs {
			if event.Process.UID == uid {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check root only
	if cond.RootOnly && event.Process.UID != 0 {
		return false
	}

	// Check path patterns
	if len(cond.PathPatterns) > 0 {
		path := e.getEventPath(event)
		if path == "" {
			return false
		}
		found := false
		for _, pattern := range cond.PathPatterns {
			if strings.Contains(path, pattern) || matchGlob(pattern, path) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check container only
	if cond.ContainerOnly && event.Container.ID == "" {
		return false
	}

	// Check privilege escalation to root
	if cond.PrivilegeEscalationToRoot {
		newUID, ok := event.RawFields["new_uid"].(uint32)
		if !ok || newUID != 0 {
			newEUID, ok := event.RawFields["new_euid"].(uint32)
			if !ok || newEUID != 0 {
				return false
			}
		}
	}

	return true
}

// applyRule applies a matched rule to an event
func (e *AlertEngine) applyRule(rule *AlertRule, event *ebpf.SecurityEvent) {
	// Elevate priority if specified
	if rule.Priority > event.Priority {
		event.Priority = rule.Priority
	}

	// Add tags
	if len(rule.Tags) > 0 {
		event.Tags = append(event.Tags, rule.Tags...)
	}

	// Add rule name to tags
	event.Tags = append(event.Tags, "rule:"+rule.Name)
}

// getEventType extracts the event type from an event
func (e *AlertEngine) getEventType(event *ebpf.SecurityEvent) int {
	if eventType, ok := event.RawFields["event_type"].(uint32); ok {
		return int(eventType)
	}
	return 0
}

// getEventPath extracts the file path from an event
func (e *AlertEngine) getEventPath(event *ebpf.SecurityEvent) string {
	if filename, ok := event.RawFields["filename"].(string); ok {
		return filename
	}
	if event.Process.ExePath != "" {
		return event.Process.ExePath
	}
	return ""
}

// UpdateRules updates the alert rules
func (e *AlertEngine) UpdateRules(rules []AlertRule) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.rules = rules

	// Re-compile regex patterns
	e.processRegexes = make(map[string]*regexp.Regexp)
	for _, rule := range rules {
		for _, pattern := range rule.Conditions.ProcessNamesRegex {
			if _, ok := e.processRegexes[pattern]; !ok {
				re, err := regexp.Compile(pattern)
				if err == nil {
					e.processRegexes[pattern] = re
				}
			}
		}
	}
}

// Stats returns the alert engine statistics
func (e *AlertEngine) Stats() (evaluated, matched uint64) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.rulesEvaluated, e.rulesMatched
}

// matchGlob performs simple glob matching (supports * and ?)
func matchGlob(pattern, str string) bool {
	// Simple glob matching
	if pattern == "*" {
		return true
	}

	// Handle ** for recursive matching
	if strings.Contains(pattern, "**") {
		parts := strings.Split(pattern, "**")
		if len(parts) == 2 {
			return strings.HasPrefix(str, parts[0]) && strings.HasSuffix(str, parts[1])
		}
	}

	// Handle single * for segment matching
	if strings.Contains(pattern, "*") {
		parts := strings.Split(pattern, "*")
		idx := 0
		for _, part := range parts {
			if part == "" {
				continue
			}
			pos := strings.Index(str[idx:], part)
			if pos < 0 {
				return false
			}
			idx += pos + len(part)
		}
		return true
	}

	return pattern == str
}

// DefaultAlertRules returns a set of default security-focused alert rules
func DefaultAlertRules() []AlertRule {
	return []AlertRule{
		// Privilege escalation to root
		{
			Name:        "privilege_escalation_to_root",
			Description: "Detects processes escalating privileges to root (UID 0)",
			Enabled:     true,
			Priority:    ebpf.PriorityCritical,
			Conditions: RuleConditions{
				Category:                  "privilege",
				PrivilegeEscalationToRoot: true,
			},
			Tags:   []string{"critical", "privilege_escalation", "sox", "pci"},
			Action: AlertActionElevate,
		},
		// Kernel module operations
		{
			Name:        "kernel_module_load",
			Description: "Detects kernel module loading/unloading",
			Enabled:     true,
			Priority:    ebpf.PriorityCritical,
			Conditions: RuleConditions{
				Category: "kernel",
			},
			Tags:   []string{"critical", "kernel_module", "rootkit", "sox", "pci"},
			Action: AlertActionElevate,
		},
		// Suspicious memory protection changes (W+X)
		{
			Name:        "memory_wx_protection",
			Description: "Detects memory regions made writable and executable (potential code injection)",
			Enabled:     true,
			Priority:    ebpf.PriorityCritical,
			Conditions: RuleConditions{
				Category: "memory",
			},
			Tags:   []string{"critical", "code_injection", "memory"},
			Action: AlertActionElevate,
		},
		// Ptrace usage (debugging/injection)
		{
			Name:        "ptrace_usage",
			Description: "Detects ptrace usage which can indicate debugging or code injection",
			Enabled:     true,
			Priority:    ebpf.PriorityWarning,
			Conditions: RuleConditions{
				Category:   "process",
				EventTypes: []int{EventTypePtrace},
			},
			Tags:   []string{"warning", "ptrace", "debugging"},
			Action: AlertActionElevate,
		},
		// Root process execution
		{
			Name:        "root_process_execution",
			Description: "Tracks process execution as root",
			Enabled:     true,
			Priority:    ebpf.PriorityNotice,
			Conditions: RuleConditions{
				Category: "process",
				RootOnly: true,
			},
			Tags:   []string{"root", "audit"},
			Action: AlertActionTag,
		},
		// Sensitive file access patterns
		{
			Name:        "sensitive_file_access",
			Description: "Detects access to sensitive system files",
			Enabled:     true,
			Priority:    ebpf.PriorityWarning,
			Conditions: RuleConditions{
				Category: "file",
				PathPatterns: []string{
					"/etc/shadow",
					"/etc/passwd",
					"/etc/sudoers",
					"/root/.ssh",
					"/etc/ssh/sshd_config",
				},
			},
			Tags:   []string{"sensitive_file", "audit", "sox", "pci"},
			Action: AlertActionElevate,
		},
		// Container escape indicators
		{
			Name:        "container_mount_attempt",
			Description: "Detects mount operations from within containers",
			Enabled:     true,
			Priority:    ebpf.PriorityCritical,
			Conditions: RuleConditions{
				Category:      "filesystem",
				ContainerOnly: true,
			},
			Tags:   []string{"container_escape", "critical"},
			Action: AlertActionElevate,
		},
		// SSH key modifications
		{
			Name:        "ssh_key_modification",
			Description: "Detects modifications to SSH authorized_keys files",
			Enabled:     true,
			Priority:    ebpf.PriorityWarning,
			Conditions: RuleConditions{
				Category: "file",
				PathPatterns: []string{
					".ssh/authorized_keys",
					".ssh/id_rsa",
					".ssh/id_ed25519",
				},
			},
			Tags:   []string{"ssh", "credential", "persistence"},
			Action: AlertActionElevate,
		},
		// Cron job modifications
		{
			Name:        "cron_modification",
			Description: "Detects modifications to cron jobs",
			Enabled:     true,
			Priority:    ebpf.PriorityWarning,
			Conditions: RuleConditions{
				Category: "file",
				PathPatterns: []string{
					"/etc/cron",
					"/var/spool/cron",
					"/etc/crontab",
				},
			},
			Tags:   []string{"cron", "persistence", "sox"},
			Action: AlertActionElevate,
		},
		// Suspicious process names
		{
			Name:        "suspicious_process_names",
			Description: "Detects processes with suspicious names commonly used in attacks",
			Enabled:     true,
			Priority:    ebpf.PriorityWarning,
			Conditions: RuleConditions{
				Category: "process",
				ProcessNamesRegex: []string{
					`^\..*`,              // Hidden processes (starting with .)
					`^[\[\]]+$`,          // Kernel thread mimicry
					`.*cryptominer.*`,    // Cryptominer
					`.*xmrig.*`,          // XMRig cryptominer
					`.*kworker.*`,        // Fake kernel worker
					`.*kdevtmpfsi.*`,     // Known malware
				},
			},
			Tags:   []string{"suspicious", "malware"},
			Action: AlertActionElevate,
		},
	}
}

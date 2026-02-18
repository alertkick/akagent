package rules

import (
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// PriorityLevel represents rule priority
type PriorityLevel int

const (
	PriorityInfo PriorityLevel = iota
	PriorityWarning
	PriorityHigh
	PriorityCritical
)

// String returns the string representation of the priority
func (p PriorityLevel) String() string {
	switch p {
	case PriorityCritical:
		return "CRITICAL"
	case PriorityHigh:
		return "HIGH"
	case PriorityWarning:
		return "WARNING"
	default:
		return "INFO"
	}
}

// Rule represents a detection rule
type Rule struct {
	Name        string
	RuleID      string
	Description string
	Condition   string
	Priority    PriorityLevel
	Tags        []string
	Enabled     bool
	Framework   string
	Severity    string
}

// RuleMatch represents a matched rule
type RuleMatch struct {
	Rule      *Rule
	MatchedAt time.Time
}

// EventContext holds the fields used for rule evaluation
type EventContext struct {
	// Event type
	EventType string

	// Process info
	PID            int
	PPID           int
	UID            int
	GID            int
	Comm           string
	Exe            string
	Cmdline        string
	ParentComm     string
	ParentExe      string
	GrandparentPID int
	GrandparentComm string

	// Container info
	ContainerID string
	CgroupID    uint64
	ContainerPrivileged bool

	// Event-specific fields
	NewUID    int
	OldUID    int
	NewGID    int
	OldGID    int
	Filename  string
	Operation string
	Direction string
	DstPort   int

	// Extended event fields (for data-driven rules)
	Signal    int    // Kill signal number (e.g., 9=SIGKILL, 19=SIGSTOP)
	TargetPID int    // Target PID for signal events
	ExitCode  int    // Process exit code
	NewEUID   int    // New effective UID (credential change)
	NewEGID   int    // New effective GID (credential change)
	DataLen   int    // Data transfer size (splice/sendfile)
	Path      string // VFS/filesystem path
	SrcPort   int    // Source port for network events
	Source    string // Event source: "syscall", "kprobe"

	// Time-based fields (populated at evaluation time)
	DayOfWeek int  // 0=Sunday, 6=Saturday
	HourOfDay int  // 0-23
	IsWeekend bool // true if Saturday or Sunday

	// Rule/output info (for API-triggered evaluations)
	Rule   string
	Output string

	// Syscall info
	Syscall string
}

// RuleEngine evaluates events against loaded rules
type RuleEngine struct {
	mu     sync.RWMutex
	lists  *FilterLists
	macros *MacroRegistry
	rules  []*Rule

	// Profile metadata
	profileName    string
	profileVersion string
	lastUpdated    time.Time
	profileLoaded  bool // true once a profile has been explicitly loaded (even if empty)

	// Statistics
	totalEvaluated uint64
	totalMatched   uint64
}

// NewRuleEngine creates a new RuleEngine
func NewRuleEngine() *RuleEngine {
	return &RuleEngine{
		lists:  NewFilterLists(),
		macros: NewMacroRegistry(),
		rules:  make([]*Rule, 0),
	}
}

// UpdateProfile loads a new security profile (hot-reload safe)
func (e *RuleEngine) UpdateProfile(config *ProfileConfig) error {
	lists, macros, rules := LoadProfile(config)

	e.mu.Lock()
	defer e.mu.Unlock()

	e.lists = lists
	e.macros = macros
	e.rules = rules
	e.profileName = config.Metadata.Name
	e.profileVersion = config.Metadata.Version
	e.lastUpdated = time.Now()
	e.profileLoaded = true

	return nil
}

// Evaluate evaluates an event against all enabled rules
// Returns matched rules (empty if no matches)
func (e *RuleEngine) Evaluate(ctx *EventContext) []*RuleMatch {
	atomic.AddUint64(&e.totalEvaluated, 1)

	e.mu.RLock()
	defer e.mu.RUnlock()

	matches := make([]*RuleMatch, 0)

	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}

		if e.evaluateCondition(rule.Condition, ctx) {
			matches = append(matches, &RuleMatch{
				Rule:      rule,
				MatchedAt: time.Now(),
			})
		}
	}

	if len(matches) > 0 {
		atomic.AddUint64(&e.totalMatched, 1)
	}

	return matches
}

// evaluateCondition evaluates a condition expression against the event context
// This is a simple interpreter - for production, consider compiling conditions
func (e *RuleEngine) evaluateCondition(condition string, ctx *EventContext) bool {
	// First expand any macros in the condition
	expanded := e.macros.ExpandExpression(condition, 0)

	// Evaluate the expanded condition
	return e.evalExpr(expanded, ctx)
}

// evalExpr evaluates a boolean expression
func (e *RuleEngine) evalExpr(expr string, ctx *EventContext) bool {
	expr = strings.TrimSpace(expr)

	// Handle parentheses
	if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
		// Find matching closing paren
		depth := 0
		for i, c := range expr {
			if c == '(' {
				depth++
			} else if c == ')' {
				depth--
				if depth == 0 && i == len(expr)-1 {
					// The whole expression is wrapped in parens
					return e.evalExpr(expr[1:len(expr)-1], ctx)
				}
			}
		}
	}

	// Handle OR (lowest precedence, evaluate left to right)
	if idx := findOperator(expr, " OR "); idx >= 0 {
		left := expr[:idx]
		right := expr[idx+4:]
		return e.evalExpr(left, ctx) || e.evalExpr(right, ctx)
	}

	// Handle AND (higher precedence than OR)
	if idx := findOperator(expr, " AND "); idx >= 0 {
		left := expr[:idx]
		right := expr[idx+5:]
		return e.evalExpr(left, ctx) && e.evalExpr(right, ctx)
	}

	// Handle NOT (highest precedence)
	if strings.HasPrefix(expr, "NOT ") {
		return !e.evalExpr(expr[4:], ctx)
	}

	// Evaluate atomic conditions
	return e.evalAtomicCondition(expr, ctx)
}

// findOperator finds an operator at the top level (not inside parentheses)
func findOperator(expr, op string) int {
	depth := 0
	for i := 0; i <= len(expr)-len(op); i++ {
		if expr[i] == '(' {
			depth++
		} else if expr[i] == ')' {
			depth--
		} else if depth == 0 && strings.HasPrefix(expr[i:], op) {
			return i
		}
	}
	return -1
}

// evalAtomicCondition evaluates a single comparison or function call
func (e *RuleEngine) evalAtomicCondition(expr string, ctx *EventContext) bool {
	expr = strings.TrimSpace(expr)

	// Handle "field in (list)" pattern
	if strings.Contains(expr, " in (") {
		parts := strings.SplitN(expr, " in ", 2)
		if len(parts) == 2 {
			field := strings.TrimSpace(parts[0])
			listName := strings.TrimSpace(parts[1])
			listName = strings.TrimPrefix(listName, "(")
			listName = strings.TrimSuffix(listName, ")")
			listName = strings.TrimSpace(listName)

			fieldValue := e.getFieldValue(field, ctx)
			if s, ok := fieldValue.(string); ok {
				return e.lists.ContainsString(listName, s)
			}
			if i, ok := fieldValue.(int); ok {
				return e.lists.ContainsInt(listName, i)
			}
		}
	}

	// Handle "field matches (pattern_list)" pattern
	if strings.Contains(expr, " matches (") {
		parts := strings.SplitN(expr, " matches ", 2)
		if len(parts) == 2 {
			field := strings.TrimSpace(parts[0])
			listName := strings.TrimSpace(parts[1])
			listName = strings.TrimPrefix(listName, "(")
			listName = strings.TrimSuffix(listName, ")")
			listName = strings.TrimSpace(listName)

			fieldValue := e.getFieldValue(field, ctx)
			if s, ok := fieldValue.(string); ok {
				return e.lists.MatchesPattern(listName, s)
			}
		}
	}

	// Handle "field prefix_in (list)" pattern - checks if any list item is a prefix of the field value
	// Used for Linux 15-char comm name truncation matching (e.g., "containerd-shim" prefix matches "containerd-shim-runc-v2")
	if strings.Contains(expr, " prefix_in (") {
		parts := strings.SplitN(expr, " prefix_in ", 2)
		if len(parts) == 2 {
			field := strings.TrimSpace(parts[0])
			listName := strings.TrimSpace(parts[1])
			listName = strings.TrimPrefix(listName, "(")
			listName = strings.TrimSuffix(listName, ")")
			listName = strings.TrimSpace(listName)

			fieldValue := e.getFieldValue(field, ctx)
			if s, ok := fieldValue.(string); ok {
				return e.lists.PrefixMatchString(listName, s)
			}
		}
	}

	// Handle "field contains value" pattern
	if strings.Contains(expr, " contains ") {
		parts := strings.SplitN(expr, " contains ", 2)
		if len(parts) == 2 {
			field := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			value = strings.Trim(value, "\"'")

			fieldValue := e.getFieldValue(field, ctx)
			if s, ok := fieldValue.(string); ok {
				return strings.Contains(s, value)
			}
		}
	}

	// Handle "field startswith value" pattern
	if strings.Contains(expr, " startswith ") {
		parts := strings.SplitN(expr, " startswith ", 2)
		if len(parts) == 2 {
			field := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			value = strings.Trim(value, "\"'")

			fieldValue := e.getFieldValue(field, ctx)
			if s, ok := fieldValue.(string); ok {
				return strings.HasPrefix(s, value)
			}
		}
	}

	// Handle "field endswith value" pattern
	if strings.Contains(expr, " endswith ") {
		parts := strings.SplitN(expr, " endswith ", 2)
		if len(parts) == 2 {
			field := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			value = strings.Trim(value, "\"'")

			fieldValue := e.getFieldValue(field, ctx)
			if s, ok := fieldValue.(string); ok {
				return strings.HasSuffix(s, value)
			}
		}
	}

	// Handle comparison operators
	for _, op := range []string{" == ", " != ", " >= ", " <= ", " > ", " < "} {
		if idx := strings.Index(expr, op); idx >= 0 {
			field := strings.TrimSpace(expr[:idx])
			value := strings.TrimSpace(expr[idx+len(op):])

			return e.compareValues(field, op, value, ctx)
		}
	}

	// If nothing matched, return false
	return false
}

// getFieldValue returns the value of a field from the event context
func (e *RuleEngine) getFieldValue(field string, ctx *EventContext) interface{} {
	switch field {
	case "event_type":
		return ctx.EventType
	case "pid":
		return ctx.PID
	case "ppid":
		return ctx.PPID
	case "uid":
		return ctx.UID
	case "gid":
		return ctx.GID
	case "comm":
		return ctx.Comm
	case "exe":
		return ctx.Exe
	case "cmdline":
		return ctx.Cmdline
	case "parent_comm":
		return ctx.ParentComm
	case "parent_exe":
		return ctx.ParentExe
	case "grandparent_pid":
		return ctx.GrandparentPID
	case "grandparent_comm":
		return ctx.GrandparentComm
	case "container_id":
		return ctx.ContainerID
	case "cgroup_id":
		return int(ctx.CgroupID)
	case "container_privileged":
		return ctx.ContainerPrivileged
	case "new_uid":
		return ctx.NewUID
	case "old_uid":
		return ctx.OldUID
	case "new_gid":
		return ctx.NewGID
	case "old_gid":
		return ctx.OldGID
	case "filename":
		return ctx.Filename
	case "operation":
		return ctx.Operation
	case "direction":
		return ctx.Direction
	case "dst_port":
		return ctx.DstPort
	case "signal":
		return ctx.Signal
	case "target_pid":
		return ctx.TargetPID
	case "exit_code":
		return ctx.ExitCode
	case "new_euid":
		return ctx.NewEUID
	case "new_egid":
		return ctx.NewEGID
	case "data_len":
		return ctx.DataLen
	case "path":
		return ctx.Path
	case "src_port":
		return ctx.SrcPort
	case "source":
		return ctx.Source
	case "day_of_week":
		return ctx.DayOfWeek
	case "hour_of_day":
		return ctx.HourOfDay
	case "is_weekend":
		return ctx.IsWeekend
	case "rule":
		return ctx.Rule
	case "output":
		return ctx.Output
	case "syscall":
		return ctx.Syscall
	default:
		return ""
	}
}

// compareValues compares a field value with a target value
func (e *RuleEngine) compareValues(field, op, value string, ctx *EventContext) bool {
	fieldValue := e.getFieldValue(field, ctx)
	op = strings.TrimSpace(op)

	// Try numeric comparison first
	if intField, ok := fieldValue.(int); ok {
		intValue := 0
		if strings.HasPrefix(value, "\"") || strings.HasPrefix(value, "'") {
			// String comparison
			strField := strconv.Itoa(intField)
			value = strings.Trim(value, "\"'")
			switch op {
			case "==":
				return strField == value
			case "!=":
				return strField != value
			}
		}
		// Parse as integer
		intValue = parseIntValue(value)
		switch op {
		case "==":
			return intField == intValue
		case "!=":
			return intField != intValue
		case ">":
			return intField > intValue
		case ">=":
			return intField >= intValue
		case "<":
			return intField < intValue
		case "<=":
			return intField <= intValue
		}
	}

	// Boolean comparison
	if boolField, ok := fieldValue.(bool); ok {
		boolValue := value == "true"
		switch op {
		case "==":
			return boolField == boolValue
		case "!=":
			return boolField != boolValue
		}
	}

	// String comparison
	if strField, ok := fieldValue.(string); ok {
		value = strings.Trim(value, "\"'")
		switch op {
		case "==":
			return strField == value
		case "!=":
			return strField != value
		case ">":
			return strField > value
		case ">=":
			return strField >= value
		case "<":
			return strField < value
		case "<=":
			return strField <= value
		}
	}

	return false
}

// parseIntValue parses an integer from a string
func parseIntValue(s string) int {
	s = strings.TrimSpace(s)
	val := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			val = val*10 + int(c-'0')
		} else {
			break
		}
	}
	return val
}

// GetStats returns engine statistics
func (e *RuleEngine) GetStats() (evaluated, matched uint64) {
	return atomic.LoadUint64(&e.totalEvaluated), atomic.LoadUint64(&e.totalMatched)
}

// GetProfileInfo returns information about the loaded profile
func (e *RuleEngine) GetProfileInfo() (name, version string, lastUpdated time.Time) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.profileName, e.profileVersion, e.lastUpdated
}

// GetRuleCount returns the number of loaded rules
func (e *RuleEngine) GetRuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// IsReady returns true if the engine has loaded rules
func (e *RuleEngine) IsReady() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules) > 0
}

// HasProfile returns true if a profile has been explicitly loaded (even if it contains zero rules).
// This distinguishes between "no profile assigned yet" and "empty profile pushed by API".
func (e *RuleEngine) HasProfile() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.profileLoaded
}

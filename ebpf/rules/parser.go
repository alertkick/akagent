package rules

import (
	"strconv"

	"gopkg.in/yaml.v3"
)

// ProfileConfig represents the structure of a security profile YAML
type ProfileConfig struct {
	Metadata ProfileMetadata       `yaml:"metadata"`
	Lists    map[string][]string   `yaml:"lists"`
	Macros   map[string]string     `yaml:"macros"`
	Rules    []RuleConfig          `yaml:"rules"`
}

// ProfileMetadata contains profile metadata
type ProfileMetadata struct {
	Name        string   `yaml:"name"`
	Version     string   `yaml:"version"`
	GeneratedAt string   `yaml:"generated_at"`
	HostUUID    string   `yaml:"host_uuid"`
	Profiles    []string `yaml:"profiles"`
}

// RuleConfig represents a rule configuration from YAML
type RuleConfig struct {
	Name        string   `yaml:"name"`
	RuleID      string   `yaml:"rule_id"`
	Description string   `yaml:"description"`
	Condition   string   `yaml:"condition"`
	Priority    string   `yaml:"priority"`
	Tags        []string `yaml:"tags"`
	Enabled     bool     `yaml:"enabled"`
	Framework   string   `yaml:"framework"`
	Severity    string   `yaml:"severity"`
}

// ParseProfileYAML parses a security profile from YAML bytes
func ParseProfileYAML(data []byte) (*ProfileConfig, error) {
	var config ProfileConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

// ParseProfileJSON parses a security profile from JSON bytes
// (YAML parser handles JSON as well since JSON is valid YAML)
func ParseProfileJSON(data []byte) (*ProfileConfig, error) {
	return ParseProfileYAML(data)
}

// LoadProfile loads a profile configuration into the rule engine
func LoadProfile(config *ProfileConfig) (*FilterLists, *MacroRegistry, []*Rule) {
	lists := NewFilterLists()
	macros := NewMacroRegistry()
	rules := make([]*Rule, 0, len(config.Rules))

	// Load lists
	for name, items := range config.Lists {
		// Determine list type based on content
		if isIntList(items) {
			intItems := make([]int, 0, len(items))
			for _, item := range items {
				if v, err := strconv.Atoi(item); err == nil {
					intItems = append(intItems, v)
				}
			}
			lists.AddIntList(name, intItems)
		} else if containsPatterns(items) {
			lists.AddPatternList(name, items)
		} else {
			lists.AddStringList(name, items)
		}
	}

	// Load macros
	for name, expression := range config.Macros {
		macro := &Macro{
			Name:       name,
			Expression: expression,
		}
		macros.AddMacro(macro)
	}

	// Load rules
	for _, ruleConfig := range config.Rules {
		if !ruleConfig.Enabled {
			continue
		}

		rule := &Rule{
			Name:        ruleConfig.Name,
			RuleID:      ruleConfig.RuleID,
			Description: ruleConfig.Description,
			Condition:   ruleConfig.Condition,
			Priority:    parsePriority(ruleConfig.Priority),
			Tags:        ruleConfig.Tags,
			Enabled:     ruleConfig.Enabled,
			Framework:   ruleConfig.Framework,
			Severity:    ruleConfig.Severity,
		}
		rules = append(rules, rule)
	}

	return lists, macros, rules
}

// isIntList checks if all items in the list can be parsed as integers
func isIntList(items []string) bool {
	if len(items) == 0 {
		return false
	}
	for _, item := range items {
		if _, err := strconv.Atoi(item); err != nil {
			return false
		}
	}
	return true
}

// containsPatterns checks if any items contain glob patterns
func containsPatterns(items []string) bool {
	for _, item := range items {
		if containsGlobChars(item) {
			return true
		}
	}
	return false
}

// containsGlobChars checks if a string contains glob pattern characters
func containsGlobChars(s string) bool {
	for _, c := range s {
		if c == '*' || c == '?' || c == '[' {
			return true
		}
	}
	return false
}

// parsePriority converts a priority string to PriorityLevel
func parsePriority(s string) PriorityLevel {
	switch s {
	case "CRITICAL":
		return PriorityCritical
	case "HIGH":
		return PriorityHigh
	case "WARNING":
		return PriorityWarning
	case "INFO":
		return PriorityInfo
	default:
		return PriorityInfo
	}
}

package rules

import (
	"strings"
	"sync"
)

// MacroRegistry holds compiled macros for expression expansion
type MacroRegistry struct {
	mu     sync.RWMutex
	macros map[string]*Macro
}

// Macro represents a reusable condition snippet
type Macro struct {
	Name        string
	Expression  string
	UsesLists   []string
	UsesMacros  []string
	Description string
}

// NewMacroRegistry creates a new MacroRegistry
func NewMacroRegistry() *MacroRegistry {
	return &MacroRegistry{
		macros: make(map[string]*Macro),
	}
}

// AddMacro adds a macro to the registry
func (r *MacroRegistry) AddMacro(macro *Macro) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.macros[macro.Name] = macro
}

// GetMacro retrieves a macro by name
func (r *MacroRegistry) GetMacro(name string) (*Macro, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	macro, ok := r.macros[name]
	return macro, ok
}

// GetExpression retrieves the expression for a macro name
func (r *MacroRegistry) GetExpression(name string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if macro, ok := r.macros[name]; ok {
		return macro.Expression
	}
	return ""
}

// Clear removes all macros
func (r *MacroRegistry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.macros = make(map[string]*Macro)
}

// ListMacros returns all macro names
func (r *MacroRegistry) ListMacros() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.macros))
	for name := range r.macros {
		names = append(names, name)
	}
	return names
}

// ExpandExpression expands macros in a condition expression
// This performs recursive expansion until no more macros are found
func (r *MacroRegistry) ExpandExpression(expression string, depth int) string {
	if depth > 10 {
		// Prevent infinite recursion
		return expression
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	expanded := expression
	changed := true

	// Keep expanding until no more changes
	for changed && depth < 10 {
		changed = false
		for name, macro := range r.macros {
			// Look for macro name as a word boundary
			// Simple approach: replace the macro name with its expression in parentheses
			if containsWord(expanded, name) {
				// Replace macro name with its expression wrapped in parentheses
				expanded = replaceWord(expanded, name, "("+macro.Expression+")")
				changed = true
			}
		}
		depth++
	}

	return expanded
}

// containsWord checks if a string contains a word (not part of another word)
func containsWord(s, word string) bool {
	// Simple implementation - check for the word surrounded by non-alphanumeric chars
	idx := strings.Index(s, word)
	for idx >= 0 {
		// Check character before
		beforeOk := idx == 0 || !isWordChar(s[idx-1])
		// Check character after
		afterIdx := idx + len(word)
		afterOk := afterIdx >= len(s) || !isWordChar(s[afterIdx])

		if beforeOk && afterOk {
			return true
		}

		// Search for next occurrence
		if idx+1 < len(s) {
			nextIdx := strings.Index(s[idx+1:], word)
			if nextIdx >= 0 {
				idx = idx + 1 + nextIdx
			} else {
				idx = -1
			}
		} else {
			idx = -1
		}
	}
	return false
}

// replaceWord replaces a word with another string (respecting word boundaries)
func replaceWord(s, word, replacement string) string {
	var result strings.Builder
	i := 0

	for i < len(s) {
		idx := strings.Index(s[i:], word)
		if idx < 0 {
			result.WriteString(s[i:])
			break
		}

		absIdx := i + idx

		// Check if this is a word boundary match
		beforeOk := absIdx == 0 || !isWordChar(s[absIdx-1])
		afterIdx := absIdx + len(word)
		afterOk := afterIdx >= len(s) || !isWordChar(s[afterIdx])

		if beforeOk && afterOk {
			result.WriteString(s[i:absIdx])
			result.WriteString(replacement)
			i = afterIdx
		} else {
			result.WriteString(s[i : absIdx+1])
			i = absIdx + 1
		}
	}

	return result.String()
}

// isWordChar returns true if the byte is part of a word (alphanumeric or underscore)
func isWordChar(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') ||
		b == '_'
}

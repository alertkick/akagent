package rules

import (
	"path/filepath"
	"strings"
	"sync"
)

// FilterLists holds all loaded lists as hash maps for O(1) lookup
type FilterLists struct {
	mu sync.RWMutex

	// String lists (exact match) - map[listName]map[value]bool
	StringLists map[string]map[string]bool

	// Integer lists (for UIDs, GIDs, ports)
	IntLists map[string]map[int]bool

	// Pattern lists (for glob matching) - using simple pattern matching
	PatternLists map[string][]string
}

// NewFilterLists creates a new FilterLists instance
func NewFilterLists() *FilterLists {
	return &FilterLists{
		StringLists:  make(map[string]map[string]bool),
		IntLists:     make(map[string]map[int]bool),
		PatternLists: make(map[string][]string),
	}
}

// AddStringList adds a string list
func (f *FilterLists) AddStringList(name string, items []string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	list := make(map[string]bool, len(items))
	for _, item := range items {
		list[item] = true
	}
	f.StringLists[name] = list
}

// AddIntList adds an integer list
func (f *FilterLists) AddIntList(name string, items []int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	list := make(map[int]bool, len(items))
	for _, item := range items {
		list[item] = true
	}
	f.IntLists[name] = list
}

// AddPatternList adds a pattern list for glob matching
func (f *FilterLists) AddPatternList(name string, patterns []string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.PatternLists[name] = patterns
}

// ContainsString checks if a string value is in the named list
// Returns false if the list doesn't exist
func (f *FilterLists) ContainsString(listName, value string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if list, ok := f.StringLists[listName]; ok {
		return list[value]
	}
	return false
}

// ContainsInt checks if an integer value is in the named list
func (f *FilterLists) ContainsInt(listName string, value int) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if list, ok := f.IntLists[listName]; ok {
		return list[value]
	}
	return false
}

// MatchesPattern checks if a value matches any pattern in the named list
func (f *FilterLists) MatchesPattern(listName, value string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	patterns, ok := f.PatternLists[listName]
	if !ok {
		return false
	}

	for _, pattern := range patterns {
		if matchGlob(pattern, value) {
			return true
		}
	}
	return false
}

// GetStringList returns a copy of the named string list
func (f *FilterLists) GetStringList(name string) []string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if list, ok := f.StringLists[name]; ok {
		items := make([]string, 0, len(list))
		for item := range list {
			items = append(items, item)
		}
		return items
	}
	return nil
}

// Clear removes all lists
func (f *FilterLists) Clear() {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.StringLists = make(map[string]map[string]bool)
	f.IntLists = make(map[string]map[int]bool)
	f.PatternLists = make(map[string][]string)
}

// matchGlob implements simple glob pattern matching
// Supports * and ** patterns
func matchGlob(pattern, value string) bool {
	// Handle exact match
	if pattern == value {
		return true
	}

	// Use filepath.Match for simple glob patterns
	if matched, _ := filepath.Match(pattern, value); matched {
		return true
	}

	// Handle ** for recursive matching
	if strings.Contains(pattern, "**") {
		// Convert ** to regex-like matching
		parts := strings.Split(pattern, "**")
		if len(parts) == 2 {
			prefix := parts[0]
			suffix := parts[1]

			if prefix != "" && !strings.HasPrefix(value, prefix) {
				return false
			}
			if suffix != "" && !strings.HasSuffix(value, suffix) {
				return false
			}
			return true
		}
	}

	// Handle simple * wildcard at end
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(value, prefix)
	}

	// Handle simple * wildcard at start
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(value, suffix)
	}

	return false
}

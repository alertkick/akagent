package falco_manager

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	falcoMainConfigFile       = "/etc/falco/falco.yaml"
	falcoConfigDir            = "/etc/falco/config.d/"
	falcoRulesDir             = "/etc/falco/rules.d/"
	falcoRulesAlertpriorityDir = "/etc/falco/rules.alertpriority/"
)

// ListFalcoRulesFiles returns a slice of filenames for all Falco rule files in /etc/falco
func ListFalcoRulesFiles() ([]string, error) {
	CheckAndCreateFalcoRulesAlertpriorityDir()
	entries, err := os.ReadDir(falcoRulesAlertpriorityDir)
	if err != nil {
		return nil, err
	}

	var ruleFiles []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yaml") {
			ruleFiles = append(ruleFiles, entry.Name())
		}
	}
	return ruleFiles, nil
}

// ReadFalcoRuleFile reads the content of a specific Falco rule file
func ReadFalcoRuleFile(filename string) (string, error) {
	CheckAndCreateFalcoRulesAlertpriorityDir()
	content, err := os.ReadFile(filepath.Join(falcoRulesAlertpriorityDir, filename))
	if err != nil {
		return "", err
	}
	return string(content), nil
}

// WriteFalcoRuleFile writes content to a Falco rule file
func WriteFalcoRuleFile(filename string, content string) error {
	CheckAndCreateFalcoRulesAlertpriorityDir()
	return os.WriteFile(filepath.Join(falcoRulesAlertpriorityDir, filename), []byte(content), 0644)
}

// DeleteFalcoRuleFile deletes a specific Falco rule file
func DeleteFalcoRuleFile(filename string) error {
	CheckAndCreateFalcoRulesAlertpriorityDir()
	return os.Remove(filepath.Join(falcoRulesAlertpriorityDir, filename))
}

// CheckAndCreateFalcoRulesAlertpriorityDir checks if the rules.alertpriority directory exists and creates it if it doesn't
func CheckAndCreateFalcoRulesAlertpriorityDir() {
	if _, err := os.Stat(falcoRulesAlertpriorityDir); os.IsNotExist(err) {
		os.MkdirAll(falcoRulesAlertpriorityDir, 0755)
	}
}

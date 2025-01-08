package falco_manager

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	falcoMainConfigFile    = "/etc/falco/falco.yaml"
	falcoConfigDir         = "/etc/falco/config.d/"
	falcoRulesDir          = "/etc/falco/rules.d/"
	falcoRulesAlertkickDir = "/etc/falco/rules.alertkick/"
)

// ListFalcoRulesFiles returns a slice of filenames for all Falco rule files in /etc/falco
func ListFalcoRulesFiles() ([]string, error) {
	CheckAndCreateFalcoRulesAlertkickDir()
	entries, err := os.ReadDir(falcoRulesAlertkickDir)
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
	CheckAndCreateFalcoRulesAlertkickDir()
	content, err := os.ReadFile(filepath.Join(falcoRulesAlertkickDir, filename))
	if err != nil {
		return "", err
	}
	return string(content), nil
}

// WriteFalcoRuleFile writes content to a Falco rule file
func WriteFalcoRuleFile(filename string, content string) error {
	CheckAndCreateFalcoRulesAlertkickDir()
	return os.WriteFile(filepath.Join(falcoRulesAlertkickDir, filename), []byte(content), 0644)
}

// DeleteFalcoRuleFile deletes a specific Falco rule file
func DeleteFalcoRuleFile(filename string) error {
	CheckAndCreateFalcoRulesAlertkickDir()
	return os.Remove(filepath.Join(falcoRulesAlertkickDir, filename))
}

// CheckAndCreateFalcoRulesAlertkickDir checks if the rules.alertkick directory exists and creates it if it doesn't
func CheckAndCreateFalcoRulesAlertkickDir() {
	if _, err := os.Stat(falcoRulesAlertkickDir); os.IsNotExist(err) {
		os.MkdirAll(falcoRulesAlertkickDir, 0755)
	}
}

//go:build !windows

package yarascan

// DefaultRulesPath is where the rules-sync component writes the bundle and the
// scanner reads it when YARA_RULES_PATH isn't set explicitly.
const DefaultRulesPath = "/var/lib/alertkick-agent/yara/rules.yar"

// BundledBinaryPath is where the agent package installs the static yara binary
// it ships per arch. Preferred over a system yara so the rule-compilation
// version matches across hosts.
const BundledBinaryPath = "/usr/lib/alertkick-agent/bin/yara"

// defaultBinaryName is the yara binary looked up on PATH as a last resort.
const defaultBinaryName = "yara"

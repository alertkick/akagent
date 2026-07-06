//go:build windows

package yarascan

// DefaultRulesPath is where rules-sync writes the bundle under ProgramData.
const DefaultRulesPath = `C:\ProgramData\AlertKick\yara\rules.yar`

// BundledBinaryPath is where the agent zip's yara64.exe lands: alongside the
// agent binary under Program Files. Preferred over a PATH lookup so the
// rule-compilation version is consistent across hosts.
const BundledBinaryPath = `C:\Program Files\AlertKick\yara64.exe`

// defaultBinaryName is the yara executable looked up on PATH as a last resort.
const defaultBinaryName = "yara64.exe"

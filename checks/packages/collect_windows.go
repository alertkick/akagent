//go:build windows

package packages

import (
	"sort"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// isCriticalPackage determines if a package is considered critical
func isCriticalPackage(name string) bool {
	criticalPrefixes := []string{
		"Microsoft Visual C++", // runtime many services depend on
		"Microsoft .NET",
		"AlertKick",
	}
	for _, p := range criticalPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// isSecurityPackage determines if a package is security-related
func isSecurityPackage(name string) bool {
	securityPackages := []string{
		"defender", "antivirus", "anti-virus", "firewall", "endpoint",
		"crowdstrike", "sentinelone", "sophos", "mcafee", "norton",
		"kaspersky", "bitdefender", "eset", "carbon black", "cylance",
		"openssh", "openssl", "openvpn", "wireguard", "bitlocker",
	}
	lower := strings.ToLower(name)
	for _, security := range securityPackages {
		if strings.Contains(lower, security) {
			return true
		}
	}
	return false
}

// uninstallRoots are the registry locations that list installed software:
// native 64-bit apps and 32-bit apps under WOW6432Node.
var uninstallRoots = []string{
	`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
	`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
}

// GetInstalledPackages reads installed software from the registry Uninstall
// keys (the same source Add/Remove Programs uses). Entries without a
// DisplayName, and system components, are skipped — matching what a user
// would consider "installed software".
func GetInstalledPackages() ([]PackageInfo, error) {
	seen := make(map[string]bool)
	var packages []PackageInfo

	for _, root := range uninstallRoots {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, root, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue // WOW6432Node doesn't exist on 32-bit-free systems
		}

		subkeys, err := key.ReadSubKeyNames(-1)
		if err != nil {
			key.Close()
			continue
		}

		for _, sub := range subkeys {
			entry, err := registry.OpenKey(registry.LOCAL_MACHINE, root+`\`+sub, registry.QUERY_VALUE)
			if err != nil {
				continue
			}

			name, _, err := entry.GetStringValue("DisplayName")
			if err != nil || name == "" {
				entry.Close()
				continue
			}
			if sysComp, _, err := entry.GetIntegerValue("SystemComponent"); err == nil && sysComp == 1 {
				entry.Close()
				continue
			}
			version, _, _ := entry.GetStringValue("DisplayVersion")
			entry.Close()

			if seen[name] {
				continue
			}
			seen[name] = true
			packages = append(packages, PackageInfo{
				Name:    name,
				Version: version,
			})
		}
		key.Close()
	}

	sort.Slice(packages, func(i, j int) bool { return packages[i].Name < packages[j].Name })
	return packages, nil
}

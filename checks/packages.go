//go:build linux

package checks

import (
	"os/exec"
	"strings"
)

// GetInstalledPackages retrieves a list of installed packages with their versions
// Only includes packages that are actually installed (status "install ok installed")
// Excludes packages with status like "deinstall ok config-files" (rc status)
func GetInstalledPackages() ([]PackageInfo, error) {
	// Run the dpkg-query command to list all packages with their status
	// Format: package_name version status
	// Status field contains something like "install ok installed" for actually installed packages
	// or "deinstall ok config-files" for packages in 'rc' state (removed but config remains)
	cmd := exec.Command("dpkg-query", "-W", "-f=${Package} ${Version} ${Status}\n")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Split the output into lines
	lines := strings.Split(string(output), "\n")

	// Parse each line to extract package name and version
	var packages []PackageInfo
	for _, line := range lines {
		if line == "" {
			continue
		}
		// Format: "package_name version status_string"
		// Status string is like "install ok installed" or "deinstall ok config-files"
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 3 {
			continue
		}
		name := parts[0]
		version := parts[1]
		status := parts[2]

		// Only include packages that are actually installed
		// The status field ends with "installed" for fully installed packages
		if strings.HasSuffix(status, "installed") {
			packages = append(packages, PackageInfo{
				Name:    name,
				Version: version,
			})
		}
	}

	return packages, nil
}

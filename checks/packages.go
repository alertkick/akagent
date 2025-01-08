package checks

import (
	"os/exec"
	"strings"
)

// GetInstalledPackages retrieves a list of installed packages with their versions
func GetInstalledPackages() ([]PackageInfo, error) {
	// Run the dpkg-query command to list all installed packages
	cmd := exec.Command("dpkg-query", "-W", "-f=${Package} ${Version}\n")
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
		parts := strings.Split(line, " ")
		if len(parts) == 2 {
			packages = append(packages, PackageInfo{
				Name:    parts[0],
				Version: parts[1],
			})
		}
	}

	return packages, nil
}

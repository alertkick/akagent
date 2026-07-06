//go:build linux

package packages

import (
	"fmt"
	"os/exec"
	"strings"
)

// isCriticalPackage determines if a package is considered critical
func isCriticalPackage(name string) bool {
	criticalPackages := map[string]bool{
		"linux-image":    true,
		"linux-headers":  true,
		"systemd":        true,
		"libc6":          true,
		"libssl":         true,
		"openssl":        true,
		"openssh-server": true,
		"openssh-client": true,
		"grub":           true,
		"kernel":         true,
	}

	for critical := range criticalPackages {
		if strings.HasPrefix(name, critical) {
			return true
		}
	}
	return false
}

// isSecurityPackage determines if a package is security-related
func isSecurityPackage(name string) bool {
	securityPackages := []string{
		"openssh", "openssl", "libssl", "gnupg", "gpg",
		"fail2ban", "ufw", "iptables", "firewalld",
		"apparmor", "selinux", "audit", "aide",
		"clamav", "rkhunter", "chkrootkit",
		"libpam", "sudo", "polkit",
	}

	for _, security := range securityPackages {
		if strings.Contains(name, security) {
			return true
		}
	}
	return false
}

// GetInstalledPackages retrieves a list of installed packages with their versions
func GetInstalledPackages() ([]PackageInfo, error) {
	// Try dpkg-query first (Debian/Ubuntu)
	packages, err := getDebianPackages()
	if err == nil && len(packages) > 0 {
		return packages, nil
	}

	// Try rpm (RHEL/CentOS/Fedora)
	packages, err = getRPMPackages()
	if err == nil && len(packages) > 0 {
		return packages, nil
	}

	// Try apk (Alpine)
	packages, err = getAlpinePackages()
	if err == nil && len(packages) > 0 {
		return packages, nil
	}

	return nil, fmt.Errorf("unable to detect package manager or no packages found")
}

// getDebianPackages uses dpkg-query to get installed packages
func getDebianPackages() ([]PackageInfo, error) {
	cmd := exec.Command("dpkg-query", "-W", "-f=${Package} ${Version} ${Status}\n")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	var packages []PackageInfo

	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 3 {
			continue
		}
		name := parts[0]
		version := parts[1]
		status := parts[2]

		// Only include packages that are actually installed
		if strings.HasSuffix(status, "installed") {
			packages = append(packages, PackageInfo{
				Name:    name,
				Version: version,
			})
		}
	}

	return packages, nil
}

// getRPMPackages uses rpm to get installed packages
func getRPMPackages() ([]PackageInfo, error) {
	cmd := exec.Command("rpm", "-qa", "--queryformat", "%{NAME} %{VERSION}-%{RELEASE}\n")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	var packages []PackageInfo

	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 2 {
			continue
		}
		packages = append(packages, PackageInfo{
			Name:    parts[0],
			Version: parts[1],
		})
	}

	return packages, nil
}

// getAlpinePackages uses apk to get installed packages
func getAlpinePackages() ([]PackageInfo, error) {
	cmd := exec.Command("apk", "info", "-v")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	var packages []PackageInfo

	for _, line := range lines {
		if line == "" {
			continue
		}
		// Alpine format: package-name-version
		// Find the last dash that separates name from version
		lastDash := strings.LastIndex(line, "-")
		if lastDash == -1 {
			continue
		}
		// Find second to last dash to get full name
		secondLastDash := strings.LastIndex(line[:lastDash], "-")
		if secondLastDash == -1 {
			packages = append(packages, PackageInfo{
				Name:    line[:lastDash],
				Version: line[lastDash+1:],
			})
		} else {
			packages = append(packages, PackageInfo{
				Name:    line[:lastDash],
				Version: line[lastDash+1:],
			})
		}
	}

	return packages, nil
}

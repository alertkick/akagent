package native

import "apagent/ebpf"

// ComplianceProfile represents a pre-defined compliance configuration
type ComplianceProfile struct {
	Name        string   `json:"name" yaml:"name"`
	DisplayName string   `json:"display_name" yaml:"display_name"`
	Description string   `json:"description" yaml:"description"`
	Framework   string   `json:"framework" yaml:"framework"` // sox, pci-dss-4.0, hipaa, etc.
	Version     string   `json:"version" yaml:"version"`
	Config      Config   `json:"config" yaml:"config"`
	Tags        []string `json:"tags" yaml:"tags"`
}

// GetComplianceProfiles returns all available compliance profiles
func GetComplianceProfiles() map[string]ComplianceProfile {
	return map[string]ComplianceProfile{
		"sox":         GetSOXProfile(),
		"pci-dss-4.0": GetPCIDSSProfile(),
		"custom":      GetCustomProfile(),
	}
}

// GetSOXProfile returns the SOX compliance profile
// SOX focuses on: access controls, privilege changes, audit trail integrity
func GetSOXProfile() ComplianceProfile {
	return ComplianceProfile{
		Name:        "sox",
		DisplayName: "SOX Compliance",
		Description: "Sarbanes-Oxley Act compliance monitoring for financial controls and audit trail",
		Framework:   "sox",
		Version:     "2002",
		Tags:        []string{"finance", "audit", "access-control"},
		Config: Config{
			Enabled:          true,
			EnableProcess:    true,  // Track process execution for audit
			EnableFile:       true,  // Track file access to financial data
			EnableNetwork:    false, // Less critical for SOX
			EnablePrivilege:  true,  // Critical: track privilege escalation
			EnableFilesystem: true,  // Track mount operations
			EnableKernel:     true,  // Track kernel module loading
			EnableMemory:     false, // Less critical for SOX
			EnableEnrichment: true,
			EnableAlerts:     true,

			// Exclude noisy paths
			ExcludePaths: []string{
				"/proc/",
				"/sys/",
				"/dev/",
				"/run/",
			},

			// SOX-specific alert rules
			AlertRules: []AlertRule{
				// Privilege escalation detection
				{
					Name:        "sox-privilege-escalation",
					Description: "Detect privilege escalation to root (SOX access control)",
					Enabled:     true,
					Conditions: RuleConditions{
						Category:                  "privilege",
						PrivilegeEscalationToRoot: true,
					},
					Priority: ebpf.PriorityCritical,
					Tags:     []string{"sox", "access-control", "privilege-escalation"},
					Action:   AlertActionElevate,
				},
				// Sudo usage monitoring
				{
					Name:        "sox-sudo-usage",
					Description: "Monitor sudo command usage (SOX audit trail)",
					Enabled:     true,
					Conditions: RuleConditions{
						Category:     "process",
						ProcessNames: []string{"sudo", "su", "pkexec"},
					},
					Priority: ebpf.PriorityWarning,
					Tags:     []string{"sox", "audit-trail", "privilege"},
					Action:   AlertActionTag,
				},
				// User/group modification
				{
					Name:        "sox-user-modification",
					Description: "Detect user/group account modifications (SOX access control)",
					Enabled:     true,
					Conditions: RuleConditions{
						Category:     "process",
						ProcessNames: []string{"useradd", "usermod", "userdel", "groupadd", "groupmod", "groupdel", "passwd", "chpasswd"},
					},
					Priority: ebpf.PriorityCritical,
					Tags:     []string{"sox", "access-control", "user-management"},
					Action:   AlertActionElevate,
				},
				// SSH key modifications
				{
					Name:        "sox-ssh-key-change",
					Description: "Detect SSH key modifications (SOX access control)",
					Enabled:     true,
					Conditions: RuleConditions{
						Category:     "file",
						PathPatterns: []string{".ssh/authorized_keys", ".ssh/id_*"},
					},
					Priority: ebpf.PriorityCritical,
					Tags:     []string{"sox", "access-control", "ssh"},
					Action:   AlertActionElevate,
				},
				// Audit log tampering
				{
					Name:        "sox-audit-log-access",
					Description: "Monitor access to audit logs (SOX audit trail integrity)",
					Enabled:     true,
					Conditions: RuleConditions{
						Category:     "file",
						PathPatterns: []string{"/var/log/audit/*", "/var/log/secure", "/var/log/auth.log"},
					},
					Priority: ebpf.PriorityWarning,
					Tags:     []string{"sox", "audit-trail", "log-integrity"},
					Action:   AlertActionTag,
				},
				// System configuration changes
				{
					Name:        "sox-system-config-change",
					Description: "Detect system configuration changes (SOX change management)",
					Enabled:     true,
					Conditions: RuleConditions{
						Category:     "file",
						PathPatterns: []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers", "/etc/sudoers.d/*"},
					},
					Priority: ebpf.PriorityCritical,
					Tags:     []string{"sox", "change-management", "system-config"},
					Action:   AlertActionElevate,
				},
				// Kernel module loading
				{
					Name:        "sox-kernel-module",
					Description: "Detect kernel module loading (SOX system integrity)",
					Enabled:     true,
					Conditions: RuleConditions{
						Category: "kernel",
					},
					Priority: ebpf.PriorityCritical,
					Tags:     []string{"sox", "system-integrity", "kernel"},
					Action:   AlertActionElevate,
				},
			},
		},
	}
}

// GetPCIDSSProfile returns the PCI-DSS 4.0 compliance profile
// PCI-DSS focuses on: network security, file integrity, authentication, malware prevention
func GetPCIDSSProfile() ComplianceProfile {
	return ComplianceProfile{
		Name:        "pci-dss-4.0",
		DisplayName: "PCI-DSS 4.0 Compliance",
		Description: "Payment Card Industry Data Security Standard 4.0 compliance monitoring",
		Framework:   "pci-dss",
		Version:     "4.0",
		Tags:        []string{"payment", "cardholder-data", "security"},
		Config: Config{
			Enabled:          true,
			EnableProcess:    true,  // Req 5: Anti-malware, Req 6: Secure systems
			EnableFile:       true,  // Req 11.5: File integrity monitoring
			EnableNetwork:    true,  // Req 1: Network security controls
			EnablePrivilege:  true,  // Req 7/8: Access control
			EnableFilesystem: true,  // Req 11.5: FIM
			EnableKernel:     true,  // Req 5: System integrity
			EnableMemory:     true,  // Req 5: Memory protection
			EnableEnrichment: true,
			EnableAlerts:     true,

			// Exclude noisy paths
			ExcludePaths: []string{
				"/proc/",
				"/sys/",
				"/dev/",
			},

			// PCI-DSS specific alert rules
			AlertRules: []AlertRule{
				// Req 1.3: Network connections to cardholder data environment
				{
					Name:        "pci-network-connection",
					Description: "Monitor network connections (PCI-DSS Req 1.3)",
					Enabled:     true,
					Conditions: RuleConditions{
						Category: "network",
					},
					Priority: ebpf.PriorityNotice,
					Tags:     []string{"pci-dss", "req-1", "network"},
					Action:   AlertActionTag,
				},
				// Req 5.2: Anti-malware - detect suspicious process execution
				{
					Name:        "pci-suspicious-process",
					Description: "Detect potentially malicious process patterns (PCI-DSS Req 5.2)",
					Enabled:     true,
					Conditions: RuleConditions{
						Category:          "process",
						ProcessNamesRegex: []string{"^\\.", ".*base64.*", ".*curl.*\\|.*sh", ".*wget.*\\|.*sh"},
					},
					Priority: ebpf.PriorityCritical,
					Tags:     []string{"pci-dss", "req-5", "malware"},
					Action:   AlertActionElevate,
				},
				// Req 5.3: Memory protection - detect mprotect with EXEC
				{
					Name:        "pci-memory-exec",
					Description: "Detect memory pages made executable (PCI-DSS Req 5.3)",
					Enabled:     true,
					Conditions: RuleConditions{
						Category: "memory",
					},
					Priority: ebpf.PriorityWarning,
					Tags:     []string{"pci-dss", "req-5", "memory-protection"},
					Action:   AlertActionTag,
				},
				// Req 7.2: Privilege escalation
				{
					Name:        "pci-privilege-escalation",
					Description: "Detect privilege escalation (PCI-DSS Req 7.2)",
					Enabled:     true,
					Conditions: RuleConditions{
						Category:                  "privilege",
						PrivilegeEscalationToRoot: true,
					},
					Priority: ebpf.PriorityCritical,
					Tags:     []string{"pci-dss", "req-7", "privilege-escalation"},
					Action:   AlertActionElevate,
				},
				// Req 8.2: Authentication monitoring
				{
					Name:        "pci-authentication",
					Description: "Monitor authentication events (PCI-DSS Req 8.2)",
					Enabled:     true,
					Conditions: RuleConditions{
						Category:     "process",
						ProcessNames: []string{"sshd", "login", "sudo", "su", "passwd"},
					},
					Priority: ebpf.PriorityNotice,
					Tags:     []string{"pci-dss", "req-8", "authentication"},
					Action:   AlertActionTag,
				},
				// Req 10.2: Audit trail - critical file access
				{
					Name:        "pci-audit-critical-files",
					Description: "Monitor access to critical system files (PCI-DSS Req 10.2)",
					Enabled:     true,
					Conditions: RuleConditions{
						Category:     "file",
						PathPatterns: []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers"},
					},
					Priority: ebpf.PriorityWarning,
					Tags:     []string{"pci-dss", "req-10", "audit-trail"},
					Action:   AlertActionTag,
				},
				// Req 11.5: File Integrity Monitoring
				{
					Name:        "pci-fim-system-binaries",
					Description: "File integrity monitoring for system binaries (PCI-DSS Req 11.5)",
					Enabled:     true,
					Conditions: RuleConditions{
						Category:     "file",
						PathPatterns: []string{"/bin/*", "/sbin/*", "/usr/bin/*", "/usr/sbin/*"},
					},
					Priority: ebpf.PriorityCritical,
					Tags:     []string{"pci-dss", "req-11", "fim"},
					Action:   AlertActionElevate,
				},
				// Req 11.5: FIM for config files
				{
					Name:        "pci-fim-config-files",
					Description: "File integrity monitoring for configuration files (PCI-DSS Req 11.5)",
					Enabled:     true,
					Conditions: RuleConditions{
						Category:     "file",
						PathPatterns: []string{"/etc/*.conf", "/etc/ssh/*", "/etc/pam.d/*"},
					},
					Priority: ebpf.PriorityWarning,
					Tags:     []string{"pci-dss", "req-11", "fim", "config"},
					Action:   AlertActionTag,
				},
				// Kernel module loading
				{
					Name:        "pci-kernel-module",
					Description: "Detect kernel module loading (PCI-DSS system integrity)",
					Enabled:     true,
					Conditions: RuleConditions{
						Category: "kernel",
					},
					Priority: ebpf.PriorityCritical,
					Tags:     []string{"pci-dss", "req-5", "kernel"},
					Action:   AlertActionElevate,
				},
				// Container escape detection
				{
					Name:        "pci-container-escape",
					Description: "Detect potential container escape attempts (PCI-DSS Req 6)",
					Enabled:     true,
					Conditions: RuleConditions{
						Category:      "process",
						ContainerOnly: true,
						ProcessNames:  []string{"nsenter", "unshare"},
					},
					Priority: ebpf.PriorityCritical,
					Tags:     []string{"pci-dss", "req-6", "container-security"},
					Action:   AlertActionElevate,
				},
			},
		},
	}
}

// GetCustomProfile returns an empty custom profile for manual configuration
func GetCustomProfile() ComplianceProfile {
	return ComplianceProfile{
		Name:        "custom",
		DisplayName: "Custom Configuration",
		Description: "Custom configuration with no pre-defined rules",
		Framework:   "custom",
		Version:     "1.0",
		Tags:        []string{"custom"},
		Config:      DefaultConfig(),
	}
}

// ApplyComplianceProfile applies the specified compliance profile to the config
func ApplyComplianceProfile(profileName string) (Config, error) {
	profiles := GetComplianceProfiles()
	profile, exists := profiles[profileName]
	if !exists {
		// Return default config for unknown profiles
		return DefaultConfig(), nil
	}
	return profile.Config, nil
}

// GetComplianceProfileInfo returns just the metadata for all profiles (for UI listing)
func GetComplianceProfileInfo() []ComplianceProfileInfo {
	profiles := GetComplianceProfiles()
	info := make([]ComplianceProfileInfo, 0, len(profiles))
	for _, p := range profiles {
		info = append(info, ComplianceProfileInfo{
			Name:        p.Name,
			DisplayName: p.DisplayName,
			Description: p.Description,
			Framework:   p.Framework,
			Version:     p.Version,
			Tags:        p.Tags,
			RuleCount:   len(p.Config.AlertRules),
		})
	}
	return info
}

// ComplianceProfileInfo contains profile metadata for UI display
type ComplianceProfileInfo struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	Description string   `json:"description"`
	Framework   string   `json:"framework"`
	Version     string   `json:"version"`
	Tags        []string `json:"tags"`
	RuleCount   int      `json:"rule_count"`
}

package ebpf

// ============================================================================
// NATIVE LISTS - Comprehensive binary/path/port lists for eBPF filtering
// ============================================================================
// This file contains all the lists used for:
// - Exclusions: Reduce noise from legitimate system processes
// - Detections: Alert on security-relevant activity
// - SOX Compliance: Financial system audit requirements
// - PCI-DSS Compliance: Payment card industry requirements
// ============================================================================

// ============================= EXCLUSION LISTS =============================
// These lists define processes and paths that generate high event volume
// but are generally not security-relevant. Used to reduce noise.
// ============================================================================

// CoreutilsBinaries - standard Unix tools that generate high event volume
// These are legitimate system utilities that execute frequently
var CoreutilsBinaries = map[string]struct{}{
	// File operations
	"cat": {}, "ls": {}, "cp": {}, "mv": {}, "rm": {}, "mkdir": {},
	"rmdir": {}, "touch": {}, "ln": {}, "readlink": {},
	// Permissions
	"chmod": {}, "chown": {}, "chgrp": {},
	// File viewing
	"head": {}, "tail": {}, "less": {}, "more": {},
	// Text processing
	"grep": {}, "egrep": {}, "fgrep": {}, "sed": {}, "awk": {}, "gawk": {},
	"sort": {}, "uniq": {}, "wc": {}, "cut": {}, "tr": {}, "paste": {},
	"join": {}, "comm": {}, "diff": {}, "patch": {},
	// File search
	"find": {}, "xargs": {}, "locate": {}, "updatedb": {}, "which": {},
	"whereis": {},
	// I/O redirection
	"tee": {}, "dd": {}, "sync": {},
	// Path manipulation
	"basename": {}, "dirname": {}, "realpath": {}, "pwd": {},
	// Environment
	"env": {}, "printenv": {}, "export": {},
	// Output
	"echo": {}, "printf": {},
	// Test utilities
	"test": {}, "[": {}, "true": {}, "false": {},
	// System info
	"uname": {}, "hostname": {}, "hostnamectl": {},
	"id": {}, "whoami": {}, "groups": {}, "logname": {},
	// Disk utilities
	"df": {}, "du": {},
	// Temp files
	"mktemp": {}, "tempfile": {},
	// Time
	"date": {}, "cal": {}, "timedatectl": {},
	// Sleep
	"sleep": {}, "usleep": {},
	// File info
	"stat": {}, "file": {}, "lsattr": {}, "getfattr": {},
	// Checksum
	"md5sum": {}, "sha1sum": {}, "sha256sum": {}, "sha512sum": {}, "cksum": {},
	// Archive (read operations)
	"tar": {}, "gzip": {}, "gunzip": {}, "bzip2": {}, "bunzip2": {},
	"xz": {}, "unxz": {}, "zip": {}, "unzip": {},
	// Text editors (when used non-interactively)
	"vi": {}, "vim": {}, "nano": {}, "ed": {},
	// Pagers
	"pg": {},
	// Misc
	"yes": {}, "seq": {}, "shuf": {}, "factor": {}, "expr": {},
	"bc": {}, "dc": {},
}

// LegitPrivEscalationParents - processes that legitimately trigger privilege escalation
// These are system/desktop processes that use pkexec/polkit for normal operations
var LegitPrivEscalationParents = map[string]struct{}{
	// Desktop update/package management
	"update-notifier":     {},
	"update-manager":      {},
	"gnome-software":      {},
	"software-center":     {},
	"ubuntu-software":     {},
	"packagekit":          {},
	"packagekitd":         {},
	"pk-command-not-found": {},
	"aptd":                {},
	"unattended-upgrade":  {},
	"unattended-upgr":     {}, // truncated version
	// Polkit/authentication agents
	"polkit-agent-helper-1": {},
	"polkit-gnome-au":       {}, // truncated
	"polkitd":               {},
	"polkit-mate-aut":       {},
	"polkit-kde-auth":       {},
	"lxpolkit":              {},
	"lxqt-policykit":        {},
	// System services
	"systemd":             {},
	"systemd-logind":      {},
	"gdm":                 {},
	"gdm-session-worker":  {},
	"gdm-session-work":    {}, // truncated
	"gdm3":                {},
	"lightdm":             {},
	"sddm":                {},
	// Snap/Flatpak
	"snapd":               {},
	"snap":                {},
	"flatpak":             {},
	"flatpak-system-helper": {},
	// Desktop environments
	"gnome-shell":         {},
	"gnome-session":       {},
	"gnome-control-cen":   {}, // truncated: gnome-control-center
	"gnome-settings-da":   {}, // truncated: gnome-settings-daemon
	"kde-settings":        {},
	"plasma-desktop":      {},
	// Other legitimate escalators
	"gksu":                {},
	"gksudo":              {},
	"kdesudo":             {},
	"beesu":               {},
}

// LoginBinaries - authentication and session management processes
// These handle user login/logout and generate many privilege events
var LoginBinaries = map[string]struct{}{
	"login":          {},
	"systemd-logind": {},
	"su":             {},
	"nologin":        {},
	"newgrp":         {},
	"sg":             {},
	"runuser":        {},
	"setsid":         {},
	"setpriv":        {},
	// Session managers
	"gdm":              {},
	"gdm-session-work": {},
	"sddm":             {},
	"lightdm":          {},
	"xdm":              {},
	"kdm":              {},
	// PAM modules
	"pam_unix.so": {},
}

// PasswdBinaries - user and group management tools
// These legitimately modify /etc/passwd, /etc/shadow, etc.
var PasswdBinaries = map[string]struct{}{
	"useradd":  {},
	"userdel":  {},
	"usermod":  {},
	"passwd":   {},
	"chpasswd": {},
	"groupadd": {},
	"groupdel": {},
	"groupmod": {},
	"gpasswd":  {},
	"newusers": {},
	"chage":    {},
	"chsh":     {},
	"chfn":     {},
	"vipw":     {},
	"vigr":     {},
	"pwck":     {},
	"grpck":    {},
}

// ContainerBinaries - container runtime processes
// These legitimately perform setuid/setgid for container isolation
var ContainerBinaries = map[string]struct{}{
	// Docker
	"docker":       {},
	"dockerd":      {},
	"docker-proxy": {},
	"docker-init":  {},
	// Containerd
	"containerd":               {},
	"containerd-shim":          {},
	"containerd-shim-runc-v1":  {},
	"containerd-shim-runc-v2":  {},
	"containerd-stress":        {},
	// runc/crun
	"runc": {},
	"crun": {},
	// CRI-O
	"crio":    {},
	"crio-lxc": {},
	// Podman/Buildah
	"podman":  {},
	"buildah": {},
	"skopeo":  {},
	// Container network
	"slirp4netns": {},
	"fuse-overlayfs": {},
	// Pause container
	"pause": {},
	// Kata containers
	"kata-runtime":      {},
	"kata-agent":        {},
	"containerd-shim-kata-v2": {},
	// gVisor
	"runsc": {},
}

// K8sBinaries - Kubernetes control plane and node components
// These are trusted infrastructure that generate many events
var K8sBinaries = map[string]struct{}{
	// Core components
	"kubectl":                 {},
	"kubelet":                 {},
	"kube-proxy":              {},
	"kube-apiserver":          {},
	"kube-controller-manager": {},
	"kube-scheduler":          {},
	// etcd
	"etcd":    {},
	"etcdctl": {},
	// DNS
	"coredns": {},
	// Legacy
	"hyperkube": {},
	// Addons
	"kube-dns":          {},
	"kube-flannel":      {},
	"kube-router":       {},
	"calico-node":       {},
	"cilium-agent":      {},
	"weave-net":         {},
	"kindnetd":          {},
	// Ingress
	"nginx-ingress-controller": {},
	"traefik":                  {},
	// Service mesh
	"envoy":      {},
	"pilot-agent": {},
	"istio-proxy": {},
}

// DBServerBinaries - database server processes
// These are long-running services that generate many file/network events
var DBServerBinaries = map[string]struct{}{
	// MySQL/MariaDB
	"mysqld":         {},
	"mysqld_safe":    {},
	"mysql":          {},
	"mariadbd":       {},
	"mariadb":        {},
	// PostgreSQL
	"postgres":         {},
	"postmaster":       {},
	"pg_ctl":           {},
	"pg_isready":       {},
	"postgresql":       {},
	// MongoDB
	"mongod": {},
	"mongos": {},
	"mongo":  {},
	// Redis
	"redis-server":   {},
	"redis-sentinel": {},
	"redis-cli":      {},
	// Elasticsearch
	"elasticsearch": {},
	// Cassandra
	"cassandra": {},
	// CockroachDB
	"cockroach": {},
	// ClickHouse
	"clickhouse-server": {},
	"clickhouse-client": {},
	// SQLite
	"sqlite3": {},
	// Oracle
	"oracle": {},
	"sqlplus": {},
	// SQL Server
	"sqlservr": {},
}

// CronBinaries - scheduled task daemons
// These legitimately execute many child processes
var CronBinaries = map[string]struct{}{
	"cron":     {},
	"crond":    {},
	"anacron":  {},
	"at":       {},
	"atd":      {},
	"batch":    {},
	// Systemd timers
	"systemd-cron":   {},
	// Job schedulers
	"fcron":    {},
	"dcron":    {},
	"bcron":    {},
	"mcron":    {},
	// Run-parts
	"run-parts": {},
}

// MailBinaries - mail server processes
// These handle legitimate network connections and file operations
var MailBinaries = map[string]struct{}{
	// Postfix
	"postfix":       {},
	"master":        {}, // Postfix master
	"pickup":        {},
	"cleanup":       {},
	"qmgr":          {},
	"smtpd":         {},
	"smtp":          {},
	"local":         {},
	"virtual":       {},
	"pipe":          {},
	// Sendmail
	"sendmail":     {},
	"sendmail-mta": {},
	// Exim
	"exim":  {},
	"exim4": {},
	// Dovecot
	"dovecot":             {},
	"dovecot-auth":        {},
	"imap":                {},
	"imap-login":          {},
	"pop3":                {},
	"pop3-login":          {},
	// Other
	"procmail": {},
	"fetchmail": {},
	"mutt":     {},
	"mail":     {},
	"mailx":    {},
}

// SafeEtcDirs - configuration directories that are frequently accessed
// Reads from these paths are generally not security-relevant
var SafeEtcDirs = []string{
	"/etc/ssl/certs/",
	"/etc/pki/",
	"/etc/ca-certificates/",
	"/etc/nginx/conf.d/",
	"/etc/nginx/sites-enabled/",
	"/etc/apache2/sites-enabled/",
	"/etc/httpd/conf.d/",
	"/etc/ld.so.cache",
	"/etc/ld.so.conf.d/",
	"/etc/alternatives/",
	"/etc/fonts/",
	"/etc/mime.types",
	"/etc/localtime",
	"/etc/timezone",
	"/etc/nsswitch.conf",
	"/etc/host.conf",
	"/etc/gai.conf",
	"/etc/protocols",
	"/etc/services",
	"/etc/shells",
	"/etc/environment",
	"/etc/profile.d/",
	"/etc/bash_completion.d/",
	"/etc/default/",
}

// ============================= DETECTION LISTS =============================
// These lists define processes, ports, and domains that should trigger alerts
// when detected. Used for security monitoring and threat detection.
// ============================================================================

// SSHBinaries - SSH-related processes (SOX/PCI: remote access monitoring)
var SSHBinaries = map[string]struct{}{
	"ssh":           {},
	"sshd":          {},
	"ssh-agent":     {},
	"ssh-add":       {},
	"ssh-keygen":    {},
	"ssh-keyscan":   {},
	"sftp":          {},
	"sftp-server":   {},
	"scp":           {},
	"rsync":         {},
	"ssh-copy-id":   {},
	"autossh":       {},
	"sshpass":       {},
}

// PackageMgmtBinaries - package management tools (SOX/PCI: change management)
var PackageMgmtBinaries = map[string]struct{}{
	// Debian/Ubuntu
	"apt":       {},
	"apt-get":   {},
	"apt-cache": {},
	"aptitude":  {},
	"dpkg":      {},
	"dpkg-deb":  {},
	// Red Hat/CentOS/Fedora
	"yum":         {},
	"dnf":         {},
	"rpm":         {},
	"yum-config-manager": {},
	// Arch
	"pacman": {},
	"yay":    {},
	"paru":   {},
	// SUSE
	"zypper": {},
	// Alpine
	"apk": {},
	// Gentoo
	"emerge":  {},
	"portage": {},
	// Universal
	"snap":    {},
	"flatpak": {},
	// Language package managers
	"pip":       {},
	"pip3":      {},
	"pipx":      {},
	"npm":       {},
	"npx":       {},
	"yarn":      {},
	"pnpm":      {},
	"gem":       {},
	"bundle":    {},
	"bundler":   {},
	"cargo":     {},
	"rustup":    {},
	"go":        {},
	"composer":  {},
	"pecl":      {},
	"cpan":      {},
	"cpanm":     {},
	"maven":     {},
	"mvn":       {},
	"gradle":    {},
	"ant":       {},
	"nuget":     {},
	"dotnet":    {},
	"mix":       {},
	"hex":       {},
	"cabal":     {},
	"stack":     {},
	"opam":      {},
	"conda":     {},
	"mamba":     {},
	"poetry":    {},
	"pdm":       {},
	"uv":        {},
}

// NetworkToolBinaries - network reconnaissance and diagnostic tools
// These can indicate lateral movement or network scanning
var NetworkToolBinaries = map[string]struct{}{
	// Netcat variants
	"nc":      {},
	"ncat":    {},
	"netcat":  {},
	"socat":   {},
	"cryptcat": {},
	// Port scanners
	"nmap":    {},
	"masscan": {},
	"zmap":    {},
	"unicornscan": {},
	"hping":   {},
	"hping3":  {},
	// Packet capture
	"tcpdump":   {},
	"tshark":    {},
	"wireshark": {},
	"dumpcap":   {},
	"ettercap":  {},
	// DNS tools
	"dig":       {},
	"nslookup":  {},
	"host":      {},
	"dnsrecon":  {},
	"dnsenum":   {},
	// Web requests (can be used for data exfil)
	"wget":   {},
	"curl":   {},
	"httpie": {},
	"http":   {},
	// Network enumeration
	"arp":        {},
	"arp-scan":   {},
	"arping":     {},
	"fping":      {},
	"ping":       {},
	"traceroute": {},
	"tracepath":  {},
	"mtr":        {},
	"netstat":    {},
	"ss":         {},
	"lsof":       {},
	"iftop":      {},
	"nethogs":    {},
	"iptraf":     {},
	// Tunneling
	"stunnel":   {},
	"proxychains": {},
	"chisel":    {},
	"ligolo":    {},
	"iodine":    {},
	"dnscat":    {},
	"dnscat2":   {},
	// Wireless
	"aircrack-ng": {},
	"airodump-ng": {},
	"aireplay-ng": {},
	"wifite":      {},
}

// ShellBinaries - interactive shells (PCI: detect shell access in containers)
var ShellBinaries = map[string]struct{}{
	"bash":   {},
	"sh":     {},
	"dash":   {},
	"zsh":    {},
	"fish":   {},
	"tcsh":   {},
	"csh":    {},
	"ksh":    {},
	"ash":    {},
	"busybox": {},
}

// MinerPorts - common cryptocurrency mining pool ports
var MinerPorts = map[int]struct{}{
	3333:  {}, // Stratum
	3334:  {},
	3335:  {},
	4444:  {}, // XMR/ETH pools
	5555:  {},
	5556:  {},
	6666:  {},
	7777:  {},
	8008:  {},
	8080:  {}, // Some pools use this
	8888:  {},
	9999:  {},
	14433: {}, // Monero SSL
	14444: {},
	45560: {}, // Monero
	45700: {},
}

// MinerDomains - cryptocurrency mining pool domain patterns
// Note: Use strings.Contains or suffix matching for these
var MinerDomains = []string{
	"nanopool.org",
	"supportxmr.com",
	"xmrpool.eu",
	"moneropool.com",
	"minexmr.com",
	"hashvault.pro",
	"2miners.com",
	"f2pool.com",
	"antpool.com",
	"btc.com",
	"slushpool.com",
	"nicehash.com",
	"ethermine.org",
	"sparkpool.com",
	"poolin.com",
	"viabtc.com",
	"cryptonight-hub.miningpoolhub.com",
	"coinhive.com",
	"coin-hive.com",
	"jsecoin.com",
	"crypto-loot.com",
	"monerominer.rocks",
	"webminepool.com",
}

// MinerProcessNames - known cryptocurrency miner process names
var MinerProcessNames = map[string]struct{}{
	"xmrig":         {},
	"xmr-stak":      {},
	"minerd":        {},
	"cpuminer":      {},
	"ccminer":       {},
	"cgminer":       {},
	"bfgminer":      {},
	"ethminer":      {},
	"phoenix":       {},
	"phoenixminer":  {},
	"claymore":      {},
	"lolminer":      {},
	"nbminer":       {},
	"t-rex":         {},
	"gminer":        {},
	"xmr":           {},
	"monero":        {},
	"kryptex":       {},
}

// ============================= SOX COMPLIANCE LISTS ========================
// SOX (Sarbanes-Oxley) requirements for financial system controls
// ============================================================================

// SOXPrivilegedCommands - commands indicating privileged access (SOX Access Control)
var SOXPrivilegedCommands = map[string]struct{}{
	"sudo":     {},
	"su":       {},
	"pkexec":   {},
	"doas":     {},
	"visudo":   {},
	"sudoedit": {},
	"passwd":   {},
	"usermod":  {},
	"groupmod": {},
	"chown":    {},
	"chmod":    {},
	"setfacl":  {},
	"chattr":   {},
}

// SOXAuditBinaries - audit and logging system processes
// Tampering with these indicates audit log manipulation
var SOXAuditBinaries = map[string]struct{}{
	"auditd":     {},
	"auditctl":   {},
	"aureport":   {},
	"ausearch":   {},
	"augenrules": {},
	"rsyslogd":   {},
	"rsyslog":    {},
	"syslog-ng":  {},
	"syslogd":    {},
	"journald":   {},
	"systemd-journald": {},
	"logrotate":  {},
}

// SOXCriticalPaths - files requiring change monitoring for SOX compliance
var SOXCriticalPaths = []string{
	// Authentication and authorization
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/gshadow",
	"/etc/sudoers",
	"/etc/sudoers.d/",
	// SSH configuration
	"/etc/ssh/sshd_config",
	"/etc/ssh/ssh_config",
	"/etc/ssh/",
	// PAM configuration
	"/etc/pam.d/",
	"/etc/security/",
	"/etc/security/limits.conf",
	"/etc/security/access.conf",
	// Audit configuration
	"/etc/audit/",
	"/etc/audit/auditd.conf",
	"/etc/audit/audit.rules",
	"/var/log/audit/",
	// Logging configuration
	"/etc/rsyslog.conf",
	"/etc/rsyslog.d/",
	"/etc/syslog-ng/",
	"/var/log/auth.log",
	"/var/log/secure",
	"/var/log/messages",
	// Cron (scheduled tasks - change control)
	"/etc/crontab",
	"/etc/cron.d/",
	"/etc/cron.daily/",
	"/etc/cron.hourly/",
	"/etc/cron.weekly/",
	"/etc/cron.monthly/",
	"/var/spool/cron/",
	// System startup
	"/etc/rc.local",
	"/etc/init.d/",
	"/etc/systemd/system/",
	// Network configuration
	"/etc/hosts",
	"/etc/hosts.allow",
	"/etc/hosts.deny",
	"/etc/resolv.conf",
}

// SOXFinancialDataPaths - paths containing financial data (SOX Data Protection)
var SOXFinancialDataPaths = []string{
	"/var/lib/mysql/",
	"/var/lib/postgresql/",
	"/var/lib/pgsql/",
	"/var/lib/mongodb/",
	"/opt/oracle/",
	"/opt/mssql/",
	"/data/",
	"/srv/",
}

// ============================= PCI-DSS COMPLIANCE LISTS ====================
// PCI-DSS requirements for payment card data protection
// ============================================================================

// PCICriticalPorts - ports requiring monitoring per PCI-DSS
var PCICriticalPorts = map[int]struct{}{
	// Remote access (PCI Req 8)
	22:   {}, // SSH
	23:   {}, // Telnet (should not be used)
	3389: {}, // RDP
	5900: {}, // VNC
	5901: {},
	5902: {},
	// Databases containing cardholder data (PCI Req 3)
	3306:  {}, // MySQL
	5432:  {}, // PostgreSQL
	1433:  {}, // SQL Server
	1521:  {}, // Oracle
	27017: {}, // MongoDB
	6379:  {}, // Redis
	9042:  {}, // Cassandra
	// Web services (PCI Req 6)
	80:   {},
	443:  {},
	8080: {},
	8443: {},
	// FTP (should use SFTP)
	20: {},
	21: {},
}

// PCIRemoteAccessBinaries - remote access tools per PCI Req 8
var PCIRemoteAccessBinaries = map[string]struct{}{
	// SSH (acceptable)
	"ssh":         {},
	"sshd":        {},
	"scp":         {},
	"sftp":        {},
	// Legacy/insecure (should be flagged)
	"telnet":      {},
	"telnetd":     {},
	"rsh":         {},
	"rshd":        {},
	"rlogin":      {},
	"rlogind":     {},
	// VNC
	"vncserver":   {},
	"Xvnc":        {},
	"x11vnc":      {},
	"vncviewer":   {},
	"tigervnc":    {},
	// RDP
	"xrdp":        {},
	"xfreerdp":    {},
	"rdesktop":    {},
	// TeamViewer etc
	"teamviewer":  {},
	"anydesk":     {},
}

// PCIAntiMalwareBinaries - anti-malware tools per PCI Req 5
var PCIAntiMalwareBinaries = map[string]struct{}{
	"clamav":       {},
	"clamd":        {},
	"clamscan":     {},
	"freshclam":    {},
	"rkhunter":     {},
	"chkrootkit":   {},
	"aide":         {},
	"tripwire":     {},
	"ossec":        {},
	"ossec-agent":  {},
	"ossec-server": {},
	"sophos":       {},
	"falcon-sensor": {},
	"carbonblack":  {},
}

// PCILoggingBinaries - logging systems per PCI Req 10
var PCILoggingBinaries = map[string]struct{}{
	"rsyslog":           {},
	"rsyslogd":          {},
	"syslog-ng":         {},
	"syslogd":           {},
	"journald":          {},
	"systemd-journald":  {},
	"filebeat":          {},
	"logstash":          {},
	"fluentd":           {},
	"fluent-bit":        {},
	"vector":            {},
	"splunk":            {},
	"splunkd":           {},
}

// PCICardholderDataPaths - paths that may contain cardholder data (PCI Req 3)
// These are examples - actual paths should be configured per environment
var PCICardholderDataPaths = []string{
	"/var/lib/mysql/",
	"/var/lib/postgresql/",
	"/var/lib/pgsql/",
	"/opt/payment/",
	"/srv/payment/",
	"/data/transactions/",
	"/var/log/payment/",
}

// ============================================================================
// CONFIGURATION
// ============================================================================

// NativeListConfig controls which native lists are active
type NativeListConfig struct {
	// ---- Exclusions (true = exclude from events to reduce noise) ----

	// ExcludeCoreutilsBinaries excludes standard Unix tools (cat, ls, cp, etc.)
	ExcludeCoreutilsBinaries bool `yaml:"exclude_coreutils_binaries"`

	// ExcludeLoginBinaries excludes authentication processes (login, systemd-logind, etc.)
	ExcludeLoginBinaries bool `yaml:"exclude_login_binaries"`

	// ExcludePasswdBinaries excludes user management tools (useradd, passwd, etc.)
	ExcludePasswdBinaries bool `yaml:"exclude_passwd_binaries"`

	// ExcludeContainerBinaries excludes container runtimes (docker, containerd, runc, etc.)
	ExcludeContainerBinaries bool `yaml:"exclude_container_binaries"`

	// ExcludeK8sBinaries excludes Kubernetes components (kubectl, kubelet, etc.)
	ExcludeK8sBinaries bool `yaml:"exclude_k8s_binaries"`

	// ExcludeDBBinaries excludes database server processes (mysqld, postgres, etc.)
	ExcludeDBBinaries bool `yaml:"exclude_db_binaries"`

	// ExcludeCronBinaries excludes scheduled task daemons (cron, anacron, etc.)
	ExcludeCronBinaries bool `yaml:"exclude_cron_binaries"`

	// ExcludeMailBinaries excludes mail server processes (postfix, sendmail, etc.)
	ExcludeMailBinaries bool `yaml:"exclude_mail_binaries"`

	// ExcludeSafeEtcDirs excludes safe /etc paths from file monitoring
	ExcludeSafeEtcDirs bool `yaml:"exclude_safe_etc_dirs"`

	// ---- Detections (true = alert on these) ----

	// DetectNetworkTools alerts on network reconnaissance tools (nc, nmap, tcpdump, etc.)
	DetectNetworkTools bool `yaml:"detect_network_tools"`

	// DetectMinerActivity alerts on cryptocurrency mining activity
	DetectMinerActivity bool `yaml:"detect_miner_activity"`

	// DetectShellInContainer alerts on shell execution inside containers
	DetectShellInContainer bool `yaml:"detect_shell_in_container"`

	// DetectPackageManagement alerts on package manager execution
	DetectPackageManagement bool `yaml:"detect_package_management"`

	// ---- Compliance (auto-enabled by compliance profile) ----

	// SOXMonitoring enables SOX-specific monitoring rules
	SOXMonitoring bool `yaml:"sox_monitoring"`

	// PCIMonitoring enables PCI-DSS specific monitoring rules
	PCIMonitoring bool `yaml:"pci_monitoring"`
}

// DefaultNativeListConfig returns the default configuration for native lists
func DefaultNativeListConfig() NativeListConfig {
	return NativeListConfig{
		// Exclusions - enable conservative defaults to reduce noise
		ExcludeCoreutilsBinaries: true,
		ExcludeLoginBinaries:     true,
		ExcludePasswdBinaries:    false, // Keep visibility into user management
		ExcludeContainerBinaries: true,
		ExcludeK8sBinaries:       true,
		ExcludeDBBinaries:        true,
		ExcludeCronBinaries:      true,
		ExcludeMailBinaries:      true,
		ExcludeSafeEtcDirs:       true,

		// Detections - enable by default for security monitoring
		DetectNetworkTools:      true,
		DetectMinerActivity:     true,
		DetectShellInContainer:  true,
		DetectPackageManagement: true,

		// Compliance - disabled by default, enabled via compliance profile
		SOXMonitoring: false,
		PCIMonitoring: false,
	}
}

// BuildExcludeComms returns a composite exclusion map based on config
// This merges all enabled exclusion lists into a single map for O(1) lookup
func (c *NativeListConfig) BuildExcludeComms() map[string]struct{} {
	result := make(map[string]struct{})

	if c.ExcludeCoreutilsBinaries {
		for k := range CoreutilsBinaries {
			result[k] = struct{}{}
		}
	}

	if c.ExcludeLoginBinaries {
		for k := range LoginBinaries {
			result[k] = struct{}{}
		}
	}

	if c.ExcludePasswdBinaries {
		for k := range PasswdBinaries {
			result[k] = struct{}{}
		}
	}

	if c.ExcludeContainerBinaries {
		for k := range ContainerBinaries {
			result[k] = struct{}{}
		}
	}

	if c.ExcludeK8sBinaries {
		for k := range K8sBinaries {
			result[k] = struct{}{}
		}
	}

	if c.ExcludeDBBinaries {
		for k := range DBServerBinaries {
			result[k] = struct{}{}
		}
	}

	if c.ExcludeCronBinaries {
		for k := range CronBinaries {
			result[k] = struct{}{}
		}
	}

	if c.ExcludeMailBinaries {
		for k := range MailBinaries {
			result[k] = struct{}{}
		}
	}

	return result
}

// BuildExcludePaths returns a composite exclusion path list based on config
func (c *NativeListConfig) BuildExcludePaths() []string {
	var result []string

	if c.ExcludeSafeEtcDirs {
		result = append(result, SafeEtcDirs...)
	}

	return result
}

// IsNetworkTool checks if a process name is a network reconnaissance tool
func IsNetworkTool(comm string) bool {
	_, ok := NetworkToolBinaries[comm]
	return ok
}

// IsMinerProcess checks if a process name is a known cryptocurrency miner
func IsMinerProcess(comm string) bool {
	_, ok := MinerProcessNames[comm]
	return ok
}

// IsMinerPort checks if a port is commonly used for cryptocurrency mining
func IsMinerPort(port int) bool {
	_, ok := MinerPorts[port]
	return ok
}

// IsShellBinary checks if a process name is an interactive shell
func IsShellBinary(comm string) bool {
	_, ok := ShellBinaries[comm]
	return ok
}

// IsSSHBinary checks if a process name is SSH-related
func IsSSHBinary(comm string) bool {
	_, ok := SSHBinaries[comm]
	return ok
}

// IsPackageManager checks if a process name is a package manager
func IsPackageManager(comm string) bool {
	_, ok := PackageMgmtBinaries[comm]
	return ok
}

// IsSOXPrivilegedCommand checks if a command is privileged per SOX
func IsSOXPrivilegedCommand(comm string) bool {
	_, ok := SOXPrivilegedCommands[comm]
	return ok
}

// IsSOXAuditBinary checks if a process is an audit system component
func IsSOXAuditBinary(comm string) bool {
	_, ok := SOXAuditBinaries[comm]
	return ok
}

// IsPCIRemoteAccessBinary checks if a process is a remote access tool
func IsPCIRemoteAccessBinary(comm string) bool {
	_, ok := PCIRemoteAccessBinaries[comm]
	return ok
}

// IsPCICriticalPort checks if a port requires PCI monitoring
func IsPCICriticalPort(port int) bool {
	_, ok := PCICriticalPorts[port]
	return ok
}

// IsContainerBinary checks if a process is a container runtime
func IsContainerBinary(comm string) bool {
	_, ok := ContainerBinaries[comm]
	return ok
}

// IsLegitPrivEscalationParent checks if a parent process legitimately triggers privilege escalation
func IsLegitPrivEscalationParent(comm string) bool {
	_, ok := LegitPrivEscalationParents[comm]
	return ok
}

// PathMatchesSOXCritical checks if a path matches SOX critical paths
func PathMatchesSOXCritical(path string) bool {
	for _, critical := range SOXCriticalPaths {
		if len(path) >= len(critical) && path[:len(critical)] == critical {
			return true
		}
		// Also check if the critical path is a prefix of the given path
		if len(critical) > 0 && critical[len(critical)-1] == '/' {
			// Directory prefix match
			if len(path) >= len(critical) && path[:len(critical)] == critical {
				return true
			}
		} else {
			// Exact match or path starts with critical path
			if path == critical {
				return true
			}
		}
	}
	return false
}

// PathMatchesPCICardholder checks if a path matches PCI cardholder data paths
func PathMatchesPCICardholder(path string) bool {
	for _, dataPath := range PCICardholderDataPaths {
		if len(path) >= len(dataPath) && path[:len(dataPath)] == dataPath {
			return true
		}
	}
	return false
}

// DomainMatchesMiner checks if a domain is associated with cryptocurrency mining
func DomainMatchesMiner(domain string) bool {
	for _, minerDomain := range MinerDomains {
		// Check if domain ends with the miner domain
		if len(domain) >= len(minerDomain) {
			suffix := domain[len(domain)-len(minerDomain):]
			if suffix == minerDomain {
				// Ensure it's a proper domain boundary
				if len(domain) == len(minerDomain) || domain[len(domain)-len(minerDomain)-1] == '.' {
					return true
				}
			}
		}
	}
	return false
}

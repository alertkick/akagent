package ebpf

// ============================================================================
// NATIVE LISTS - Public-knowledge binary/path/port lists for eBPF filtering
// ============================================================================
// Only carries the high-volume exclusion sets the agent uses to drop noise
// at source. Framework-specific lists and matchers live at the endpoint.
// ============================================================================

// ============================= EXCLUSION LISTS =============================
// These lists define processes and paths that generate high event volume
// but are generally not security-relevant. Used to reduce noise.
// ============================================================================

// AKCoreutilsBinaries - standard Unix tools that generate high event volume
// These are legitimate system utilities that execute frequently
var AKCoreutilsBinaries = map[string]struct{}{
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

// AKLegitPrivEscalationParents - processes that legitimately trigger privilege escalation
// These are system/desktop processes that use pkexec/polkit for normal operations
var AKLegitPrivEscalationParents = map[string]struct{}{
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

// AKLoginBinaries - authentication and session management processes
// These handle user login/logout and generate many privilege events
var AKLoginBinaries = map[string]struct{}{
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

// AKPasswdBinaries - user and group management tools
// These legitimately modify /etc/passwd, /etc/shadow, etc.
var AKPasswdBinaries = map[string]struct{}{
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

// AKContainerBinaries - container runtime processes
// These legitimately perform setuid/setgid for container isolation
var AKContainerBinaries = map[string]struct{}{
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

// AKK8sBinaries - Kubernetes control plane and node components
// These are trusted infrastructure that generate many events
var AKK8sBinaries = map[string]struct{}{
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

// AKDBServerBinaries - database server processes
// These are long-running services that generate many file/network events
var AKDBServerBinaries = map[string]struct{}{
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

// AKCronBinaries - scheduled task daemons
// These legitimately execute many child processes
var AKCronBinaries = map[string]struct{}{
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

// AKMailBinaries - mail server processes
// These handle legitimate network connections and file operations
var AKMailBinaries = map[string]struct{}{
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

// AKSafeEtcDirs - configuration directories that are frequently accessed
// Reads from these paths are generally not security-relevant
var AKSafeEtcDirs = []string{
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

// AKSSHBinaries - SSH-related processes
var AKSSHBinaries = map[string]struct{}{
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

// AKPackageMgmtBinaries - package management tools
var AKPackageMgmtBinaries = map[string]struct{}{
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

// AKNetworkToolBinaries - network reconnaissance and diagnostic tools
// These can indicate lateral movement or network scanning
var AKNetworkToolBinaries = map[string]struct{}{
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

// AKShellBinaries - interactive shells
var AKShellBinaries = map[string]struct{}{
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

// ============================================================================
// CONFIGURATION
// ============================================================================

// NativeListConfig controls which native lists are active in the agent's
// noise filter. Framework-specific lists and the matchers that consume
// them live at the endpoint — the agent only carries the public-knowledge
// exclusion sets needed to drop high-volume noise at source.
type NativeListConfig struct {
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
}

// DefaultNativeListConfig returns the default configuration for noise filtering.
func DefaultNativeListConfig() NativeListConfig {
	return NativeListConfig{
		ExcludeCoreutilsBinaries: true,
		ExcludeLoginBinaries:     true,
		ExcludePasswdBinaries:    false, // Keep visibility into user management
		ExcludeContainerBinaries: true,
		ExcludeK8sBinaries:       true,
		ExcludeDBBinaries:        true,
		ExcludeCronBinaries:      true,
		ExcludeMailBinaries:      true,
		ExcludeSafeEtcDirs:       true,
	}
}

// BuildExcludeComms returns a composite exclusion map based on config.
// This merges all enabled exclusion lists into a single map for O(1) lookup.
func (c *NativeListConfig) BuildExcludeComms() map[string]struct{} {
	result := make(map[string]struct{})

	if c.ExcludeCoreutilsBinaries {
		for k := range AKCoreutilsBinaries {
			result[k] = struct{}{}
		}
	}
	if c.ExcludeLoginBinaries {
		for k := range AKLoginBinaries {
			result[k] = struct{}{}
		}
	}
	if c.ExcludePasswdBinaries {
		for k := range AKPasswdBinaries {
			result[k] = struct{}{}
		}
	}
	if c.ExcludeContainerBinaries {
		for k := range AKContainerBinaries {
			result[k] = struct{}{}
		}
	}
	if c.ExcludeK8sBinaries {
		for k := range AKK8sBinaries {
			result[k] = struct{}{}
		}
	}
	if c.ExcludeDBBinaries {
		for k := range AKDBServerBinaries {
			result[k] = struct{}{}
		}
	}
	if c.ExcludeCronBinaries {
		for k := range AKCronBinaries {
			result[k] = struct{}{}
		}
	}
	if c.ExcludeMailBinaries {
		for k := range AKMailBinaries {
			result[k] = struct{}{}
		}
	}

	return result
}

// BuildExcludePaths returns a composite exclusion path list based on config.
func (c *NativeListConfig) BuildExcludePaths() []string {
	var result []string
	if c.ExcludeSafeEtcDirs {
		result = append(result, AKSafeEtcDirs...)
	}
	return result
}

// IsShellBinary checks if a process name is an interactive shell.
// Kept on the agent because shell-name lookup is occasionally useful for
// noise-filter exclusion (e.g., "drop trivial shell completions").
func IsShellBinary(comm string) bool {
	_, ok := AKShellBinaries[comm]
	return ok
}

// IsSSHBinary checks if a process name is SSH-related.
func IsSSHBinary(comm string) bool {
	_, ok := AKSSHBinaries[comm]
	return ok
}

// IsContainerBinary checks if a process is a container runtime.
func IsContainerBinary(comm string) bool {
	_, ok := AKContainerBinaries[comm]
	return ok
}

package fim

import "path/filepath"

// pkgMgrComms is the set of process names that legitimately rewrite binaries
// and /etc during normal operation. A change attributed to one of these (the
// modifying process or any ancestor) is "expected" and, when suppression is
// on, re-baselined silently instead of raising a finding.
var pkgMgrComms = map[string]bool{
	"apt":             true,
	"apt-get":         true,
	"aptitude":        true,
	"dpkg":            true,
	"dpkg-deb":        true,
	"unattended-upgr": true,
	"rpm":             true,
	"yum":             true,
	"dnf":             true,
	"apk":             true,
	"zypper":          true,
	"pacman":          true,
}

// isPkgMgrName reports whether a process comm/exe basename is a known package
// manager.
func isPkgMgrName(name string) bool {
	if name == "" {
		return false
	}
	return pkgMgrComms[filepath.Base(name)]
}

// AttributedToPkgMgr reports whether the modifying process — by its own comm or
// exe, or any of its ancestor comms — is a package manager.
func AttributedToPkgMgr(t Trigger) bool {
	if isPkgMgrName(t.Comm) || isPkgMgrName(t.Exe) {
		return true
	}
	for _, a := range t.Ancestry {
		if isPkgMgrName(a) {
			return true
		}
	}
	return false
}

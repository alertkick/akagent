// Package responder performs host-side active-response enforcement: blocking an
// IP via iptables (with a TTL auto-revert) and killing a process. Safety is the
// whole point — it defaults to dry-run, never blocks an allowlisted/management
// address, and refuses to kill protected processes. The actual command exec is
// injectable so the safety logic unit-tests without touching the host.
package responder

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Config controls the responder. DryRun defaults to true at the wiring layer:
// nothing is enforced until an operator explicitly turns it off.
type Config struct {
	DryRun    bool
	Allowlist []string // IPs/CIDRs that must never be blocked
	Chain     string   // iptables chain to own (default ALERTKICK_BLOCK)
}

// protectedComms are processes we refuse to kill — losing them would take the
// host down or cut off management access.
var protectedComms = map[string]bool{
	"systemd": true, "init": true, "sshd": true,
	"alertkick-agent": true, "akagent": true, "kthreadd": true,
}

// Responder applies and tracks active-response actions.
type Responder struct {
	cfg       Config
	run       func(name string, args ...string) error
	onAudit   func(action, target, result string)
	commOf    func(pid int) string

	mu        sync.Mutex
	allowIPs  map[string]bool
	allowNets []*net.IPNet
	blocked   map[string]*time.Timer // ip → auto-unblock timer
	chained   bool
}

// New builds a Responder. onAudit (optional) records every attempt/outcome.
func New(cfg Config, onAudit func(action, target, result string)) *Responder {
	if cfg.Chain == "" {
		cfg.Chain = "ALERTKICK_BLOCK"
	}
	r := &Responder{
		cfg:      cfg,
		run:      execRun,
		onAudit:  onAudit,
		commOf:   commOf,
		allowIPs: map[string]bool{},
		blocked:  map[string]*time.Timer{},
	}
	// Always protect loopback so we can never cut local management.
	always := append([]string{"127.0.0.1", "::1"}, cfg.Allowlist...)
	for _, a := range always {
		if strings.Contains(a, "/") {
			if _, n, err := net.ParseCIDR(a); err == nil {
				r.allowNets = append(r.allowNets, n)
			}
			continue
		}
		if net.ParseIP(a) != nil {
			r.allowIPs[a] = true
		}
	}
	// Protect the host's own addresses — blocking them is never useful and can
	// break local services.
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				r.allowIPs[ipn.IP.String()] = true
			}
		}
	}
	return r
}

// isAllowlisted reports whether ip must never be blocked.
func (r *Responder) isAllowlisted(ip string) bool {
	if r.allowIPs[ip] {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true // unparseable → refuse to act
	}
	for _, n := range r.allowNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// BlockIP drops traffic to/from ip for ttlSeconds (0 = until explicitly
// unblocked). Refuses allowlisted/management addresses; in dry-run it audits
// the intent without touching iptables.
func (r *Responder) BlockIP(ip string, ttlSeconds int) error {
	if r.isAllowlisted(ip) {
		r.audit("block_ip", ip, "refused: allowlisted")
		return fmt.Errorf("refusing to block allowlisted/management address %q", ip)
	}
	if r.cfg.DryRun {
		r.audit("block_ip", ip, "dry-run")
		return nil
	}
	if err := r.ensureChain(); err != nil {
		r.audit("block_ip", ip, "error: "+err.Error())
		return err
	}
	for _, flag := range []string{"-s", "-d"} {
		if err := r.run("iptables", "-A", r.cfg.Chain, flag, ip, "-j", "DROP"); err != nil {
			r.audit("block_ip", ip, "error: "+err.Error())
			return err
		}
	}
	r.scheduleUnblock(ip, ttlSeconds)
	r.audit("block_ip", ip, "blocked")
	return nil
}

// UnblockIP removes the block rules for ip.
func (r *Responder) UnblockIP(ip string) error {
	r.mu.Lock()
	if t, ok := r.blocked[ip]; ok {
		t.Stop()
		delete(r.blocked, ip)
	}
	r.mu.Unlock()
	if r.cfg.DryRun {
		r.audit("unblock_ip", ip, "dry-run")
		return nil
	}
	var firstErr error
	for _, flag := range []string{"-s", "-d"} {
		if err := r.run("iptables", "-D", r.cfg.Chain, flag, ip, "-j", "DROP"); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	r.audit("unblock_ip", ip, "unblocked")
	return firstErr
}

// KillProcess sends SIGKILL to pid after the safety checks.
func (r *Responder) KillProcess(pid int) error {
	if pid <= 1 {
		r.audit("kill_process", strconv.Itoa(pid), "refused: protected pid")
		return fmt.Errorf("refusing to kill pid %d", pid)
	}
	if pid == os.Getpid() {
		r.audit("kill_process", strconv.Itoa(pid), "refused: self")
		return fmt.Errorf("refusing to kill the agent itself")
	}
	if comm := r.commOf(pid); protectedComms[comm] {
		r.audit("kill_process", strconv.Itoa(pid), "refused: protected comm "+comm)
		return fmt.Errorf("refusing to kill protected process %q (pid %d)", comm, pid)
	}
	if r.cfg.DryRun {
		r.audit("kill_process", strconv.Itoa(pid), "dry-run")
		return nil
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		r.audit("kill_process", strconv.Itoa(pid), "error: "+err.Error())
		return err
	}
	r.audit("kill_process", strconv.Itoa(pid), "killed")
	return nil
}

func (r *Responder) scheduleUnblock(ip string, ttlSeconds int) {
	if ttlSeconds <= 0 {
		return
	}
	r.mu.Lock()
	if old, ok := r.blocked[ip]; ok {
		old.Stop()
	}
	r.blocked[ip] = time.AfterFunc(time.Duration(ttlSeconds)*time.Second, func() {
		_ = r.UnblockIP(ip)
	})
	r.mu.Unlock()
}

// ensureChain creates the owned chain and jumps to it from INPUT and OUTPUT,
// idempotently (iptables -C tells us whether the jump already exists).
func (r *Responder) ensureChain() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.chained {
		return nil
	}
	_ = r.run("iptables", "-N", r.cfg.Chain) // ignore "exists"
	for _, hook := range []string{"INPUT", "OUTPUT"} {
		if err := r.run("iptables", "-C", hook, "-j", r.cfg.Chain); err != nil {
			if err := r.run("iptables", "-I", hook, "-j", r.cfg.Chain); err != nil {
				return err
			}
		}
	}
	r.chained = true
	return nil
}

func (r *Responder) audit(action, target, result string) {
	if r.onAudit != nil {
		r.onAudit(action, target, result)
	}
}

func execRun(name string, args ...string) error {
	return runCommand(name, args...)
}

func commOf(pid int) string {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

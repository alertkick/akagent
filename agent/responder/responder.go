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
	"sync/atomic"
	"time"
)

// Config controls the responder. DryRun defaults to true at the wiring layer:
// nothing is enforced until an operator explicitly turns it off.
type Config struct {
	DryRun    bool
	Allowlist []string // IPs/CIDRs that must never be blocked
	Chain     string   // iptables chain to own (default ALERTKICK_BLOCK)
}

// enfState is the enforcement config the responder reads on every action:
// dry-run vs enforce, plus the resolved allowlist. It is immutable once built
// and swapped atomically by UpdateConfig, so BlockIP/isAllowlisted get a
// consistent snapshot without locking and a live config change (e.g. flipping
// enforce or the tenant kill switch) takes effect with no restart.
type enfState struct {
	dryRun    bool
	allowIPs  map[string]bool
	allowNets []*net.IPNet
}

// buildEnfState resolves an allowlist into the lookup structures, always
// including loopback and the host's own interface addresses so we can never cut
// local management or block the host itself.
func buildEnfState(dryRun bool, allowlist []string) *enfState {
	s := &enfState{dryRun: dryRun, allowIPs: map[string]bool{}}
	for _, a := range append([]string{"127.0.0.1", "::1"}, allowlist...) {
		if strings.Contains(a, "/") {
			if _, n, err := net.ParseCIDR(a); err == nil {
				s.allowNets = append(s.allowNets, n)
			}
			continue
		}
		if net.ParseIP(a) != nil {
			s.allowIPs[a] = true
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				s.allowIPs[ipn.IP.String()] = true
			}
		}
	}
	return s
}

// protectedComms are processes we refuse to kill — losing them would take the
// host down or cut off management access.
var protectedComms = map[string]bool{
	"systemd": true, "init": true, "sshd": true,
	"alertkick-agent": true, "akagent": true, "kthreadd": true,
}

// Responder applies and tracks active-response actions.
type Responder struct {
	chain   string // iptables chain we own; immutable after New
	run     func(name string, args ...string) error
	onAudit func(action, target, result string)
	commOf  func(pid int) string

	enf atomic.Pointer[enfState] // dry-run + allowlist; swapped by UpdateConfig

	mu      sync.Mutex
	blocked map[string]*time.Timer // ip → auto-unblock timer
	chained bool
}

// New builds a Responder. onAudit (optional) records every attempt/outcome.
func New(cfg Config, onAudit func(action, target, result string)) *Responder {
	if cfg.Chain == "" {
		cfg.Chain = "ALERTKICK_BLOCK"
	}
	r := &Responder{
		chain:   cfg.Chain,
		run:     execRun,
		onAudit: onAudit,
		commOf:  commOf,
		blocked: map[string]*time.Timer{},
	}
	r.enf.Store(buildEnfState(cfg.DryRun, cfg.Allowlist))
	return r
}

// UpdateConfig live-swaps the enforcement settings (dry-run + allowlist)
// without dropping active blocks: the blocked-IP timer map and the owned
// iptables chain are left intact. Called when a new native config is pushed so
// an operator can flip enforce (or the tenant kill switch) without an agent
// restart. The chain is immutable and never changes here.
func (r *Responder) UpdateConfig(cfg Config) {
	r.enf.Store(buildEnfState(cfg.DryRun, cfg.Allowlist))
}

// isAllowlisted reports whether ip must never be blocked.
func (r *Responder) isAllowlisted(ip string) bool {
	s := r.enf.Load()
	if s.allowIPs[ip] {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true // unparseable → refuse to act
	}
	for _, n := range s.allowNets {
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
	if r.enf.Load().dryRun {
		r.audit("block_ip", ip, "dry-run")
		return nil
	}
	if err := r.ensureChain(); err != nil {
		r.audit("block_ip", ip, "error: "+err.Error())
		return err
	}
	for _, flag := range []string{"-s", "-d"} {
		if err := r.run("iptables", "-A", r.chain, flag, ip, "-j", "DROP"); err != nil {
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
	if r.enf.Load().dryRun {
		r.audit("unblock_ip", ip, "dry-run")
		return nil
	}
	var firstErr error
	for _, flag := range []string{"-s", "-d"} {
		if err := r.run("iptables", "-D", r.chain, flag, ip, "-j", "DROP"); err != nil && firstErr == nil {
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
	if r.enf.Load().dryRun {
		r.audit("kill_process", strconv.Itoa(pid), "dry-run")
		return nil
	}
	// os.Process.Kill sends SIGKILL on Unix and TerminateProcess on Windows,
	// so this path cross-compiles (syscall.Kill does not exist on Windows).
	proc, err := os.FindProcess(pid)
	if err == nil {
		err = proc.Kill()
	}
	if err != nil {
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
	_ = r.run("iptables", "-N", r.chain) // ignore "exists"
	for _, hook := range []string{"INPUT", "OUTPUT"} {
		if err := r.run("iptables", "-C", hook, "-j", r.chain); err != nil {
			if err := r.run("iptables", "-I", hook, "-j", r.chain); err != nil {
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

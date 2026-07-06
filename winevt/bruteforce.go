package winevt

import (
	"fmt"
	"sync"
	"time"

	"akagent/ebpf"

	"github.com/rs/xid"
)

// bruteForce tracks failed-logon bursts per source and raises a high-severity
// event when one source crosses a threshold inside a sliding window. It is
// the Windows analogue of agent/authmonitor, fed by 4625 records instead of
// auth.log lines. Safe for concurrent Observe calls.
type bruteForce struct {
	threshold int
	window    time.Duration
	cooldown  time.Duration

	mu        sync.Mutex
	failures  map[string][]time.Time
	lastAlert map[string]time.Time
	lastUser  map[string]string
	now       func() time.Time // injectable for tests
}

func newBruteForce() *bruteForce {
	return &bruteForce{
		threshold: 5,
		window:    2 * time.Minute,
		cooldown:  5 * time.Minute,
		failures:  make(map[string][]time.Time),
		lastAlert: make(map[string]time.Time),
		lastUser:  make(map[string]string),
		now:       time.Now,
	}
}

// Observe records a failed logon (Security 4625). It returns a brute-force
// SecurityEvent and true when the source crosses the threshold (subject to
// the per-source cooldown), otherwise a zero event and false. Failures with
// no usable source IP are keyed by the targeted user instead.
func (b *bruteForce) Observe(r *Record) (ebpf.SecurityEvent, bool) {
	source := r.get("IpAddress")
	user := r.get("TargetUserName")
	key := "ip:" + source
	if source == "" || source == "-" {
		key = "user:" + user
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	cutoff := now.Add(-b.window)

	times := append(b.failures[key], now)
	pruned := times[:0]
	for _, t := range times {
		if !t.Before(cutoff) {
			pruned = append(pruned, t)
		}
	}
	b.failures[key] = pruned
	b.lastUser[key] = user

	if len(pruned) < b.threshold {
		return ebpf.SecurityEvent{}, false
	}
	if last, ok := b.lastAlert[key]; ok && now.Sub(last) < b.cooldown {
		return ebpf.SecurityEvent{}, false
	}
	b.lastAlert[key] = now

	count := len(pruned)
	windowSecs := int(b.window.Seconds())
	ev := ebpf.SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: ebpf.AgentTypeNative,
		Timestamp: now,
		Priority:  ebpf.PriorityError,
		Rule:      "RDP Brute Force",
		Source:    "winevt",
		Category:  "auth",
		Hostname:  r.Computer,
		Output:    fmt.Sprintf("%d failed logins from %s within %ds (user %s)", count, source, windowSecs, user),
		Process:   ebpf.ProcessInfo{Username: user},
		Network:   ebpf.NetworkInfo{SrcIP: source},
		RawFields: map[string]interface{}{
			"brute_force_kind": "rdp_brute_force",
			"source":           source,
			"user":             user,
			"failure_count":    count,
			"window_seconds":   windowSecs,
		},
	}
	return ev, true
}

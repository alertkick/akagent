package authmonitor

import "testing"

func TestSSHBruteForce(t *testing.T) {
	var findings []Finding
	m := New(Config{Threshold: 3, WindowSeconds: 60, CooldownSeconds: 100}, func(f Finding) {
		findings = append(findings, f)
	})
	line := "May 30 10:00:00 host sshd[123]: Failed password for invalid user admin from 203.0.113.9 port 5555 ssh2"
	// Below threshold → no finding.
	m.processLine(line, 1000)
	m.processLine(line, 1001)
	if len(findings) != 0 {
		t.Fatalf("expected no finding below threshold, got %d", len(findings))
	}
	// Third failure within the window → one finding.
	m.processLine(line, 1002)
	if len(findings) != 1 {
		t.Fatalf("expected one finding at threshold, got %d", len(findings))
	}
	f := findings[0]
	if f.Kind != KindSSHBruteForce || f.Source != "203.0.113.9" || f.User != "admin" || f.Count != 3 {
		t.Fatalf("unexpected finding: %+v", f)
	}
	// Within cooldown → suppressed.
	m.processLine(line, 1003)
	if len(findings) != 1 {
		t.Fatalf("cooldown should suppress, got %d", len(findings))
	}
}

func TestWindowExpiry(t *testing.T) {
	var findings []Finding
	m := New(Config{Threshold: 3, WindowSeconds: 60, CooldownSeconds: 1}, func(f Finding) {
		findings = append(findings, f)
	})
	line := "sshd[1]: Failed password for root from 198.51.100.7 port 22 ssh2"
	m.processLine(line, 1000)
	m.processLine(line, 1030)
	// Old failures fall out of the 60s window, so this is only the 2nd live one.
	m.processLine(line, 1100)
	if len(findings) != 0 {
		t.Fatalf("stale failures should expire from the window, got %d", len(findings))
	}
}

// OpenSSH 9.8+ logs failures from the per-connection "sshd-session" process,
// so the parser must accept that identifier as well as classic "sshd".
func TestSSHSessionIdentifier(t *testing.T) {
	var findings []Finding
	m := New(Config{Threshold: 2, WindowSeconds: 60, CooldownSeconds: 100}, func(f Finding) {
		findings = append(findings, f)
	})
	line := "Jul 17 10:00:00 host sshd-session[456]: Failed password for root from 203.0.113.20 port 40000 ssh2"
	m.processLine(line, 1000)
	m.processLine(line, 1001)
	if len(findings) != 1 || findings[0].Source != "203.0.113.20" || findings[0].User != "root" {
		t.Fatalf("sshd-session line not parsed as brute force: %+v", findings)
	}
}

func TestSudoBruteForce(t *testing.T) {
	var findings []Finding
	m := New(Config{Threshold: 2, WindowSeconds: 60, CooldownSeconds: 100}, func(f Finding) {
		findings = append(findings, f)
	})
	line := "sudo:   eviluser : authentication failure; logname=eviluser uid=1000 tty=/dev/pts/0 ruser=eviluser rhost= user=root"
	m.processLine(line, 1000)
	m.processLine(line, 1001)
	if len(findings) != 1 || findings[0].Kind != KindSudoBruteForce || findings[0].User != "eviluser" {
		t.Fatalf("expected one sudo brute-force finding for eviluser, got %+v", findings)
	}
}

func TestIgnoresBenignLines(t *testing.T) {
	var findings []Finding
	m := New(Config{Threshold: 1}, func(f Finding) { findings = append(findings, f) })
	m.processLine("sshd[1]: Accepted publickey for ssidhu from 10.0.0.1 port 50000 ssh2", 1000)
	m.processLine("systemd[1]: Started Session 5 of user root.", 1000)
	if len(findings) != 0 {
		t.Fatalf("benign lines should not trigger, got %d", len(findings))
	}
}

func TestGCStaleBoundsMaps(t *testing.T) {
	m := New(Config{Threshold: 3, WindowSeconds: 60, CooldownSeconds: 100}, func(Finding) {})
	// Simulate a brute-force flood from many distinct source IPs, each seen
	// once and never again (the leak scenario).
	base := int64(1000)
	for i := 0; i < 500; i++ {
		line := "May 30 10:00:00 host sshd[123]: Failed password for root from 10.0." + itoa(i/256) + "." + itoa(i%256) + " port 22 ssh2"
		m.processLine(line, base)
	}
	if len(m.failures) == 0 {
		t.Fatal("expected failure entries after flood")
	}
	// Advance well past window + cooldown and GC.
	m.gcStale(base + 1000)
	if len(m.failures) != 0 || len(m.users) != 0 || len(m.lastAlert) != 0 {
		t.Fatalf("gcStale left entries: failures=%d users=%d lastAlert=%d",
			len(m.failures), len(m.users), len(m.lastAlert))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [3]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

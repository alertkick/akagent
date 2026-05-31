//go:build linux

package ebpf

import "testing"

func TestDirMatchAny(t *testing.T) {
	dirs := []string{"/etc", "/usr/bin", "/home/*/.ssh"}
	cases := map[string]bool{
		"/etc":                          true,  // exact dir
		"/etc/passwd":                   true,  // descendant
		"/etcfoo":                       false, // prefix must be at a boundary
		"/usr/bin/sshd":                 true,
		"/usr/binary":                   false,
		"/home/bob/.ssh/authorized_keys": true, // glob ancestor match
		"/home/bob/projects/file":       false,
		"/var/log/x":                    false,
	}
	for path, want := range cases {
		if got := dirMatchAny(path, dirs); got != want {
			t.Errorf("dirMatchAny(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestFileMatchAny(t *testing.T) {
	files := []string{"/etc/shadow", "/etc/sudoers.d/*", "/home/*/.ssh/id_*"}
	cases := map[string]bool{
		"/etc/shadow":            true,
		"/etc/shadow-":           false,
		"/etc/sudoers.d/myrule":  true,
		"/etc/sudoers":           false,
		"/home/bob/.ssh/id_rsa":  true,
		"/home/bob/.ssh/known_hosts": false,
	}
	for path, want := range cases {
		if got := fileMatchAny(path, files); got != want {
			t.Errorf("fileMatchAny(%q) = %v, want %v", path, got, want)
		}
	}
}

// fileEvent builds a minimal file SecurityEvent for scoping tests.
func fileEvent(path, op string, flags uint64) SecurityEvent {
	return SecurityEvent{
		Category:  "file",
		Rule:      "File Open",
		File:      FileInfo{Path: path, Operation: op},
		RawFields: map[string]interface{}{"filename": path, "flags": flags},
	}
}

func scopedFilter() *EventFilter {
	cfg := DefaultNativeConfig()
	cfg.EnableFile = true
	cfg.EnableProcess = true
	return NewEventFilter(&cfg)
}

func TestFileScoping(t *testing.T) {
	f := scopedFilter()
	const oWRONLY = 0x1

	cases := []struct {
		name  string
		event SecurityEvent
		want  bool
	}{
		{"write under /etc emitted", fileEvent("/etc/passwd", "open", oWRONLY), true},
		{"create under /usr/bin emitted", fileEvent("/usr/bin/evil", "open", 0x40), true},
		{"unlink under /etc emitted", fileEvent("/etc/cron.d/job", "unlink", 0), true},
		{"read of /etc dropped", fileEvent("/etc/passwd", "open", 0), false},
		{"read of /etc/shadow emitted", fileEvent("/etc/shadow", "open", 0), true},
		{"read of ssh key emitted", fileEvent("/home/bob/.ssh/id_rsa", "open", 0), true},
		{"write outside watch-set dropped", fileEvent("/var/lib/app/data", "open", oWRONLY), false},
		{"read outside watch-set dropped", fileEvent("/tmp/scratch", "open", 0), false},
	}
	for _, c := range cases {
		e := c.event
		if got := f.ShouldInclude(&e); got != c.want {
			t.Errorf("%s: ShouldInclude = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSignalScoping(t *testing.T) {
	f := scopedFilter()
	signalEvent := func(sig int) SecurityEvent {
		return SecurityEvent{
			Category:  "process",
			Rule:      "Process Signal",
			RawFields: map[string]interface{}{"sig": uint32(sig)},
		}
	}
	cases := map[int]bool{
		9:  true,  // SIGKILL
		15: true,  // SIGTERM
		2:  true,  // SIGINT
		17: false, // SIGCHLD
		28: false, // SIGWINCH
		0:  false, // liveness probe
	}
	for sig, want := range cases {
		e := signalEvent(sig)
		if got := f.ShouldInclude(&e); got != want {
			t.Errorf("signal %d: ShouldInclude = %v, want %v", sig, got, want)
		}
	}
}

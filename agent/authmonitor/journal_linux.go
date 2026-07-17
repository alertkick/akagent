//go:build linux

package authmonitor

import (
	"bufio"
	"context"
	"os/exec"
	"time"
)

// journalUnits are the journal _COMM values we follow: classic sshd, the
// OpenSSH 9.8+ per-connection "sshd-session" process (which logs the
// "Failed password" lines on modern distros), and sudo. Filtering by _COMM
// (a trusted, kernel-set field) keeps the followed stream small instead of
// parsing the whole journal firehose, while still catching every sshd variant.
var journalUnits = []string{"_COMM=sshd", "_COMM=sshd-session", "_COMM=sudo"}

// startJournalSource launches a goroutine that follows the systemd journal for
// auth failures when no auth-log file exists. Returns false (so Start reports
// no source) when journalctl is not installed.
func (m *Monitor) startJournalSource() bool {
	if _, err := exec.LookPath(m.journalctlPath()); err != nil {
		return false
	}
	go m.followJournal()
	return true
}

func (m *Monitor) journalctlPath() string {
	if m.cfg.JournalctlPath != "" {
		return m.cfg.JournalctlPath
	}
	return "journalctl"
}

// followJournal runs `journalctl -f` and feeds each rendered line into
// processLine, restarting the subprocess with a short backoff if it exits
// (journal rotation, transient error) until Stop() closes m.stop.
func (m *Monitor) followJournal() {
	for {
		select {
		case <-m.stop:
			return
		default:
		}

		ctx, cancel := context.WithCancel(context.Background())
		// Terminate journalctl promptly when Stop() fires.
		go func() {
			select {
			case <-m.stop:
				cancel()
			case <-ctx.Done():
			}
		}()
		m.runJournalctl(ctx)
		cancel()

		// Back off before restarting so a persistently-failing journalctl
		// (e.g. missing permissions) can't spin the CPU.
		select {
		case <-m.stop:
			return
		case <-time.After(time.Duration(m.cfg.PollSeconds) * time.Second):
		}
	}
}

// runJournalctl streams one journalctl -f invocation into processLine. It
// returns when the process exits or ctx is cancelled.
func (m *Monitor) runJournalctl(ctx context.Context) {
	// -o short renders the classic "Mon DD HH:MM:SS host ident[pid]: msg"
	// syslog line, so the same sshFail/sudoFail regexes that parse
	// /var/log/auth.log match journal lines unchanged. -n 0 suppresses the
	// backlog so an agent restart never replays (and re-counts) old failures.
	args := append([]string{"-f", "-o", "short", "-n", "0"}, journalUnits...)
	cmd := exec.CommandContext(ctx, m.journalctlPath(), args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}
	scanner := bufio.NewScanner(stdout)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		m.processLine(scanner.Text(), time.Now().Unix())
	}
	_ = cmd.Wait()
}

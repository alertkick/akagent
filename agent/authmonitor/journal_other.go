//go:build !linux

package authmonitor

// startJournalSource is a no-op on non-Linux platforms: the systemd journal
// fallback exists only where journalctl does. Start reports no source, matching
// the historical no-op behaviour on hosts without an auth-log file.
func (m *Monitor) startJournalSource() bool { return false }

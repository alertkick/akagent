//go:build linux

package agent

import (
	"akagent/client"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// embeddedUpdaterScript is the canonical updater shipped inside the agent
// binary. Used as a fallback when the on-disk script at updaterScriptPath
// is missing — e.g. an agent that was installed from a package that
// pre-dates updater-script shipping (anything before v1.6.4). The .deb
// and .rpm install this same file at updaterScriptPath, so on-disk and
// embedded are bit-for-bit identical.
//
//go:embed scripts/updater.sh
var embeddedUpdaterScript []byte

const (
	updaterScriptPath = "/usr/local/bin/alertkick-agent-updater.sh"
	downloadDir       = "/var/lib/alertkick-agent/updates"
)

// handleUpdateAgentRequest handles the update_agent command from the server.
// It downloads the new package, verifies its checksum, and launches the updater
// script which will stop the agent service, install the package, and restart.
func (a *agent) handleUpdateAgentRequest(req client.Request) {
	a.log.Info().Msg("agent.handleUpdateAgentRequest - received update_agent request")

	// Parse params
	var params updateAgentParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		a.log.Err(err).Msg("agent.handleUpdateAgentRequest - failed to parse params")
		a.sendUpdateProgress(req, "failed", "Failed to parse update parameters: "+err.Error(), 0, "failed")
		return
	}

	a.log.Info().
		Str("target_version", params.TargetVersion).
		Str("download_url", params.DownloadURL).
		Msg("agent.handleUpdateAgentRequest - starting update")

	// Reject server-supplied values that would let a compromised/misconfigured
	// endpoint write outside the download directory or fetch over plain HTTP.
	if !targetVersionRE.MatchString(params.TargetVersion) {
		msg := "Invalid target_version: must match " + targetVersionRE.String()
		a.log.Error().Str("target_version", params.TargetVersion).Msg("agent.handleUpdateAgentRequest - " + msg)
		a.sendUpdateProgress(req, "failed", msg, 0, "failed")
		return
	}
	if u, err := url.Parse(params.DownloadURL); err != nil || u.Scheme != "https" || u.Host == "" {
		msg := "Invalid download_url: must be an https:// URL"
		a.log.Error().Str("download_url", params.DownloadURL).Msg("agent.handleUpdateAgentRequest - " + msg)
		a.sendUpdateProgress(req, "failed", msg, 0, "failed")
		return
	}
	if params.Checksum == "" {
		msg := "Missing checksum: package updates require a sha256 checksum"
		a.log.Error().Msg("agent.handleUpdateAgentRequest - " + msg)
		a.sendUpdateProgress(req, "failed", msg, 0, "failed")
		return
	}

	// Send pending progress
	a.sendUpdateProgress(req, "pending", "Update command received, preparing to download", 10, "in_progress")

	// Create download directory
	if err := os.MkdirAll(downloadDir, 0755); err != nil {
		a.log.Err(err).Msg("agent.handleUpdateAgentRequest - failed to create download directory")
		a.sendUpdateProgress(req, "failed", "Failed to create download directory: "+err.Error(), 0, "failed")
		return
	}

	// Download the package
	a.sendUpdateProgress(req, "downloading", "Downloading agent package...", 30, "in_progress")

	packageFilename := fmt.Sprintf("alertkick-agent-%s.deb", params.TargetVersion)
	packagePath := filepath.Join(downloadDir, packageFilename)

	if err := a.downloadPackage(params.DownloadURL, packagePath); err != nil {
		a.log.Err(err).Msg("agent.handleUpdateAgentRequest - failed to download package")
		a.sendUpdateProgress(req, "failed", "Failed to download package: "+err.Error(), 0, "failed")
		os.Remove(packagePath)
		return
	}

	a.log.Info().Str("path", packagePath).Msg("agent.handleUpdateAgentRequest - package downloaded")

	// Verify checksum (mandatory — enforced at request entry).
	a.sendUpdateProgress(req, "downloading", "Verifying package checksum...", 45, "in_progress")

	actualChecksum, err := computeFileChecksum(packagePath)
	if err != nil {
		a.log.Err(err).Msg("agent.handleUpdateAgentRequest - failed to compute checksum")
		a.sendUpdateProgress(req, "failed", "Failed to verify package checksum: "+err.Error(), 0, "failed")
		os.Remove(packagePath)
		return
	}

	expectedChecksum := params.Checksum
	if _, after, ok := strings.Cut(expectedChecksum, ":"); ok {
		expectedChecksum = after
	}

	if actualChecksum != expectedChecksum {
		msg := fmt.Sprintf("Checksum mismatch: expected %s, got %s", params.Checksum, actualChecksum)
		a.log.Error().Msg("agent.handleUpdateAgentRequest - " + msg)
		a.sendUpdateProgress(req, "failed", msg, 0, "failed")
		os.Remove(packagePath)
		return
	}

	a.log.Info().Msg("agent.handleUpdateAgentRequest - checksum verified")

	// Send installing progress
	a.sendUpdateProgress(req, "installing", "Installing agent package...", 60, "in_progress")

	// Resolve which updater script to exec. Prefer the on-disk script
	// installed by the .deb/.rpm; fall back to the embedded copy when the
	// installed package pre-dates updater-script shipping (anything before
	// v1.6.4). The embedded copy is the same source file the package ships.
	scriptPath, err := resolveUpdaterScript()
	if err != nil {
		a.log.Err(err).Msg("agent.handleUpdateAgentRequest - updater script unavailable")
		a.sendUpdateProgress(req, "failed", "Updater script unavailable: "+err.Error(), 0, "failed")
		os.Remove(packagePath)
		return
	}

	// Launch the updater script. It stops our service, installs the new .deb,
	// and starts us again. The catch: stopping our service also tears down our
	// cgroup, and systemd's default KillMode=control-group would SIGTERM every
	// process in it — the updater included — before it can reinstall us. A new
	// process group (Setpgid) does NOT escape the cgroup, so that isn't enough.
	//
	// Run the updater as a transient systemd unit instead. systemd-run reparents
	// it under PID 1 in its own cgroup, so `systemctl stop alertkick-agent` can't
	// reach it. Fall back to a bare detached exec on hosts without systemd-run.
	var cmd *exec.Cmd
	if runner, lookErr := exec.LookPath("systemd-run"); lookErr == nil {
		cmd = exec.Command(runner,
			"--collect",
			"--unit", fmt.Sprintf("alertkick-agent-update-%d", time.Now().Unix()),
			"--description", "AlertKick agent self-update",
			scriptPath, "--package", packagePath, "--current-version", a.version)
	} else {
		a.log.Warn().Msg("agent.handleUpdateAgentRequest - systemd-run not found, falling back to detached exec (update may be killed with our cgroup)")
		cmd = exec.Command(scriptPath, "--package", packagePath, "--current-version", a.version)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		a.log.Err(err).Msg("agent.handleUpdateAgentRequest - failed to start updater script")
		a.sendUpdateProgress(req, "failed", "Failed to start updater script: "+err.Error(), 0, "failed")
		os.Remove(packagePath)
		return
	}

	a.log.Info().Int("pid", cmd.Process.Pid).Msg("agent.handleUpdateAgentRequest - updater script launched")

	// Send restarting progress - this may be the last message we send before being killed
	a.sendUpdateProgress(req, "restarting", "Agent service is being restarted with new version", 85, "in_progress")

	// Release the process so it isn't waited on by our process
	cmd.Process.Release()
}

// resolveUpdaterScript returns a path to a runnable updater script.
// Prefers the on-disk script at updaterScriptPath; if missing, writes the
// embedded fallback to a private temp file (0755) and returns that path.
//
// Why the fallback exists: older agent packages (< v1.6.4) did not ship
// scripts/alertkick-agent-updater.sh, so a fresh `update_agent` command
// against an old install would fail with "updater script not found" and
// leave the host unable to upgrade itself. Embedding the script in the
// binary lets the running agent self-bootstrap regardless of what its
// installer left on disk.
func resolveUpdaterScript() (string, error) {
	if _, err := os.Stat(updaterScriptPath); err == nil {
		return updaterScriptPath, nil
	}

	if len(embeddedUpdaterScript) == 0 {
		// Should never happen — embed guarantees a non-empty file at
		// build time. Surfaced explicitly so a stripped/tampered binary
		// reports something better than "permission denied".
		return "", fmt.Errorf("updater script missing on disk and no embedded fallback available")
	}

	// Write to a private temp file. Caller execs it as a detached
	// process; the script's own cleanup at the end of a successful run
	// leaves this temp file around, which is fine — /tmp is reaped on
	// reboot and the next update will produce a fresh copy anyway.
	f, err := os.CreateTemp("", "alertkick-agent-updater-*.sh")
	if err != nil {
		return "", fmt.Errorf("create temp script: %w", err)
	}
	if _, err := f.Write(embeddedUpdaterScript); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", fmt.Errorf("write temp script: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("close temp script: %w", err)
	}
	if err := os.Chmod(f.Name(), 0o755); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("chmod temp script: %w", err)
	}
	return f.Name(), nil
}

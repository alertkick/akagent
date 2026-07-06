//go:build windows

package agent

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"akagent/client"
)

// Windows self-update. Unlike Linux (which hands off to a package manager via
// an updater script), Windows can't overwrite or delete the running exe — but
// it CAN rename it. So the update is: download+verify the zip, extract the new
// exe next to the current one under a temp name, rename the running exe aside,
// move the new exe into place, then have a detached helper restart the
// service. The service restart re-launches the new exe; the renamed old exe is
// cleaned up on the next start.
const windowsServiceName = "AlertKickAgent"

func windowsInstallDir() string {
	// The service binary lives here (set by the install script). Fall back to
	// the running executable's directory.
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe)
	}
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "AlertKick")
}

func windowsDownloadDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "AlertKick", "updates")
}

// handleUpdateAgentRequest performs a Windows self-update from a zip package.
func (a *agent) handleUpdateAgentRequest(req client.Request) {
	a.log.Info().Msg("agent.handleUpdateAgentRequest - received update_agent request (windows)")

	var params updateAgentParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		a.log.Err(err).Msg("agent.handleUpdateAgentRequest - failed to parse params")
		a.sendUpdateProgress(req, "failed", "Failed to parse update parameters", 0, "failed")
		return
	}

	if !targetVersionRE.MatchString(params.TargetVersion) {
		msg := "Invalid target_version: must match " + targetVersionRE.String()
		a.log.Error().Str("target_version", params.TargetVersion).Msg("agent.handleUpdateAgentRequest - " + msg)
		a.sendUpdateProgress(req, "failed", msg, 0, "failed")
		return
	}
	if params.DownloadURL == "" || params.Checksum == "" {
		a.sendUpdateProgress(req, "failed", "download_url and checksum are required", 0, "failed")
		return
	}

	a.sendUpdateProgress(req, "pending", "Update command received, preparing to download", 10, "in_progress")

	dlDir := windowsDownloadDir()
	if err := os.MkdirAll(dlDir, 0o755); err != nil {
		a.sendUpdateProgress(req, "failed", "Failed to create download directory: "+err.Error(), 0, "failed")
		return
	}

	a.sendUpdateProgress(req, "downloading", "Downloading agent package...", 30, "in_progress")
	zipPath := filepath.Join(dlDir, fmt.Sprintf("alertkick-agent-%s.zip", params.TargetVersion))
	if err := a.downloadPackage(params.DownloadURL, zipPath); err != nil {
		a.sendUpdateProgress(req, "failed", "Failed to download package: "+err.Error(), 0, "failed")
		os.Remove(zipPath)
		return
	}

	a.sendUpdateProgress(req, "downloading", "Verifying package checksum...", 45, "in_progress")
	actual, err := computeFileChecksum(zipPath)
	if err != nil {
		a.sendUpdateProgress(req, "failed", "Failed to verify checksum: "+err.Error(), 0, "failed")
		os.Remove(zipPath)
		return
	}
	expected := params.Checksum
	if _, after, ok := strings.Cut(expected, ":"); ok {
		expected = after
	}
	if !strings.EqualFold(actual, expected) {
		a.sendUpdateProgress(req, "failed", fmt.Sprintf("Checksum mismatch: expected %s, got %s", expected, actual), 0, "failed")
		os.Remove(zipPath)
		return
	}

	a.sendUpdateProgress(req, "installing", "Installing new agent binary...", 60, "in_progress")
	installDir := windowsInstallDir()
	newExe, err := extractAgentExe(zipPath, dlDir)
	if err != nil {
		a.sendUpdateProgress(req, "failed", "Failed to extract package: "+err.Error(), 0, "failed")
		os.Remove(zipPath)
		return
	}

	if err := swapAgentExe(installDir, newExe); err != nil {
		a.sendUpdateProgress(req, "failed", "Failed to install new binary: "+err.Error(), 0, "failed")
		return
	}

	a.sendUpdateProgress(req, "restarting", "Restarting service with new version", 85, "in_progress")
	if err := scheduleServiceRestart(); err != nil {
		// The binary is already swapped, so a manual/next-boot restart will
		// still pick it up; report but don't hard-fail.
		a.log.Err(err).Msg("agent.handleUpdateAgentRequest - failed to schedule service restart")
		a.sendUpdateProgress(req, "restarting", "New binary installed; restart could not be scheduled automatically", 90, "in_progress")
		return
	}
	a.log.Info().Msg("agent.handleUpdateAgentRequest - service restart scheduled; new version will start shortly")
}

// extractAgentExe pulls alertkick-agent.exe out of the zip into dstDir under a
// temporary name and returns its path.
func extractAgentExe(zipPath, dstDir string) (string, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", err
	}
	defer zr.Close()

	for _, f := range zr.File {
		if !strings.EqualFold(filepath.Base(f.Name), "alertkick-agent.exe") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", err
		}
		defer rc.Close()

		dst := filepath.Join(dstDir, "alertkick-agent.exe.new")
		out, err := os.Create(dst)
		if err != nil {
			return "", err
		}
		// Cap extraction so a malicious oversized entry can't fill the disk.
		// 200 MB is far above any real agent binary.
		const maxBytes = 200 << 20
		if _, err := io.Copy(out, io.LimitReader(rc, maxBytes)); err != nil {
			out.Close()
			os.Remove(dst)
			return "", err
		}
		out.Close()
		return dst, nil
	}
	return "", fmt.Errorf("alertkick-agent.exe not found in package")
}

// swapAgentExe renames the running exe aside and moves the new one into place.
// A running Windows exe can be renamed but not deleted, so the old file is left
// as *.old and cleaned up opportunistically on the next start.
func swapAgentExe(installDir, newExe string) error {
	target := filepath.Join(installDir, "alertkick-agent.exe")
	old := target + ".old"

	// Remove a stale .old from a previous update if the process no longer
	// holds it (best-effort).
	_ = os.Remove(old)

	if _, err := os.Stat(target); err == nil {
		if err := os.Rename(target, old); err != nil {
			return fmt.Errorf("rename running exe: %w", err)
		}
	}
	if err := os.Rename(newExe, target); err != nil {
		// Try to roll back the rename so the service can still start.
		_ = os.Rename(old, target)
		return fmt.Errorf("move new exe into place: %w", err)
	}
	return nil
}

// scheduleServiceRestart launches a detached cmd.exe that waits briefly, then
// stops and starts our service. It must be detached and outside our process
// tree because stopping the service kills this process before the restart
// completes. `net stop`/`net start` drive the SCM directly.
func scheduleServiceRestart() error {
	// timeout waits ~3s (gives this handler time to send its last progress
	// message), then restart the service.
	script := fmt.Sprintf(
		"timeout /t 3 /nobreak >nul & net stop %s >nul 2>&1 & net start %s >nul 2>&1",
		windowsServiceName, windowsServiceName)

	cmd := exec.Command("cmd.exe", "/C", script)
	// DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP so the helper survives our
	// exit and isn't in our console/process group.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x00000008 | 0x00000200,
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	// Release so we don't wait on it (we're about to be stopped anyway).
	return cmd.Process.Release()
}

//go:build linux

package agent

import (
	"apagent/client"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const (
	updaterScriptPath = "/usr/local/bin/alertpriority-agent-updater.sh"
	downloadDir       = "/var/lib/alertpriority-agent/updates"
)

// updateAgentParams mirrors the command params sent from the API
type updateAgentParams struct {
	TargetVersion string `json:"target_version"`
	DownloadURL   string `json:"download_url"`
	Checksum      string `json:"checksum"`
}

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

	packageFilename := fmt.Sprintf("alertpriority-agent-%s.deb", params.TargetVersion)
	packagePath := filepath.Join(downloadDir, packageFilename)

	if err := a.downloadPackage(params.DownloadURL, packagePath); err != nil {
		a.log.Err(err).Msg("agent.handleUpdateAgentRequest - failed to download package")
		a.sendUpdateProgress(req, "failed", "Failed to download package: "+err.Error(), 0, "failed")
		os.Remove(packagePath)
		return
	}

	a.log.Info().Str("path", packagePath).Msg("agent.handleUpdateAgentRequest - package downloaded")

	// Verify checksum if provided
	if params.Checksum != "" {
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
	}

	// Send installing progress
	a.sendUpdateProgress(req, "installing", "Installing agent package...", 60, "in_progress")

	// Verify updater script exists
	if _, err := os.Stat(updaterScriptPath); os.IsNotExist(err) {
		a.log.Err(err).Msg("agent.handleUpdateAgentRequest - updater script not found")
		a.sendUpdateProgress(req, "failed", "Updater script not found at "+updaterScriptPath, 0, "failed")
		os.Remove(packagePath)
		return
	}

	// Launch the updater script as a detached process.
	// The script will: stop the agent service, install the new .deb, and restart.
	// Since the script stops our service, our process will be killed during the update.
	// We run it in a new process group so it survives our termination.
	cmd := exec.Command(updaterScriptPath, "--package", packagePath, "--current-version", a.version)
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

// sendUpdateProgress sends a progress update response back to the server
func (a *agent) sendUpdateProgress(req client.Request, stage, message string, percent int, status string) {
	progress := client.UpdateAgentProgressResponse{
		Stage:   stage,
		Message: message,
		Percent: percent,
		Status:  status,
	}

	msg := client.Response{
		Version:       "1",
		ID:            req.ID,
		Target:        "agent.update_agent",
		Source:        a.AgentID,
		Tenant:        a.Subdomain,
		Subdomain:     a.Subdomain,
		Result:        json.RawMessage(progress.String()),
		CorrelationID: req.CorrelationID,
	}

	if err := a.conn.SendJSONMessageNoResponse(msg); err != nil {
		a.log.Err(err).Str("stage", stage).Msg("agent.sendUpdateProgress - failed to send progress")
	}

	// Small delay to allow the message to be sent before the next one
	time.Sleep(100 * time.Millisecond)
}

// downloadPackage downloads a file from the given URL to destPath
func (a *agent) downloadPackage(url, destPath string) error {
	a.log.Info().Str("url", url).Str("dest", destPath).Msg("agent.downloadPackage - starting download")

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with HTTP status %d", resp.StatusCode)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()

	written, err := io.Copy(out, resp.Body)
	if err != nil {
		os.Remove(destPath)
		return fmt.Errorf("failed to write file: %w", err)
	}

	a.log.Info().Int64("bytes", written).Msg("agent.downloadPackage - download complete")
	return nil
}

// computeFileChecksum computes the SHA256 checksum of a file
func computeFileChecksum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

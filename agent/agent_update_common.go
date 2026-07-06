package agent

import (
	"akagent/client"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"time"
)

// targetVersionRE restricts TargetVersion to a safe filename charset so the
// server-supplied value can be interpolated into a path. Anything with `/`,
// `\`, `..`, or other shell-meaningful characters is rejected.
var targetVersionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// updateAgentParams mirrors the command params sent from the API
type updateAgentParams struct {
	TargetVersion string `json:"target_version"`
	DownloadURL   string `json:"download_url"`
	Checksum      string `json:"checksum"`
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

// downloadPackage downloads a file from the given URL to destPath.
// A whole-request timeout caps how long a hostile or slow endpoint can stall
// the agent — 10 min is generous for the small (~tens of MB) agent packages.
func (a *agent) downloadPackage(url, destPath string) error {
	a.log.Info().Str("url", url).Str("dest", destPath).Msg("agent.downloadPackage - starting download")

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(url)
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

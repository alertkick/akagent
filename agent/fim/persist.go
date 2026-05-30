package fim

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// DefaultBaselinePath is where the agent persists the FIM baseline across
// restarts so it doesn't have to re-hash the whole filesystem on every boot.
const DefaultBaselinePath = "/var/lib/alertkick-agent/fim-baseline.json"

// LoadBaseline reads a persisted Baseline from path. A missing or empty file is
// the fresh-install case: returns (nil, nil) so the caller knows to do an
// initial scan. Filesystem and JSON errors are returned.
func LoadBaseline(path string) (Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return b, nil
}

// SaveBaseline writes the Baseline atomically (temp file + rename) so a crash
// mid-write can't leave a half-written file that fails to parse on next boot.
// The parent dir is created 0o700 and the file 0o600 — the baseline reveals
// the layout of every system binary and config, so a non-root reader has no
// business with it.
func SaveBaseline(path string, b Baseline) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".fim-baseline-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

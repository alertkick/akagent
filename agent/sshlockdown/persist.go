package sshlockdown

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// DefaultStatePath is where the agent persists its lockdown State across
// restarts. Survives crashes; on startup the manager reloads from this
// file before contacting the control plane. Path is fixed (not config)
// because if you change it, an old agent build leaves a state file
// behind and the new one boots with a fresh default posture, silently
// discarding a lock an operator intentionally enabled. (A pre-posture
// state file has no lock_enabled field, so upgraded agents boot unlocked
// — the intended default — until the API pushes the stored posture.)
const DefaultStatePath = "/var/lib/akagent/lockdown.json"

// LoadState reads a persisted State from path. Returns (zero State, nil)
// when the file doesn't exist — that's the fresh-install case, not an
// error. Returns an error only for filesystem failures and malformed
// JSON; the manager treats either as "trust the control plane" and
// keeps the current in-memory state.
func LoadState(path string) (State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{}, nil
		}
		return State{}, err
	}
	if len(data) == 0 {
		return State{}, nil
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return State{}, err
	}
	return s, nil
}

// SaveState writes State atomically — temp file + rename — so a crash
// mid-write can't leave a half-written lockdown.json that fails to
// parse on the next boot. Atomic rename also means a concurrent reader
// either sees the old or the new state, never a partial one.
//
// The parent directory is created with mode 0o700 if it doesn't yet
// exist; the state file itself is 0o600 because it contains the
// authoritative answer to "is SSH allowed right now" and a non-root
// reader has no business knowing.
func SaveState(path string, s State) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".lockdown-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// On any failure after CreateTemp we remove the temp file — leaving
	// stray ".lockdown-*.json" files in /var/lib/akagent would slowly
	// fill the dir and the next operator would spend twenty minutes
	// figuring out where they came from.
	defer func() {
		_ = os.Remove(tmpName)
	}()

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

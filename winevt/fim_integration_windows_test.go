//go:build windows

package winevt

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestFIMPipeline proves the Windows FIM path end-to-end: fsnotify
// (ReadDirectoryChangesW) → fim.Manager debounce/re-hash → emitted
// SecurityEvent. It watches a temp directory with a pre-existing file
// (so a baseline is built), modifies the file, and asserts a file-integrity
// event surfaces on the collector channel.
func TestFIMPipeline(t *testing.T) {
	if testing.Short() {
		t.Skip("FIM integration test does real filesystem watching; run in the dedicated CI step")
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "watched.txt")
	if err := os.WriteFile(target, []byte("original\n"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	c := NewCollector(100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Point the watcher at the temp dir instead of the default Windows paths.
	c.startFIM(ctx, []string{dir})

	// The baseline scan runs async; for a one-file temp dir it completes
	// almost immediately, but give it a moment before mutating.
	time.Sleep(2 * time.Second)

	// Modify the watched file — this should trip the integrity check.
	if err := os.WriteFile(target, []byte("tampered by test\n"), 0o644); err != nil {
		t.Fatalf("modify file: %v", err)
	}

	ch := c.EventChannel()
	deadline := time.After(20 * time.Second)
	for {
		select {
		case ev := <-ch:
			if ev.Category == "file" && ev.File.Path == target {
				if ev.Rule != "File Integrity Violation" && ev.Rule != "Expected File Change" {
					t.Fatalf("unexpected FIM rule: %q", ev.Rule)
				}
				return // success
			}
		case <-deadline:
			t.Fatal("no file-integrity event observed within timeout")
		}
	}
}

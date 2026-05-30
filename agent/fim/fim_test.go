package fim

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func newTestManager(t *testing.T, dir string, suppress bool) (*Manager, *[]Change, *[]Change) {
	t.Helper()
	var changes, expected []Change
	cfg := Config{
		Paths:          []string{dir},
		HashAlgo:       "sha256",
		SuppressPkgMgr: suppress,
		DebounceMs:     20,
		StatePath:      filepath.Join(dir, ".baseline.json"),
	}
	m := New(cfg,
		func(c Change) { changes = append(changes, c) },
		func(c Change) { expected = append(expected, c) },
	)
	return m, &changes, &expected
}

func TestScanAndFastPath(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a"), "alpha")
	write(t, filepath.Join(dir, "b"), "bravo")
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "sub", "c"), "charlie")

	b := Scan([]string{dir}, nil, "sha256", nil)
	if len(b) != 3 {
		t.Fatalf("expected 3 files, got %d", len(b))
	}
	// Fast-path: rescan with prev — unchanged files keep the same Entry.
	b2 := Scan([]string{dir}, nil, "sha256", b)
	for p, e := range b {
		if b2[p] != e {
			t.Fatalf("fast-path changed entry for %s", p)
		}
	}
	// Exclusion drops a file.
	bEx := Scan([]string{dir}, []string{filepath.Join(dir, "b")}, "sha256", nil)
	if _, ok := bEx[filepath.Join(dir, "b")]; ok {
		t.Fatal("excluded file should not be in baseline")
	}
}

func TestCheckModifiedAddedRemoved(t *testing.T) {
	dir := t.TempDir()
	fileA := filepath.Join(dir, "a")
	write(t, fileA, "v1")
	m, changes, _ := newTestManager(t, dir, false)
	m.Rebaseline()

	// Modified
	write(t, fileA, "v2")
	m.CheckNow(fileA, Trigger{Comm: "vim"})
	if len(*changes) != 1 || (*changes)[0].Kind != KindModified {
		t.Fatalf("expected 1 modified change, got %+v", *changes)
	}
	if (*changes)[0].OldHash == "" || (*changes)[0].NewHash == "" || (*changes)[0].OldHash == (*changes)[0].NewHash {
		t.Fatalf("expected distinct old/new hashes, got %+v", (*changes)[0])
	}

	// De-dupe: same content again → no new emission.
	m.CheckNow(fileA, Trigger{Comm: "vim"})
	if len(*changes) != 1 {
		t.Fatalf("expected de-dupe, got %d changes", len(*changes))
	}

	// Added
	fileNew := filepath.Join(dir, "new")
	write(t, fileNew, "x")
	m.CheckNow(fileNew, Trigger{Comm: "touch"})
	if last := (*changes)[len(*changes)-1]; last.Kind != KindAdded {
		t.Fatalf("expected added, got %s", last.Kind)
	}

	// Removed
	if err := os.Remove(fileA); err != nil {
		t.Fatal(err)
	}
	m.CheckNow(fileA, Trigger{Comm: "rm"})
	if last := (*changes)[len(*changes)-1]; last.Kind != KindRemoved {
		t.Fatalf("expected removed, got %s", last.Kind)
	}
}

func TestPkgMgrSuppression(t *testing.T) {
	dir := t.TempDir()
	fileA := filepath.Join(dir, "a")
	write(t, fileA, "v1")
	m, changes, expected := newTestManager(t, dir, true)
	m.Rebaseline()

	write(t, fileA, "v2")
	m.CheckNow(fileA, Trigger{Comm: "bash", Ancestry: []string{"dpkg", "apt"}})
	if len(*changes) != 0 {
		t.Fatalf("pkg-mgr change should be suppressed, got %+v", *changes)
	}
	if len(*expected) != 1 || !(*expected)[0].PkgMgrAttributed {
		t.Fatalf("expected one suppressed/audit change, got %+v", *expected)
	}
	// Suppressed change re-baselined: a further identical check is a no-op.
	m.CheckNow(fileA, Trigger{Comm: "cat"})
	if len(*changes) != 0 {
		t.Fatalf("re-baselined path should not now flag, got %+v", *changes)
	}
}

func TestApproveClearsFinding(t *testing.T) {
	dir := t.TempDir()
	fileA := filepath.Join(dir, "a")
	write(t, fileA, "v1")
	m, changes, _ := newTestManager(t, dir, false)
	m.Rebaseline()

	write(t, fileA, "v2")
	m.CheckNow(fileA, Trigger{Comm: "vim"})
	if len(*changes) != 1 {
		t.Fatalf("expected a finding, got %d", len(*changes))
	}
	// Operator approves: current content becomes the new baseline.
	m.ApprovePaths([]string{fileA})
	m.CheckNow(fileA, Trigger{Comm: "vim"})
	if len(*changes) != 1 {
		t.Fatalf("approved path should not re-flag, got %d", len(*changes))
	}
}

func TestPersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	b := Baseline{"/usr/bin/x": {Hash: "abc", Size: 10, MtimeNs: 123}}
	if err := SaveBaseline(path, b); err != nil {
		t.Fatal(err)
	}
	got, err := LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	if got["/usr/bin/x"] != b["/usr/bin/x"] {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	// Missing file → (nil, nil).
	if got, err := LoadBaseline(filepath.Join(dir, "nope.json")); err != nil || got != nil {
		t.Fatalf("missing file should be (nil,nil), got %+v %v", got, err)
	}
}

func TestNotifyDebounce(t *testing.T) {
	dir := t.TempDir()
	fileA := filepath.Join(dir, "a")
	write(t, fileA, "v1")
	done := make(chan Change, 4)
	cfg := Config{Paths: []string{dir}, HashAlgo: "sha256", DebounceMs: 30, StatePath: filepath.Join(dir, ".b.json")}
	m := New(cfg, func(c Change) { done <- c }, nil)
	m.Rebaseline()

	write(t, fileA, "v2")
	// Burst of notifies for the same path should collapse into one re-check.
	for i := 0; i < 5; i++ {
		m.Notify(fileA, Trigger{Comm: "vim"})
		time.Sleep(3 * time.Millisecond)
	}
	select {
	case c := <-done:
		if c.Kind != KindModified {
			t.Fatalf("expected modified, got %s", c.Kind)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("debounced check never fired")
	}
	// No second emission for the same change.
	select {
	case c := <-done:
		t.Fatalf("unexpected second emission: %+v", c)
	case <-time.After(120 * time.Millisecond):
	}
}

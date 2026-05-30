package rootkitscan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindHiddenModules(t *testing.T) {
	proc := map[string]bool{"ext4": true, "nf_tables": true}
	sys := []string{"ext4", "nf_tables", "evil_rk"}
	hidden := findHiddenModules(proc, sys)
	if len(hidden) != 1 || hidden[0] != "evil_rk" {
		t.Fatalf("expected [evil_rk], got %v", hidden)
	}
	// Nothing hidden when sysfs and /proc/modules agree.
	if h := findHiddenModules(proc, []string{"ext4", "nf_tables"}); len(h) != 0 {
		t.Fatalf("expected no hidden modules, got %v", h)
	}
}

func TestFindHiddenPIDs(t *testing.T) {
	visible := map[int]bool{1: true, 100: true, 200: true}
	accessible := []int{1, 100, 200, 1337} // 1337 reachable but not in readdir
	hidden := findHiddenPIDs(visible, accessible)
	if len(hidden) != 1 || hidden[0] != 1337 {
		t.Fatalf("expected [1337], got %v", hidden)
	}
}

func TestReadSysLoadedModulesFiltersBuiltins(t *testing.T) {
	root := t.TempDir()
	// loadable module: has refcnt
	mkdir(t, filepath.Join(root, "evil_rk"))
	touch(t, filepath.Join(root, "evil_rk", "refcnt"))
	// built-in module: dir but no refcnt → must be ignored
	mkdir(t, filepath.Join(root, "builtin_thing"))

	loaded := readSysLoadedModules(root)
	if len(loaded) != 1 || loaded[0] != "evil_rk" {
		t.Fatalf("expected [evil_rk], got %v", loaded)
	}
}

func TestScanPreload(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ld.so.preload")
	s := New(Config{PreloadPath: p}, nil)

	// Absent → no finding.
	if _, ok := s.scanPreload(); ok {
		t.Fatal("expected no preload finding when file absent")
	}
	// Present with a lib → finding.
	if err := os.WriteFile(p, []byte("/usr/lib/evil.so\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	libs, ok := s.scanPreload()
	if !ok || libs != "/usr/lib/evil.so" {
		t.Fatalf("expected preload finding, got %q %v", libs, ok)
	}
}

func TestEmitDeDupe(t *testing.T) {
	var findings []Finding
	s := New(Config{}, func(f Finding) { findings = append(findings, f) })
	s.emit(Finding{Kind: KindHiddenModule, Detail: "evil_rk"})
	s.emit(Finding{Kind: KindHiddenModule, Detail: "evil_rk"}) // duplicate
	s.emit(Finding{Kind: KindHiddenModule, Detail: "other_rk"})
	if len(findings) != 2 {
		t.Fatalf("expected 2 unique findings, got %d", len(findings))
	}
}

func mkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func touch(t *testing.T, p string) {
	t.Helper()
	if err := os.WriteFile(p, []byte("0"), 0o644); err != nil {
		t.Fatal(err)
	}
}

package yarascan

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestParseYaraOutput(t *testing.T) {
	out := "Eicar_Test_File /tmp/sample\nMalware_XYZ /tmp/sample\nEicar_Test_File /tmp/sample\n"
	rules := parseYaraOutput(out)
	if len(rules) != 2 || rules[0] != "Eicar_Test_File" || rules[1] != "Malware_XYZ" {
		t.Fatalf("unexpected rules: %v", rules)
	}
	if len(parseYaraOutput("")) != 0 {
		t.Fatal("empty output should yield no rules")
	}
}

func TestUnavailableNoop(t *testing.T) {
	// No rules path → not available; ScanAsync must be a safe no-op.
	s := New(Config{}, func(Match) { t.Fatal("onMatch should not fire") })
	if s.Available() {
		t.Fatal("scanner should be unavailable without rules")
	}
	s.ScanAsync("/bin/sh")
}

func TestScanOneMatchAndDedupe(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules.yar")
	if err := os.WriteFile(rules, []byte("rule x {condition: true}"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "sample")
	if err := os.WriteFile(target, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var matches []Match
	s := New(Config{RulesPath: rules}, func(m Match) {
		mu.Lock()
		matches = append(matches, m)
		mu.Unlock()
	})
	// Force-enable and inject a fake yara that always reports a hit.
	s.available = true
	var runs int
	s.run = func(_, target string) (string, error) {
		runs++
		return "Malware_Test " + target + "\n", nil
	}

	s.scanOne(target)
	s.scanOne(target) // same mtime → de-duped, no second run
	if runs != 1 {
		t.Fatalf("expected one yara run after de-dupe, got %d", runs)
	}
	if len(matches) != 1 || len(matches[0].Rules) != 1 || matches[0].Rules[0] != "Malware_Test" {
		t.Fatalf("unexpected matches: %+v", matches)
	}

	// Modify the file → new mtime → scans again.
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(target, []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.scanOne(target)
	if runs != 2 {
		t.Fatalf("expected re-scan after mtime change, got %d runs", runs)
	}
}

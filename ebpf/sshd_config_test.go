//go:build linux

package ebpf

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseSSHDConfig_DefaultPortWhenMissing(t *testing.T) {
	path := writeTempConfig(t, "# nothing relevant here\nPermitRootLogin no\n")
	got, err := parseSSHDConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Ports, []int{22}) {
		t.Fatalf("ports = %v, want [22]", got.Ports)
	}
}

func TestParseSSHDConfig_SingleCustomPort(t *testing.T) {
	path := writeTempConfig(t, "Port 2222\n")
	got, err := parseSSHDConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Ports, []int{2222}) {
		t.Fatalf("ports = %v, want [2222]", got.Ports)
	}
}

func TestParseSSHDConfig_MultiplePortsSortedDeduped(t *testing.T) {
	path := writeTempConfig(t, "Port 2222\nPort 22\nPort 2222\nPort 8022\n")
	got, err := parseSSHDConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Ports, []int{22, 2222, 8022}) {
		t.Fatalf("ports = %v, want [22 2222 8022]", got.Ports)
	}
}

func TestParseSSHDConfig_IgnoreCommentsAndInvalid(t *testing.T) {
	path := writeTempConfig(t, "# Port 9999\nPort 0\nPort 65536\nPort -22\nPort abc\nPort 2200\n")
	got, err := parseSSHDConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Ports, []int{2200}) {
		t.Fatalf("ports = %v, want [2200]", got.Ports)
	}
}

func TestParseSSHDConfig_FollowsInclude(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "sshd_config")
	subdir := filepath.Join(dir, "sshd_config.d")
	if err := os.Mkdir(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "10-custom.conf"), []byte("Port 2222\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "20-emergency.conf"), []byte("Port 2200\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root, []byte("Include sshd_config.d/*.conf\nPort 22\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := parseSSHDConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Ports, []int{22, 2200, 2222}) {
		t.Fatalf("ports = %v, want [22 2200 2222] (root + 2 includes)", got.Ports)
	}
	if len(got.SourcePaths) != 3 {
		t.Fatalf("SourcePaths = %v, want 3 entries (root + 2 includes)", got.SourcePaths)
	}
}

func TestParseSSHDConfig_IncludeCycleTerminates(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.conf")
	b := filepath.Join(dir, "b.conf")
	if err := os.WriteFile(a, []byte("Include "+b+"\nPort 2222\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("Include "+a+"\nPort 2200\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := parseSSHDConfig(a)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Ports, []int{2200, 2222}) {
		t.Fatalf("ports = %v, want [2200 2222] despite Include cycle", got.Ports)
	}
}

func TestSSHDConfigHasPort_EmptySnapshotDefaultsTo22(t *testing.T) {
	// Zero-value snapshot — simulates a reader that never refreshed
	// successfully. Has to behave as if sshd is on its default port so
	// SSH detection isn't silently disabled.
	var c *SSHDConfig
	if !c.HasPort(22) {
		t.Fatal("nil receiver should treat 22 as a hit")
	}
	if c.HasPort(2222) {
		t.Fatal("nil receiver should not claim non-default ports")
	}
	empty := &SSHDConfig{}
	if !empty.HasPort(22) {
		t.Fatal("empty snapshot should treat 22 as a hit")
	}
}

func TestSSHDConfigReader_RetainsPreviousSnapshotOnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(path, []byte("Port 2222\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := NewSSHDConfigReaderAt(path)
	if _, err := r.Refresh(); err != nil {
		t.Fatal(err)
	}
	snap1 := r.Snapshot()
	if !reflect.DeepEqual(snap1.Ports, []int{2222}) {
		t.Fatalf("initial snapshot Ports = %v, want [2222]", snap1.Ports)
	}

	// Delete the file — Refresh now errors but the previous snapshot stays.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	snap2, err := r.Refresh()
	if err == nil {
		t.Fatal("expected error from Refresh after file removal, got nil")
	}
	if !reflect.DeepEqual(snap2.Ports, []int{2222}) {
		t.Fatalf("snapshot after failed refresh = %v, want previous [2222]", snap2.Ports)
	}
}

func writeTempConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sshd_config")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

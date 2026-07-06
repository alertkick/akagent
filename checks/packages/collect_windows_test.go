//go:build windows

package packages

import "testing"

// TestGetInstalledPackagesWindows verifies registry Uninstall-key enumeration
// returns installed software with names.
func TestGetInstalledPackagesWindows(t *testing.T) {
	pkgs, err := GetInstalledPackages()
	if err != nil {
		t.Fatalf("GetInstalledPackages: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatal("expected at least one installed package")
	}
	for _, p := range pkgs {
		if p.Name == "" {
			t.Error("package with empty name should have been skipped")
		}
	}
}

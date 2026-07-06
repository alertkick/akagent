//go:build windows

package ports

import "testing"

// TestGetListeningPortsWindows verifies the gopsutil-backed TCP/UDP table read
// runs and returns well-formed entries. A Windows host always has listeners
// (RPC endpoint mapper on 135, etc.).
func TestGetListeningPortsWindows(t *testing.T) {
	ports, err := GetListeningPorts()
	if err != nil {
		t.Fatalf("GetListeningPorts: %v", err)
	}
	if len(ports) == 0 {
		t.Fatal("expected at least one listening port")
	}
	for _, p := range ports {
		if p.Port == 0 {
			t.Errorf("listener with port 0: %+v", p)
		}
		if p.Protocol == "" {
			t.Errorf("listener with empty protocol: %+v", p)
		}
	}
}

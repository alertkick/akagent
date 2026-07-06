//go:build windows

package memory

import (
	"strconv"
	"testing"
)

// TestMemoryUsagesWindows exercises the real gopsutil-backed collector on a
// Windows runner: total must be present and positive.
func TestMemoryUsagesWindows(t *testing.T) {
	m := memoryUsages()
	total, ok := m["total"]
	if !ok {
		t.Fatal("memoryUsages returned no 'total' metric")
	}
	v, err := strconv.ParseFloat(total.Value, 64)
	if err != nil {
		t.Fatalf("total not numeric: %q", total.Value)
	}
	if v <= 0 {
		t.Fatalf("total memory should be > 0, got %v", v)
	}
	for _, k := range []string{"used", "free", "swap_used", "swap_free"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing metric %q", k)
		}
	}
}

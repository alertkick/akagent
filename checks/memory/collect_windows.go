//go:build windows

package memory

import (
	"strconv"

	"akagent/internal/api"

	"github.com/shirou/gopsutil/mem"
)

// memoryUsages returns memory stats via gopsutil. Values are reported in kB
// to match the Linux collector (which reads /proc/meminfo kB values), so a
// mixed fleet renders consistently. shared/buffers/cached have no Windows
// equivalent and are reported as 0.
func memoryUsages() map[string]api.Metric {
	metrics := make(map[string]api.Metric)

	vm, err := mem.VirtualMemory()
	if err != nil {
		return metrics
	}

	kb := func(b uint64) string {
		return strconv.FormatFloat(float64(b)/1024, 'f', -1, 64)
	}

	metrics["total"] = api.Metric{Type: "total", Value: kb(vm.Total), Unit: "float64"}
	metrics["used"] = api.Metric{Type: "used", Value: kb(vm.Used), Unit: "float64"}
	metrics["free"] = api.Metric{Type: "free", Value: kb(vm.Available), Unit: "float64"}
	metrics["shared"] = api.Metric{Type: "shared", Value: "0", Unit: "float64"}
	metrics["buffers"] = api.Metric{Type: "buffers", Value: "0", Unit: "float64"}
	metrics["cached"] = api.Metric{Type: "cached", Value: "0", Unit: "float64"}

	// Swap on Windows is the pagefile.
	swapUsed, swapFree := "0", "0"
	if sm, err := mem.SwapMemory(); err == nil {
		swapUsed = kb(sm.Used)
		swapFree = kb(sm.Free)
	}
	metrics["swap_used"] = api.Metric{Type: "swap_used", Value: swapUsed, Unit: "float64"}
	metrics["swap_free"] = api.Metric{Type: "swap_free", Value: swapFree, Unit: "float64"}

	return metrics
}

//go:build linux

package bpflsm

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// readProcUptime reads /proc/uptime and returns the system uptime as
// a time.Duration. /proc/uptime format is "<seconds_idle_sum> <seconds_total>";
// we use the first field, which is the wall-clock uptime since boot.
func readProcUptime() (time.Duration, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0, os.ErrInvalid
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}
	return time.Duration(secs * float64(time.Second)), nil
}

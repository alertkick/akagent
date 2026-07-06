//go:build linux

package memory

import (
	"akagent/internal/api"
	"bufio"
	"os"
	"strconv"
	"strings"
)

// memoryUsages - return a map with memory usages stats
func memoryUsages() map[string]api.Metric {
	metrics := make(map[string]api.Metric)

	mInfo, err := getMemInfo()
	if err != nil {
		return metrics
	}

	total := (*mInfo)["MemTotal"]
	used := (*mInfo)["MemTotal"] - (*mInfo)["MemFree"] - (*mInfo)["Buffers"] - (*mInfo)["Cached"]
	free := (*mInfo)["MemFree"]
	shared := (*mInfo)["Shmem"]
	buffers := (*mInfo)["Buffers"]
	cached := (*mInfo)["Cached"]
	swapUsed := (*mInfo)["SwapTotal"] - (*mInfo)["SwapFree"]
	swapFree := (*mInfo)["SwapFree"]

	metrics["total"] = api.Metric{Type: "total", Value: strconv.FormatFloat(total, 'f', -1, 64), Unit: "float64"}
	metrics["used"] = api.Metric{Type: "used", Value: strconv.FormatFloat(used, 'f', -1, 64), Unit: "float64"}
	metrics["free"] = api.Metric{Type: "free", Value: strconv.FormatFloat(free, 'f', -1, 64), Unit: "float64"}
	metrics["shared"] = api.Metric{Type: "shared", Value: strconv.FormatFloat(shared, 'f', -1, 64), Unit: "float64"}
	metrics["buffers"] = api.Metric{Type: "buffers", Value: strconv.FormatFloat(buffers, 'f', -1, 64), Unit: "float64"}
	metrics["cached"] = api.Metric{Type: "cached", Value: strconv.FormatFloat(cached, 'f', -1, 64), Unit: "float64"}
	metrics["swap_used"] = api.Metric{Type: "swap_used", Value: strconv.FormatFloat(swapUsed, 'f', -1, 64), Unit: "float64"}
	metrics["swap_free"] = api.Metric{Type: "swap_free", Value: strconv.FormatFloat(swapFree, 'f', -1, 64), Unit: "float64"}

	return metrics
}

func getMemInfo() (*map[string]float64, error) {
	m := make(map[string]float64)

	path := "/proc/meminfo"

	file, err := os.Open(path)
	if err != nil {
		return &m, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()

		n := strings.Index(text, ":")
		if n == -1 {
			continue
		}

		key := text[:n]
		data := strings.Split(strings.Trim(text[(n+1):], " "), " ")
		if len(data) == 1 {
			value, err := strconv.ParseFloat(data[0], 10)
			if err != nil {
				continue
			}
			m[key] = value
		} else if len(data) == 2 {
			if data[1] == "kB" {
				value, err := strconv.ParseFloat(data[0], 10)
				if err != nil {
					continue
				}

				m[key] = value
			}
		}
	}

	return &m, nil
}

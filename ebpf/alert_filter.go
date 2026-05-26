package ebpf

import (
	"strings"
	"sync/atomic"
)

// AlertFilter drops events that match configured noise patterns before
// they leave the host. It is intentionally dumb: comm name in an
// exclusion set, UID in an exclusion set, file path prefix in an
// exclusion set. All classification, framework tagging, and severity
// scoring happens at the endpoint after this filter has passed an event
// through.
type AlertFilter struct {
	config      *AlertFilterConfig
	nativeLists *NativeListConfig

	// Pre-built lookup sets derived from nativeLists at construction
	// time. Rebuilt by UpdateConfig when the config is hot-swapped so
	// hot-path lookups stay O(1).
	excludeComms map[string]struct{}
	excludePaths []string

	// Statistics
	totalEvents   uint64
	alertedEvents uint64
	droppedEvents uint64
}

// AlertFilterStats contains statistics about alert filtering
type AlertFilterStats struct {
	TotalEvents   uint64
	AlertedEvents uint64
	DroppedEvents uint64
	AlertRate     float64
}

// NewAlertFilter creates a new noise filter from the given configuration.
// Without an explicit NativeListConfig the conservative defaults are used.
func NewAlertFilter(config *AlertFilterConfig) *AlertFilter {
	defaults := DefaultNativeListConfig()
	return NewAlertFilterWithLists(config, &defaults)
}

// NewAlertFilterWithLists creates a noise filter with explicit list config.
func NewAlertFilterWithLists(config *AlertFilterConfig, nativeLists *NativeListConfig) *AlertFilter {
	f := &AlertFilter{
		config:      config,
		nativeLists: nativeLists,
	}
	f.rebuildLookups()
	return f
}

// SetNativeLists swaps in a fresh list configuration and rebuilds the
// internal lookup sets used on the hot path.
func (f *AlertFilter) SetNativeLists(nativeLists *NativeListConfig) {
	f.nativeLists = nativeLists
	f.rebuildLookups()
}

// UpdateConfig swaps in a fresh AlertFilterConfig. The native-list set
// is unchanged; call SetNativeLists separately if those are also new.
func (f *AlertFilter) UpdateConfig(config *AlertFilterConfig) {
	f.config = config
}

// ShouldAlert returns true if the event should be sent to the endpoint.
// Events that match a noise pattern (excluded comm / path prefix) are
// dropped at the source. The endpoint classifies everything else.
func (f *AlertFilter) ShouldAlert(event *SecurityEvent) bool {
	atomic.AddUint64(&f.totalEvents, 1)

	if !f.config.Enabled {
		atomic.AddUint64(&f.alertedEvents, 1)
		return true
	}

	if f.matchesNoise(event) {
		atomic.AddUint64(&f.droppedEvents, 1)
		return false
	}

	atomic.AddUint64(&f.alertedEvents, 1)
	return true
}

// matchesNoise checks the event against the configured noise patterns.
// Returns true when the event should be dropped as noise.
func (f *AlertFilter) matchesNoise(event *SecurityEvent) bool {
	if len(f.excludeComms) > 0 {
		if _, ok := f.excludeComms[event.Process.Name]; ok {
			return true
		}
	}

	if len(f.excludePaths) > 0 && event.File.Path != "" {
		for _, prefix := range f.excludePaths {
			if strings.HasPrefix(event.File.Path, prefix) {
				return true
			}
		}
	}

	return false
}

// rebuildLookups regenerates the comm and path exclusion sets from the
// native-list configuration.
func (f *AlertFilter) rebuildLookups() {
	if f.nativeLists == nil {
		f.excludeComms = nil
		f.excludePaths = nil
		return
	}
	f.excludeComms = f.nativeLists.BuildExcludeComms()
	f.excludePaths = f.nativeLists.BuildExcludePaths()
}

// Stats returns a snapshot of filtering statistics.
func (f *AlertFilter) Stats() AlertFilterStats {
	total := atomic.LoadUint64(&f.totalEvents)
	alerted := atomic.LoadUint64(&f.alertedEvents)
	dropped := atomic.LoadUint64(&f.droppedEvents)

	var rate float64
	if total > 0 {
		rate = float64(alerted) / float64(total)
	}
	return AlertFilterStats{
		TotalEvents:   total,
		AlertedEvents: alerted,
		DroppedEvents: dropped,
		AlertRate:     rate,
	}
}

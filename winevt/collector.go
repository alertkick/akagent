package winevt

import (
	"context"
	"sync"
	"sync/atomic"

	"akagent/ebpf"
	"akagent/logger"
)

var log = logger.Sublogger("winevt")

// channels this collector subscribes to. Each maps to one EvtSubscribe on
// Windows. Kept here (portable) so the set is visible and testable.
var subscribedChannels = []string{
	"Security",
	"System",
	"Application",
	"Microsoft-Windows-Windows Defender/Operational",
}

// Collector reads Windows event-log records, maps them to security events,
// and exposes them on a channel drained by the agent's shared event sender.
// The record-processing core here is platform-neutral; the subscription
// reader that produces Records lives in winevt_windows.go.
type Collector struct {
	eventChan  chan ebpf.SecurityEvent
	bruteForce *bruteForce

	running   atomic.Bool
	listening atomic.Bool
	dropped   atomic.Uint64

	mu      sync.Mutex
	cancel  context.CancelFunc
	started bool
}

// NewCollector builds a collector with a buffered event channel. bufSize
// mirrors NativeConfig.EventChannelSize (default 1000 on the eBPF side).
func NewCollector(bufSize int) *Collector {
	if bufSize < 10 {
		bufSize = 1000
	}
	return &Collector{
		eventChan:  make(chan ebpf.SecurityEvent, bufSize),
		bruteForce: newBruteForce(),
	}
}

// EventChannel returns the receive side drained by agent.StartEBPFEventSender.
func (c *Collector) EventChannel() <-chan ebpf.SecurityEvent {
	return c.eventChan
}

func (c *Collector) IsRunning() bool   { return c.running.Load() }
func (c *Collector) IsListening() bool { return c.listening.Load() }

// process maps a single record to zero, one, or two security events and
// emits them. A 4625 both maps to a failure event and feeds the brute-force
// windower, so it can produce two events. Called by the platform reader.
func (c *Collector) process(r *Record) {
	if r == nil {
		return
	}
	if ev, ok := MapEvent(r); ok {
		c.emit(ev)
	}
	if r.EventID == 4625 {
		if !isMachineOrServiceAccount(r.get("TargetUserName")) {
			if ev, ok := c.bruteForce.Observe(r); ok {
				c.emit(ev)
			}
		}
	}
}

// emit does a non-blocking send, counting drops the same way the eBPF
// engine does when the channel is saturated.
func (c *Collector) emit(ev ebpf.SecurityEvent) {
	if !ev.Validate() {
		log.Debug().Msgf("winevt.emit - dropping invalid event (rule=%q id=%v)", ev.Rule, ev.RawFields["event_id"])
		return
	}
	select {
	case c.eventChan <- ev:
	default:
		c.dropped.Add(1)
	}
}

// DroppedEvents returns how many events were dropped due to a full channel.
func (c *Collector) DroppedEvents() uint64 { return c.dropped.Load() }

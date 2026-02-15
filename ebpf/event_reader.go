package ebpf

import (
	"errors"
	"sync/atomic"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
)

// OutputMode represents the BPF event output mechanism
type OutputMode int

const (
	// OutputModeRingBuf uses BPF_MAP_TYPE_RINGBUF (kernel 5.8+)
	OutputModeRingBuf OutputMode = iota
	// OutputModePerf uses BPF_MAP_TYPE_PERF_EVENT_ARRAY (kernel 4.3+)
	OutputModePerf
)

// String returns the human-readable name of the output mode
func (m OutputMode) String() string {
	switch m {
	case OutputModeRingBuf:
		return "ringbuf"
	case OutputModePerf:
		return "perf"
	default:
		return "unknown"
	}
}

// ErrReaderClosed is returned when reading from a closed EventReader
var ErrReaderClosed = errors.New("event reader closed")

// EventReader provides a unified interface for reading BPF events from either
// ring buffer or perf event array maps. This abstraction allows the agent to
// transparently support both output modes based on kernel capabilities.
type EventReader interface {
	// Read blocks until an event is available and returns the raw event bytes.
	// Returns ErrReaderClosed if the reader has been closed.
	Read() ([]byte, error)

	// Close closes the reader and releases associated resources.
	// Any blocked Read calls will return ErrReaderClosed.
	Close() error

	// DroppedCount returns the cumulative number of events dropped since the
	// reader was created. For perf readers this reflects LostSamples reports.
	// For ring buffer readers this reflects read errors (the kernel drops
	// events when the ring buffer is full before they reach userspace).
	DroppedCount() uint64
}

// ringbufEventReader wraps cilium/ebpf ringbuf.Reader
type ringbufEventReader struct {
	reader  *ringbuf.Reader
	dropped atomic.Uint64
}

// NewRingBufReader creates an EventReader backed by a ring buffer map
func NewRingBufReader(m *ciliumebpf.Map) (EventReader, error) {
	r, err := ringbuf.NewReader(m)
	if err != nil {
		return nil, err
	}
	return &ringbufEventReader{reader: r}, nil
}

func (r *ringbufEventReader) Read() ([]byte, error) {
	record, err := r.reader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, ErrReaderClosed
		}
		// Track non-close errors as potential drops (e.g., truncated records)
		r.dropped.Add(1)
		return nil, err
	}
	return record.RawSample, nil
}

func (r *ringbufEventReader) Close() error {
	return r.reader.Close()
}

func (r *ringbufEventReader) DroppedCount() uint64 {
	return r.dropped.Load()
}

// perfEventReader wraps cilium/ebpf perf.Reader
type perfEventReader struct {
	reader  *perf.Reader
	dropped atomic.Uint64
}

// NewPerfReader creates an EventReader backed by a perf event array map.
// The perCPUBuffer parameter sets the per-CPU buffer size for perf ring buffers.
func NewPerfReader(m *ciliumebpf.Map, perCPUBuffer int) (EventReader, error) {
	r, err := perf.NewReader(m, perCPUBuffer)
	if err != nil {
		return nil, err
	}
	return &perfEventReader{reader: r}, nil
}

func (r *perfEventReader) Read() ([]byte, error) {
	record, err := r.reader.Read()
	if err != nil {
		if errors.Is(err, perf.ErrClosed) {
			return nil, ErrReaderClosed
		}
		return nil, err
	}
	// Track and skip lost events (perf can report event loss)
	if record.LostSamples > 0 {
		r.dropped.Add(record.LostSamples)
		nativeLog.Warn().Uint64("lost", record.LostSamples).Msg("Lost perf events")
		// Read next valid record
		return r.Read()
	}
	return record.RawSample, nil
}

func (r *perfEventReader) Close() error {
	return r.reader.Close()
}

func (r *perfEventReader) DroppedCount() uint64 {
	return r.dropped.Load()
}

// DefaultPerfPerCPUBuffer is the default per-CPU buffer size for perf readers.
// 8 pages (32KB) provides a good balance between memory usage and throughput.
const DefaultPerfPerCPUBuffer = 8 * 4096

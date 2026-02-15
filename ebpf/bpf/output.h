// SPDX-License-Identifier: GPL-2.0 OR MIT
// output.h - BPF event output abstraction layer
//
// Provides compile-time selection between ring buffer (kernel 5.8+)
// and perf event array (kernel 4.3+) output modes.
//
// Usage:
//   Default compilation uses ring buffers.
//   Compile with -DUSE_PERF_OUTPUT to use perf event arrays instead.
//
// Example:
//   DECLARE_EVENT_OUTPUT(events, struct my_event, 256 * 1024);
//
//   SEC("tracepoint/...")
//   int my_prog(struct trace_event_raw_sys_enter *ctx) {
//       struct my_event *e;
//       e = EVENT_OUTPUT_BEGIN(events, struct my_event);
//       if (!e) return 0;
//       // ... fill event fields ...
//       EVENT_OUTPUT_END(events, e, struct my_event, ctx);
//       return 0;
//   }

#ifndef __OUTPUT_H
#define __OUTPUT_H

// BPF_F_CURRENT_CPU is used with bpf_perf_event_output to select the
// current CPU's perf ring buffer. Defined here in case vmlinux.h or
// libbpf headers don't provide it.
#ifndef BPF_F_CURRENT_CPU
#define BPF_F_CURRENT_CPU 0xFFFFFFFFULL
#endif

#ifdef USE_PERF_OUTPUT

// ============================================================================
// Perf Event Array Mode
// ============================================================================
//
// In perf mode, events are sent via bpf_perf_event_output().
// Since perf output copies from a source buffer (unlike ring buffer which
// returns a reservation pointer), we use a per-CPU array map as a scratch
// buffer. This avoids BPF stack limit issues for large events (>512 bytes).
//
// Each DECLARE_EVENT_OUTPUT creates two maps:
//   1. A perf event array map (for bpf_perf_event_output)
//   2. A per-CPU array scratch map (for event construction)

// Declare a perf event array output map with associated scratch buffer.
// Parameters:
//   name       - map name (also used as prefix for scratch map: name_heap)
//   event_type - the event struct type
//   buf_size   - ignored in perf mode (kept for API compatibility with ringbuf)
#define DECLARE_EVENT_OUTPUT(name, event_type, buf_size)    \
struct {                                                     \
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);            \
    __uint(key_size, sizeof(__u32));                         \
    __uint(value_size, sizeof(__u32));                       \
} name SEC(".maps");                                         \
                                                             \
struct {                                                     \
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);                \
    __uint(max_entries, 1);                                  \
    __type(key, __u32);                                      \
    __type(value, event_type);                               \
} name##_heap SEC(".maps")

// Acquire a pointer to scratch space for building an event.
// Returns a pointer to a zeroed event struct, or NULL on failure.
// In perf mode, this performs a per-CPU array lookup (always succeeds
// unless the map is somehow invalid).
#define EVENT_OUTPUT_BEGIN(name, event_type)                 \
({                                                           \
    __u32 __output_key = 0;                                  \
    (event_type *)bpf_map_lookup_elem(&name##_heap, &__output_key); \
})

// Submit the event to userspace via perf_event_output.
// Parameters:
//   name       - output map name
//   ptr        - pointer to the filled event
//   event_type - the event struct type (for sizeof)
//   ctx        - the BPF program context (tracepoint ctx)
#define EVENT_OUTPUT_END(name, ptr, event_type, ctx)         \
    bpf_perf_event_output(ctx, &name, BPF_F_CURRENT_CPU,    \
                          ptr, sizeof(event_type))

// Discard a partially-filled event (no-op in perf mode since nothing was reserved)
#define EVENT_OUTPUT_DISCARD(name, ptr) ((void)0)

#else /* !USE_PERF_OUTPUT */

// ============================================================================
// Ring Buffer Mode (default)
// ============================================================================
//
// Ring buffers (BPF_MAP_TYPE_RINGBUF, kernel 5.8+) provide:
//   - Single shared buffer across all CPUs (better memory efficiency)
//   - Reservation-based API (no copy on submit)
//   - Adaptive notification (epoll-based wakeup)
//
// This is the preferred output mode when available.

// Declare a ring buffer output map.
// Parameters:
//   name       - map name
//   event_type - the event struct type (unused, kept for API compatibility)
//   buf_size   - ring buffer size in bytes
#define DECLARE_EVENT_OUTPUT(name, event_type, buf_size)    \
struct {                                                     \
    __uint(type, BPF_MAP_TYPE_RINGBUF);                     \
    __uint(max_entries, buf_size);                           \
} name SEC(".maps")

// Reserve space from the ring buffer for an event.
// Returns a pointer to reserved space, or NULL if the buffer is full.
#define EVENT_OUTPUT_BEGIN(name, event_type)                 \
    (event_type *)bpf_ringbuf_reserve(&name, sizeof(event_type), 0)

// Submit the reserved event to the ring buffer.
// Parameters:
//   name       - output map name (unused, kept for API compatibility)
//   ptr        - pointer to the reserved event
//   event_type - the event struct type (unused, kept for API compatibility)
//   ctx        - BPF program context (unused, kept for API compatibility)
#define EVENT_OUTPUT_END(name, ptr, event_type, ctx)         \
    bpf_ringbuf_submit(ptr, 0)

// Discard a reserved ring buffer entry without submitting
#define EVENT_OUTPUT_DISCARD(name, ptr)                      \
    bpf_ringbuf_discard(ptr, 0)

#endif /* USE_PERF_OUTPUT */

#endif /* __OUTPUT_H */

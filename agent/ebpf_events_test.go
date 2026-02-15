package agent

import (
	"apagent/ebpf"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func testLogger() zerolog.Logger {
	return zerolog.New(os.Stderr).Level(zerolog.Disabled)
}

func makeEvent(rule, processName, parentName string, priority ebpf.PriorityLevel, ts time.Time) ebpf.SecurityEvent {
	return ebpf.SecurityEvent{
		UUID:      "test-uuid",
		AgentType: "native",
		Timestamp: ts,
		Priority:  priority,
		Rule:      rule,
		Process: ebpf.ProcessInfo{
			PID:        1234,
			Name:       processName,
			ParentName: parentName,
		},
	}
}

func TestDeduplicationKey(t *testing.T) {
	e := makeEvent("Process Execution", "cat", "bash", ebpf.PriorityInformational, time.Now())
	key := e.DeduplicationKey()
	expected := "Process Execution|cat|bash"
	if key != expected {
		t.Errorf("DeduplicationKey() = %q, want %q", key, expected)
	}
}

func TestDedup_EmptyFlush(t *testing.T) {
	d := NewEventDeduplicator(testLogger())
	result := d.Flush()
	if result != nil {
		t.Errorf("Flush() on empty dedup returned %d events, want nil", len(result))
	}
}

func TestDedup_SingleEvent(t *testing.T) {
	d := NewEventDeduplicator(testLogger())
	ts := time.Date(2026, 1, 30, 10, 0, 0, 0, time.UTC)
	e := makeEvent("Process Execution", "cat", "bash", ebpf.PriorityInformational, ts)

	d.Add(e)
	result := d.Flush()

	if len(result) != 1 {
		t.Fatalf("Flush() returned %d events, want 1", len(result))
	}

	// Single event should NOT have aggregation fields
	if result[0].AggregatedCount != 0 {
		t.Errorf("AggregatedCount = %d, want 0 (omitted for single events)", result[0].AggregatedCount)
	}
	if result[0].FirstOccurrence != nil {
		t.Error("FirstOccurrence should be nil for single events")
	}
	if result[0].LastOccurrence != nil {
		t.Error("LastOccurrence should be nil for single events")
	}
}

func TestDedup_DuplicateEvents(t *testing.T) {
	d := NewEventDeduplicator(testLogger())
	base := time.Date(2026, 1, 30, 10, 0, 0, 0, time.UTC)

	for i := 0; i < 50; i++ {
		e := makeEvent("Process Execution", "cat", "bash", ebpf.PriorityInformational,
			base.Add(time.Duration(i)*time.Second))
		d.Add(e)
	}

	result := d.Flush()

	if len(result) != 1 {
		t.Fatalf("Flush() returned %d events, want 1", len(result))
	}

	if result[0].AggregatedCount != 50 {
		t.Errorf("AggregatedCount = %d, want 50", result[0].AggregatedCount)
	}
	if result[0].FirstOccurrence == nil || !result[0].FirstOccurrence.Equal(base) {
		t.Errorf("FirstOccurrence = %v, want %v", result[0].FirstOccurrence, base)
	}
	expectedLast := base.Add(49 * time.Second)
	if result[0].LastOccurrence == nil || !result[0].LastOccurrence.Equal(expectedLast) {
		t.Errorf("LastOccurrence = %v, want %v", result[0].LastOccurrence, expectedLast)
	}
}

func TestDedup_DifferentKeys(t *testing.T) {
	d := NewEventDeduplicator(testLogger())
	ts := time.Date(2026, 1, 30, 10, 0, 0, 0, time.UTC)

	// Two different rules
	d.Add(makeEvent("Process Execution", "cat", "bash", ebpf.PriorityInformational, ts))
	d.Add(makeEvent("File Access", "cat", "bash", ebpf.PriorityInformational, ts))
	// Same rule but different process
	d.Add(makeEvent("Process Execution", "ls", "bash", ebpf.PriorityInformational, ts))

	result := d.Flush()

	if len(result) != 3 {
		t.Fatalf("Flush() returned %d events, want 3", len(result))
	}

	// All single events, no aggregation fields
	for i, e := range result {
		if e.AggregatedCount != 0 {
			t.Errorf("event[%d] AggregatedCount = %d, want 0", i, e.AggregatedCount)
		}
	}
}

func TestDedup_MixedDuplicatesAndUnique(t *testing.T) {
	d := NewEventDeduplicator(testLogger())
	ts := time.Date(2026, 1, 30, 10, 0, 0, 0, time.UTC)

	// 10 duplicates of cat|bash
	for i := 0; i < 10; i++ {
		d.Add(makeEvent("Process Execution", "cat", "bash", ebpf.PriorityInformational,
			ts.Add(time.Duration(i)*time.Second)))
	}
	// 1 unique ls|bash
	d.Add(makeEvent("Process Execution", "ls", "bash", ebpf.PriorityInformational, ts))

	result := d.Flush()

	if len(result) != 2 {
		t.Fatalf("Flush() returned %d events, want 2", len(result))
	}

	// Find the cat event and ls event
	var catEvent, lsEvent *ebpf.SecurityEvent
	for i := range result {
		if result[i].Process.Name == "cat" {
			catEvent = &result[i]
		} else if result[i].Process.Name == "ls" {
			lsEvent = &result[i]
		}
	}

	if catEvent == nil {
		t.Fatal("cat event not found in results")
	}
	if catEvent.AggregatedCount != 10 {
		t.Errorf("cat AggregatedCount = %d, want 10", catEvent.AggregatedCount)
	}

	if lsEvent == nil {
		t.Fatal("ls event not found in results")
	}
	if lsEvent.AggregatedCount != 0 {
		t.Errorf("ls AggregatedCount = %d, want 0", lsEvent.AggregatedCount)
	}
}

func TestDedup_CrossWindowSuppression(t *testing.T) {
	d := NewEventDeduplicator(testLogger())
	ts := time.Date(2026, 1, 30, 10, 0, 0, 0, time.UTC)

	// Window 1: 50 duplicates
	for i := 0; i < 50; i++ {
		d.Add(makeEvent("Process Execution", "cat", "bash", ebpf.PriorityInformational,
			ts.Add(time.Duration(i)*time.Second)))
	}
	result := d.Flush()
	if len(result) != 1 || result[0].AggregatedCount != 50 {
		t.Fatalf("Window 1: expected 1 event with count 50, got %d events", len(result))
	}

	// suppressedKeys should now contain the cat|bash key
	if len(d.suppressedKeys) != 1 {
		t.Errorf("suppressedKeys after W1 = %d, want 1", len(d.suppressedKeys))
	}

	// Window 2: same key fires 30 more times
	for i := 0; i < 30; i++ {
		d.Add(makeEvent("Process Execution", "cat", "bash", ebpf.PriorityInformational,
			ts.Add(time.Duration(60+i)*time.Second)))
	}
	result = d.Flush()
	if len(result) != 1 || result[0].AggregatedCount != 30 {
		t.Fatalf("Window 2: expected 1 event with count 30, got %d events", len(result))
	}

	// Window 3: key does NOT fire
	result = d.Flush()
	if result != nil {
		t.Fatalf("Window 3: expected nil, got %d events", len(result))
	}
	// Key should be evicted from suppressedKeys
	if len(d.suppressedKeys) != 0 {
		t.Errorf("suppressedKeys after W3 = %d, want 0", len(d.suppressedKeys))
	}

	// Window 4: key fires once (treated as new, no aggregation)
	d.Add(makeEvent("Process Execution", "cat", "bash", ebpf.PriorityInformational,
		ts.Add(120*time.Second)))
	result = d.Flush()
	if len(result) != 1 {
		t.Fatalf("Window 4: expected 1 event, got %d", len(result))
	}
	if result[0].AggregatedCount != 0 {
		t.Errorf("Window 4: AggregatedCount = %d, want 0 (single event)", result[0].AggregatedCount)
	}
}

func TestDedup_MemoryCleanup(t *testing.T) {
	d := NewEventDeduplicator(testLogger())
	ts := time.Date(2026, 1, 30, 10, 0, 0, 0, time.UTC)

	// Add events for 100 distinct keys with duplicates
	for i := 0; i < 100; i++ {
		for j := 0; j < 5; j++ {
			d.Add(makeEvent("Rule", "proc"+string(rune('A'+i%26)), "parent",
				ebpf.PriorityInformational, ts))
		}
	}
	d.Flush()

	// suppressedKeys should have entries (all had count > 1)
	suppressedCount := len(d.suppressedKeys)
	if suppressedCount == 0 {
		t.Error("suppressedKeys should not be empty after flushing duplicates")
	}

	// Flush again with no new events — suppressedKeys should be cleared
	d.Flush()
	if len(d.suppressedKeys) != 0 {
		t.Errorf("suppressedKeys after empty window = %d, want 0", len(d.suppressedKeys))
	}
	if len(d.currentWindow) != 0 {
		t.Errorf("currentWindow after flush = %d, want 0", len(d.currentWindow))
	}
}

func TestDedup_TimestampOrdering(t *testing.T) {
	d := NewEventDeduplicator(testLogger())

	// Add events in reverse timestamp order
	late := time.Date(2026, 1, 30, 10, 0, 30, 0, time.UTC)
	early := time.Date(2026, 1, 30, 10, 0, 0, 0, time.UTC)
	mid := time.Date(2026, 1, 30, 10, 0, 15, 0, time.UTC)

	d.Add(makeEvent("Rule", "cat", "bash", ebpf.PriorityInformational, late))
	d.Add(makeEvent("Rule", "cat", "bash", ebpf.PriorityInformational, early))
	d.Add(makeEvent("Rule", "cat", "bash", ebpf.PriorityInformational, mid))

	result := d.Flush()

	if len(result) != 1 {
		t.Fatalf("expected 1 event, got %d", len(result))
	}
	if !result[0].FirstOccurrence.Equal(early) {
		t.Errorf("FirstOccurrence = %v, want %v", result[0].FirstOccurrence, early)
	}
	if !result[0].LastOccurrence.Equal(late) {
		t.Errorf("LastOccurrence = %v, want %v", result[0].LastOccurrence, late)
	}
}

func TestDedup_JSONOmitsFieldsForSingleEvent(t *testing.T) {
	d := NewEventDeduplicator(testLogger())
	ts := time.Date(2026, 1, 30, 10, 0, 0, 0, time.UTC)
	d.Add(makeEvent("Process Execution", "cat", "bash", ebpf.PriorityInformational, ts))

	result := d.Flush()
	data, err := json.Marshal(result[0])
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	// Single events should not have these fields
	for _, field := range []string{"aggregated_count", "first_occurrence", "last_occurrence"} {
		if _, exists := m[field]; exists {
			t.Errorf("field %q should be omitted for single events, but found in JSON", field)
		}
	}
}

func TestDedup_JSONIncludesFieldsForDuplicated(t *testing.T) {
	d := NewEventDeduplicator(testLogger())
	ts := time.Date(2026, 1, 30, 10, 0, 0, 0, time.UTC)

	d.Add(makeEvent("Process Execution", "cat", "bash", ebpf.PriorityInformational, ts))
	d.Add(makeEvent("Process Execution", "cat", "bash", ebpf.PriorityInformational,
		ts.Add(28*time.Second)))

	result := d.Flush()
	data, err := json.Marshal(result[0])
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	for _, field := range []string{"aggregated_count", "first_occurrence", "last_occurrence"} {
		if _, exists := m[field]; !exists {
			t.Errorf("field %q should be present for deduplicated events, but missing from JSON", field)
		}
	}

	if count, ok := m["aggregated_count"].(float64); !ok || int(count) != 2 {
		t.Errorf("aggregated_count = %v, want 2", m["aggregated_count"])
	}
}

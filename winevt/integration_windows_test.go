//go:build windows

package winevt

import (
	"context"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestEventLogReaderIntegration validates the hand-written wevtapi path —
// EvtSubscribe → EvtNext → EvtRender → parseEventXML — against the real
// Windows Event Log. It subscribes to the Application channel, writes a known
// event with eventcreate, and asserts the reader parses it back.
//
// This is the highest-risk Windows-only code (raw syscall bindings), so the
// test exercises it directly rather than mocking. Requires the ability to
// write to the Application log (eventcreate needs an elevated shell; GitHub
// runners run as admin).
func TestEventLogReaderIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test writes to the Event Log; run in the dedicated CI step")
	}
	const testEventID = 999

	var mu sync.Mutex
	seen := map[int]bool{}
	c := NewCollector(100)
	c.onRecord = func(r *Record) {
		mu.Lock()
		seen[r.EventID] = true
		mu.Unlock()
	}

	// Subscribe only to Application for this test (avoids needing Security
	// audit config). subscribe + a manual drain loop mirror readLoop.
	sub, err := subscribe("Application")
	if err != nil {
		t.Fatalf("subscribe(Application): %v", err)
	}
	defer sub.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.readLoop(ctx, sub)

	// Give the subscription a moment to arm before writing the event.
	time.Sleep(500 * time.Millisecond)

	out, err := exec.Command("eventcreate",
		"/T", "INFORMATION",
		"/ID", strconv.Itoa(testEventID),
		"/L", "APPLICATION",
		"/SO", "AlertKickAgentTest",
		"/D", "akagent winevt integration test event",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("eventcreate failed: %v (%s)", err, out)
	}

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := seen[testEventID]
		mu.Unlock()
		if got {
			return // success: the reader delivered our synthetic event
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("event %d not observed via EvtSubscribe within timeout", testEventID)
}

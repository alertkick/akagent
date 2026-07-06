//go:build windows

package winevt

import (
	"context"
	"encoding/xml"
	"fmt"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows Event Log ("wevtapi") bindings. golang.org/x/sys/windows does not
// wrap the Evt* subscription API, so we bind the handful of entry points we
// need directly against wevtapi.dll.
var (
	modwevtapi       = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtSubscribe = modwevtapi.NewProc("EvtSubscribe")
	procEvtNext      = modwevtapi.NewProc("EvtNext")
	procEvtRender    = modwevtapi.NewProc("EvtRender")
	procEvtClose     = modwevtapi.NewProc("EvtClose")
)

const (
	// EvtSubscribeToFutureEvents = 1: only events after subscription time.
	// EvtSubscribeStartAtOldestRecord = 2 would replay history; we start at
	// "now" per channel so a first install doesn't flood with old events.
	// (Bookmark-based resume is a follow-up — see the plan doc.)
	evtSubscribeToFutureEvents = 1

	evtRenderEventXml = 1

	// ERROR_NO_MORE_ITEMS from EvtNext when the batch is drained.
	errorNoMoreItems = 259
)

// subscription holds one channel's EvtSubscribe handle and its signal event.
type subscription struct {
	channel string
	handle  windows.Handle
	signal  windows.Handle
}

// Start subscribes to the configured channels and launches per-channel reader
// goroutines. It returns after subscriptions are established; events flow to
// EventChannel() until Stop.
func (c *Collector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started {
		return nil
	}

	runCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel

	var subs []*subscription
	for _, ch := range subscribedChannels {
		sub, err := subscribe(ch)
		if err != nil {
			// A missing channel (e.g. Defender not installed) is non-fatal;
			// keep the others.
			log.Warn().Err(err).Msgf("winevt.Start - could not subscribe to %q", ch)
			continue
		}
		subs = append(subs, sub)
	}
	if len(subs) == 0 {
		cancel()
		return fmt.Errorf("winevt: no event channels could be subscribed")
	}

	c.started = true
	c.running.Store(true)
	c.listening.Store(true)

	var wg sync.WaitGroup
	for _, sub := range subs {
		wg.Add(1)
		go func(s *subscription) {
			defer wg.Done()
			c.readLoop(runCtx, s)
			s.close()
		}(sub)
	}

	go func() {
		<-runCtx.Done()
		wg.Wait()
		c.running.Store(false)
		c.listening.Store(false)
	}()

	log.Info().Msgf("winevt.Start - subscribed to %d event channels", len(subs))
	return nil
}

// StartEventListener is a no-op alias kept for parity with the eBPF agent's
// two-phase Start/StartEventListener lifecycle — Start already begins
// reading. Present so the agent seam can call both uniformly.
func (c *Collector) StartEventListener(ctx context.Context) error { return nil }

// Stop cancels the reader goroutines and closes subscriptions.
func (c *Collector) Stop(ctx context.Context) error {
	c.mu.Lock()
	cancel := c.cancel
	c.started = false
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}

// StopEventListener mirrors Stop for lifecycle parity.
func (c *Collector) StopEventListener() error { return nil }

func subscribe(channel string) (*subscription, error) {
	// Manual-reset signal event fired by wevtapi when new events are ready.
	signal, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("create signal event: %w", err)
	}

	chanPtr, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		windows.CloseHandle(signal)
		return nil, err
	}

	h, _, callErr := procEvtSubscribe.Call(
		0,                                // Session (local)
		uintptr(signal),                  // SignalEvent
		uintptr(unsafe.Pointer(chanPtr)), // ChannelPath
		0,                                // Query (all events)
		0,                                // Bookmark
		0,                                // Context
		0,                                // Callback (nil = signal mode)
		uintptr(evtSubscribeToFutureEvents),
	)
	if h == 0 {
		windows.CloseHandle(signal)
		return nil, fmt.Errorf("EvtSubscribe(%s): %v", channel, callErr)
	}

	return &subscription{
		channel: channel,
		handle:  windows.Handle(h),
		signal:  signal,
	}, nil
}

func (s *subscription) close() {
	if s.handle != 0 {
		procEvtClose.Call(uintptr(s.handle))
	}
	if s.signal != 0 {
		windows.CloseHandle(s.signal)
	}
}

// readLoop waits for the subscription signal and drains ready events until
// the context is cancelled.
func (c *Collector) readLoop(ctx context.Context, s *subscription) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Wait up to 1s for new events; the timeout lets us re-check ctx.
		wait, _ := windows.WaitForSingleObject(s.signal, 1000)
		if wait == uint32(windows.WAIT_TIMEOUT) {
			continue
		}
		windows.ResetEvent(s.signal)
		c.drain(s)
	}
}

// drain pulls all currently-available events from the subscription in
// batches and processes each.
func (c *Collector) drain(s *subscription) {
	const batch = 32
	handles := make([]windows.Handle, batch)
	for {
		var returned uint32
		ret, _, callErr := procEvtNext.Call(
			uintptr(s.handle),
			uintptr(batch),
			uintptr(unsafe.Pointer(&handles[0])),
			uintptr(0xFFFFFFFF), // INFINITE timeout (events already ready)
			0,
			uintptr(unsafe.Pointer(&returned)),
		)
		if ret == 0 {
			if errno, ok := callErr.(windows.Errno); ok && uintptr(errno) == errorNoMoreItems {
				return
			}
			return
		}

		for i := 0; i < int(returned); i++ {
			if xmlStr, err := renderEventXML(handles[i]); err == nil {
				if rec := parseEventXML(xmlStr, s.channel); rec != nil {
					c.process(rec)
				}
			}
			procEvtClose.Call(uintptr(handles[i]))
		}
	}
}

// renderEventXML renders an event handle to its XML representation.
func renderEventXML(event windows.Handle) (string, error) {
	var bufferUsed, propCount uint32

	// First call sizes the buffer.
	procEvtRender.Call(0, uintptr(event), evtRenderEventXml, 0, 0,
		uintptr(unsafe.Pointer(&bufferUsed)), uintptr(unsafe.Pointer(&propCount)))
	if bufferUsed == 0 {
		return "", fmt.Errorf("EvtRender returned zero size")
	}

	buf := make([]uint16, (bufferUsed/2)+1)
	ret, _, callErr := procEvtRender.Call(0, uintptr(event), evtRenderEventXml,
		uintptr(len(buf)*2), uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufferUsed)), uintptr(unsafe.Pointer(&propCount)))
	if ret == 0 {
		return "", fmt.Errorf("EvtRender: %v", callErr)
	}
	return windows.UTF16ToString(buf), nil
}

// --- event XML parsing ---

// evtXML is the subset of the Windows event XML schema we consume.
type evtXML struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     string `xml:"EventID"`
		Level       string `xml:"Level"`
		Computer    string `xml:"Computer"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// parseEventXML converts rendered event XML into a Record. Returns nil if the
// XML can't be parsed or lacks an event id.
func parseEventXML(xmlStr, channel string) *Record {
	var e evtXML
	if err := xml.Unmarshal([]byte(xmlStr), &e); err != nil {
		return nil
	}

	eventID := parseHexInt(strings.TrimSpace(e.System.EventID))
	if eventID == 0 {
		return nil
	}

	rec := &Record{
		Channel:  channel,
		Provider: e.System.Provider.Name,
		EventID:  eventID,
		Level:    parseHexInt(strings.TrimSpace(e.System.Level)),
		Computer: e.System.Computer,
		Data:     make(map[string]string, len(e.EventData.Data)),
	}
	if t, err := time.Parse(time.RFC3339Nano, e.System.TimeCreated.SystemTime); err == nil {
		rec.Timestamp = t
	}
	for i, d := range e.EventData.Data {
		name := d.Name
		if name == "" {
			// Some providers emit positional <Data> with no Name — key them
			// param1, param2, ... so MsiInstaller mapping can reach them.
			name = fmt.Sprintf("param%d", i+1)
		}
		rec.Data[strings.ToLower(name)] = d.Value
	}
	return rec
}

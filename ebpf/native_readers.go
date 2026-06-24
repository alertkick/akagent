//go:build linux

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"time"

	"akagent/logger"
)

// StartEventListener starts reading events from all ring buffers
func (a *NativeEBPFAgent) StartEventListener(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.listening {
		return nil
	}

	if a.execveObjs == nil && a.perfExecveObjs == nil {
		return errors.New("BPF objects not loaded, call Start() first")
	}

	var err error

	// Create event readers for each program (ringbuf or perf based on output mode)
	if a.outputMode == OutputModePerf {
		a.execveReader, err = NewPerfReader(a.perfExecveObjs.Events, DefaultPerfPerCPUBuffer)
	} else {
		a.execveReader, err = NewRingBufReader(a.execveObjs.Events)
	}
	if err != nil {
		return fmt.Errorf("failed to create execve event reader: %w", err)
	}

	if a.outputMode == OutputModePerf {
		a.fileopsReader, err = NewPerfReader(a.perfFileopsObjs.FileEvents, DefaultPerfPerCPUBuffer)
	} else {
		a.fileopsReader, err = NewRingBufReader(a.fileopsObjs.FileEvents)
	}
	if err != nil {
		a.execveReader.Close()
		return fmt.Errorf("failed to create fileops event reader: %w", err)
	}

	if a.outputMode == OutputModePerf {
		a.networkReader, err = NewPerfReader(a.perfNetworkObjs.NetworkEvents, DefaultPerfPerCPUBuffer)
	} else {
		a.networkReader, err = NewRingBufReader(a.networkObjs.NetworkEvents)
	}
	if err != nil {
		a.execveReader.Close()
		a.fileopsReader.Close()
		return fmt.Errorf("failed to create network event reader: %w", err)
	}

	if a.outputMode == OutputModePerf {
		a.processReader, err = NewPerfReader(a.perfProcessObjs.ProcessEvents, DefaultPerfPerCPUBuffer)
	} else {
		a.processReader, err = NewRingBufReader(a.processObjs.ProcessEvents)
	}
	if err != nil {
		a.execveReader.Close()
		a.fileopsReader.Close()
		a.networkReader.Close()
		return fmt.Errorf("failed to create process event reader: %w", err)
	}

	// Compliance event readers
	if a.outputMode == OutputModePerf {
		a.privilegeReader, err = NewPerfReader(a.perfPrivilegeObjs.PrivilegeEvents, DefaultPerfPerCPUBuffer)
	} else {
		a.privilegeReader, err = NewRingBufReader(a.privilegeObjs.PrivilegeEvents)
	}
	if err != nil {
		a.execveReader.Close()
		a.fileopsReader.Close()
		a.networkReader.Close()
		a.processReader.Close()
		return fmt.Errorf("failed to create privilege event reader: %w", err)
	}

	if a.outputMode == OutputModePerf {
		a.mountReader, err = NewPerfReader(a.perfMountObjs.MountEvents, DefaultPerfPerCPUBuffer)
	} else {
		a.mountReader, err = NewRingBufReader(a.mountObjs.MountEvents)
	}
	if err != nil {
		a.execveReader.Close()
		a.fileopsReader.Close()
		a.networkReader.Close()
		a.processReader.Close()
		a.privilegeReader.Close()
		return fmt.Errorf("failed to create mount event reader: %w", err)
	}

	if a.outputMode == OutputModePerf {
		a.moduleReader, err = NewPerfReader(a.perfModuleObjs.ModuleEvents, DefaultPerfPerCPUBuffer)
	} else {
		a.moduleReader, err = NewRingBufReader(a.moduleObjs.ModuleEvents)
	}
	if err != nil {
		a.execveReader.Close()
		a.fileopsReader.Close()
		a.networkReader.Close()
		a.processReader.Close()
		a.privilegeReader.Close()
		a.mountReader.Close()
		return fmt.Errorf("failed to create module event reader: %w", err)
	}

	if a.outputMode == OutputModePerf {
		a.memoryReader, err = NewPerfReader(a.perfMemoryObjs.MemoryEvents, DefaultPerfPerCPUBuffer)
	} else {
		a.memoryReader, err = NewRingBufReader(a.memoryObjs.MemoryEvents)
	}
	if err != nil {
		a.execveReader.Close()
		a.fileopsReader.Close()
		a.networkReader.Close()
		a.processReader.Close()
		a.privilegeReader.Close()
		a.mountReader.Close()
		a.moduleReader.Close()
		return fmt.Errorf("failed to create memory event reader: %w", err)
	}

	if a.outputMode == OutputModePerf {
		a.dnsReader, err = NewPerfReader(a.perfDnsObjs.DnsEvents, DefaultPerfPerCPUBuffer)
	} else {
		a.dnsReader, err = NewRingBufReader(a.dnsObjs.DnsEvents)
	}
	if err != nil {
		a.execveReader.Close()
		a.fileopsReader.Close()
		a.networkReader.Close()
		a.processReader.Close()
		a.privilegeReader.Close()
		a.mountReader.Close()
		a.moduleReader.Close()
		a.memoryReader.Close()
		return fmt.Errorf("failed to create DNS event reader: %w", err)
	}

	if a.outputMode == OutputModePerf {
		a.imdsReader, err = NewPerfReader(a.perfImdsObjs.ImdsEvents, DefaultPerfPerCPUBuffer)
	} else {
		a.imdsReader, err = NewRingBufReader(a.imdsObjs.ImdsEvents)
	}
	if err != nil {
		a.execveReader.Close()
		a.fileopsReader.Close()
		a.networkReader.Close()
		a.processReader.Close()
		a.privilegeReader.Close()
		a.mountReader.Close()
		a.moduleReader.Close()
		a.memoryReader.Close()
		a.dnsReader.Close()
		return fmt.Errorf("failed to create IMDS event reader: %w", err)
	}

	if a.outputMode == OutputModePerf {
		a.bpfsyscallReader, err = NewPerfReader(a.perfBpfsyscallObjs.BpfSyscallEvents, DefaultPerfPerCPUBuffer)
	} else {
		a.bpfsyscallReader, err = NewRingBufReader(a.bpfsyscallObjs.BpfSyscallEvents)
	}
	if err != nil {
		a.execveReader.Close()
		a.fileopsReader.Close()
		a.networkReader.Close()
		a.processReader.Close()
		a.privilegeReader.Close()
		a.mountReader.Close()
		a.moduleReader.Close()
		a.memoryReader.Close()
		a.dnsReader.Close()
		a.imdsReader.Close()
		return fmt.Errorf("failed to create BPF syscall event reader: %w", err)
	}

	if a.outputMode == OutputModePerf {
		a.memfdReader, err = NewPerfReader(a.perfMemfdObjs.MemfdEvents, DefaultPerfPerCPUBuffer)
	} else {
		a.memfdReader, err = NewRingBufReader(a.memfdObjs.MemfdEvents)
	}
	if err != nil {
		a.execveReader.Close()
		a.fileopsReader.Close()
		a.networkReader.Close()
		a.processReader.Close()
		a.privilegeReader.Close()
		a.mountReader.Close()
		a.moduleReader.Close()
		a.memoryReader.Close()
		a.dnsReader.Close()
		a.imdsReader.Close()
		a.bpfsyscallReader.Close()
		return fmt.Errorf("failed to create memfd event reader: %w", err)
	}

	if a.outputMode == OutputModePerf {
		a.iouringReader, err = NewPerfReader(a.perfIouringObjs.IouringEvents, DefaultPerfPerCPUBuffer)
	} else {
		a.iouringReader, err = NewRingBufReader(a.iouringObjs.IouringEvents)
	}
	if err != nil {
		a.execveReader.Close()
		a.fileopsReader.Close()
		a.networkReader.Close()
		a.processReader.Close()
		a.privilegeReader.Close()
		a.mountReader.Close()
		a.moduleReader.Close()
		a.memoryReader.Close()
		a.dnsReader.Close()
		a.imdsReader.Close()
		a.bpfsyscallReader.Close()
		a.memfdReader.Close()
		return fmt.Errorf("failed to create io_uring event reader: %w", err)
	}

	if a.outputMode == OutputModePerf {
		a.namespaceReader, err = NewPerfReader(a.perfNamespaceObjs.NamespaceEvents, DefaultPerfPerCPUBuffer)
	} else {
		a.namespaceReader, err = NewRingBufReader(a.namespaceObjs.NamespaceEvents)
	}
	if err != nil {
		a.execveReader.Close()
		a.fileopsReader.Close()
		a.networkReader.Close()
		a.processReader.Close()
		a.privilegeReader.Close()
		a.mountReader.Close()
		a.moduleReader.Close()
		a.memoryReader.Close()
		a.dnsReader.Close()
		a.imdsReader.Close()
		a.bpfsyscallReader.Close()
		a.memfdReader.Close()
		a.iouringReader.Close()
		return fmt.Errorf("failed to create namespace event reader: %w", err)
	}

	if a.outputMode == OutputModePerf {
		a.capsReader, err = NewPerfReader(a.perfCapsObjs.CapsetEvents, DefaultPerfPerCPUBuffer)
	} else {
		a.capsReader, err = NewRingBufReader(a.capsObjs.CapsetEvents)
	}
	if err != nil {
		a.execveReader.Close()
		a.fileopsReader.Close()
		a.networkReader.Close()
		a.processReader.Close()
		a.privilegeReader.Close()
		a.mountReader.Close()
		a.moduleReader.Close()
		a.memoryReader.Close()
		a.dnsReader.Close()
		a.imdsReader.Close()
		a.bpfsyscallReader.Close()
		a.memfdReader.Close()
		a.iouringReader.Close()
		a.namespaceReader.Close()
		return fmt.Errorf("failed to create capset event reader: %w", err)
	}

	if a.outputMode == OutputModePerf {
		a.dataexfilReader, err = NewPerfReader(a.perfDataexfilObjs.DataexfilEvents, DefaultPerfPerCPUBuffer)
	} else {
		a.dataexfilReader, err = NewRingBufReader(a.dataexfilObjs.DataexfilEvents)
	}
	if err != nil {
		a.execveReader.Close()
		a.fileopsReader.Close()
		a.networkReader.Close()
		a.processReader.Close()
		a.privilegeReader.Close()
		a.mountReader.Close()
		a.moduleReader.Close()
		a.memoryReader.Close()
		a.dnsReader.Close()
		a.imdsReader.Close()
		a.bpfsyscallReader.Close()
		a.memfdReader.Close()
		a.iouringReader.Close()
		a.namespaceReader.Close()
		a.capsReader.Close()
		return fmt.Errorf("failed to create dataexfil event reader: %w", err)
	}

	if a.outputMode == OutputModePerf {
		a.diropsReader, err = NewPerfReader(a.perfDiropsObjs.DiropsEvents, DefaultPerfPerCPUBuffer)
	} else {
		a.diropsReader, err = NewRingBufReader(a.diropsObjs.DiropsEvents)
	}
	if err != nil {
		a.execveReader.Close()
		a.fileopsReader.Close()
		a.networkReader.Close()
		a.processReader.Close()
		a.privilegeReader.Close()
		a.mountReader.Close()
		a.moduleReader.Close()
		a.memoryReader.Close()
		a.dnsReader.Close()
		a.imdsReader.Close()
		a.bpfsyscallReader.Close()
		a.memfdReader.Close()
		a.iouringReader.Close()
		a.namespaceReader.Close()
		a.capsReader.Close()
		a.dataexfilReader.Close()
		return fmt.Errorf("failed to create dirops event reader: %w", err)
	}

	// Optional kprobe readers (only if BPF objects were loaded)
	kprobeReaders := 0
	if a.vfshooksObjs != nil || a.perfVfshooksObjs != nil {
		if a.outputMode == OutputModePerf && a.perfVfshooksObjs != nil {
			a.vfshooksReader, err = NewPerfReader(a.perfVfshooksObjs.VfsEvents, DefaultPerfPerCPUBuffer)
		} else if a.vfshooksObjs != nil {
			a.vfshooksReader, err = NewRingBufReader(a.vfshooksObjs.VfsEvents)
		}
		if err != nil {
			nativeLog.Warn().Err(err).Msg("Failed to create VFS hooks event reader")
		} else {
			kprobeReaders++
		}
	}

	if a.credhooksObjs != nil || a.perfCredhooksObjs != nil {
		if a.outputMode == OutputModePerf && a.perfCredhooksObjs != nil {
			a.credhooksReader, err = NewPerfReader(a.perfCredhooksObjs.CredEvents, DefaultPerfPerCPUBuffer)
		} else if a.credhooksObjs != nil {
			a.credhooksReader, err = NewRingBufReader(a.credhooksObjs.CredEvents)
		}
		if err != nil {
			nativeLog.Warn().Err(err).Msg("Failed to create credential hooks event reader")
		} else {
			kprobeReaders++
		}
	}

	// Create ioctl reader
	if a.outputMode == OutputModePerf {
		a.ioctlReader, err = NewPerfReader(a.perfIoctlObjs.IoctlEvents, DefaultPerfPerCPUBuffer)
	} else {
		a.ioctlReader, err = NewRingBufReader(a.ioctlObjs.IoctlEvents)
	}
	if err != nil {
		return fmt.Errorf("failed to create ioctl reader: %w", err)
	}

	a.listening = true
	a.shutdownChan = make(chan struct{})

	// Start reader goroutines for each ring buffer
	a.readerWg.Add(18 + kprobeReaders)
	go a.readExecveEvents()
	go a.readFileopsEvents()
	go a.readNetworkEvents()
	go a.readProcessEvents()
	go a.readPrivilegeEvents()
	go a.readMountEvents()
	go a.readModuleEvents()
	go a.readMemoryEvents()
	go a.readDnsEvents()
	go a.readImdsEvents()
	go a.readBpfSyscallEvents()
	go a.readMemfdEvents()
	go a.readIouringEvents()
	go a.readNamespaceEvents()
	go a.readCapsEvents()
	go a.readDataexfilEvents()
	go a.readDiropsEvents()
	if a.vfshooksReader != nil {
		go a.readVfshooksEvents()
	}
	if a.credhooksReader != nil {
		go a.readCredhooksEvents()
	}
	go a.readIoctlEvents()

	// Start the auth-log brute-force monitor alongside the eBPF readers.
	a.initAuthMonitor()

	// Start the periodic rootkit-indicator scanner.
	a.initRootkitScanner()

	// Start the YARA malware scanner (no-op unless YARA_RULES_PATH is set).
	a.initYara()

	// Start cache cleanup goroutine
	go a.runCacheCleanup()

	// Keep the container-name inventory warm so per-event enrichment is a
	// pure map lookup and never forks a `docker inspect`.
	go a.runInventoryRefresh()

	// Resolve sshd's listening ports once at startup, then refresh on a
	// long ticker so a sshd_config edit + `systemctl reload ssh` is picked
	// up without an agent restart. Failures are non-fatal — the reader
	// retains its last good snapshot or falls back to {22}.
	if a.sshdConfig != nil {
		if snap, err := a.sshdConfig.Refresh(); err == nil && snap != nil {
			a.fireSSHDConfigCallbacks(snap)
		}
		a.readerWg.Add(1)
		go a.runSSHDConfigRefresh()
	}

	// Start process cache cleanup goroutine
	if a.processCache != nil {
		a.readerWg.Add(1)
		go func() {
			defer a.readerWg.Done()
			a.runProcessCacheCleanup()
		}()
	}

	// Start the SSH login session heartbeat (re-emits live sessions, closes
	// exited ones). Wire the tracker's callbacks first: immediate emit for the
	// session-open event (so an untrusted login alerts at connect time), and the
	// source-IP resolver. Then re-adopt any connections already open before the
	// agent (re)started so they keep one stable session instead of orphaning.
	if a.sshSessionTracker != nil {
		a.sshSessionTracker.SetEmit(func(ev SecurityEvent) {
			select {
			case a.eventChan <- ev:
			default:
				a.recordDroppedEvent()
			}
		})
		if a.sshHydrator != nil {
			a.sshSessionTracker.SetResolveIPFunc(a.sshHydrator.ResolveForPID)
		}
		a.sshSessionTracker.Readopt(a.processCache)

		a.readerWg.Add(1)
		go func() {
			defer a.readerWg.Done()
			a.runSSHSessionHeartbeat()
		}()
	}

	nativeLog.Info().Msg("Native eBPF event listener started")
	return nil
}

// StopEventListener stops reading events
func (a *NativeEBPFAgent) StopEventListener() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.listening {
		return nil
	}

	// Signal shutdown
	close(a.shutdownChan)

	// Close all readers to unblock Read() calls
	if a.execveReader != nil {
		a.execveReader.Close()
		a.execveReader = nil
	}
	if a.fileopsReader != nil {
		a.fileopsReader.Close()
		a.fileopsReader = nil
	}
	if a.networkReader != nil {
		a.networkReader.Close()
		a.networkReader = nil
	}
	if a.processReader != nil {
		a.processReader.Close()
		a.processReader = nil
	}
	// Compliance readers
	if a.privilegeReader != nil {
		a.privilegeReader.Close()
		a.privilegeReader = nil
	}
	if a.mountReader != nil {
		a.mountReader.Close()
		a.mountReader = nil
	}
	if a.moduleReader != nil {
		a.moduleReader.Close()
		a.moduleReader = nil
	}
	if a.memoryReader != nil {
		a.memoryReader.Close()
		a.memoryReader = nil
	}
	if a.dnsReader != nil {
		a.dnsReader.Close()
		a.dnsReader = nil
	}
	if a.imdsReader != nil {
		a.imdsReader.Close()
		a.imdsReader = nil
	}
	if a.bpfsyscallReader != nil {
		a.bpfsyscallReader.Close()
		a.bpfsyscallReader = nil
	}
	if a.memfdReader != nil {
		a.memfdReader.Close()
		a.memfdReader = nil
	}
	if a.iouringReader != nil {
		a.iouringReader.Close()
		a.iouringReader = nil
	}
	if a.namespaceReader != nil {
		a.namespaceReader.Close()
		a.namespaceReader = nil
	}
	if a.capsReader != nil {
		a.capsReader.Close()
		a.capsReader = nil
	}
	if a.dataexfilReader != nil {
		a.dataexfilReader.Close()
		a.dataexfilReader = nil
	}
	if a.diropsReader != nil {
		a.diropsReader.Close()
		a.diropsReader = nil
	}
	if a.vfshooksReader != nil {
		a.vfshooksReader.Close()
		a.vfshooksReader = nil
	}
	if a.credhooksReader != nil {
		a.credhooksReader.Close()
		a.credhooksReader = nil
	}
	if a.ioctlReader != nil {
		a.ioctlReader.Close()
		a.ioctlReader = nil
	}

	// Wait for all reader goroutines to finish
	a.readerWg.Wait()

	a.listening = false
	nativeLog.Info().Msg("Native eBPF event listener stopped")
	return nil
}

// EventChannel returns the channel for receiving security events
func (a *NativeEBPFAgent) EventChannel() <-chan SecurityEvent {
	return a.eventChan
}

// IsListening returns whether the event listener is active
func (a *NativeEBPFAgent) IsListening() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.listening
}

// sendEvent sends an event to the channel (non-blocking) after applying filters, enrichment, and alerts
func (a *NativeEBPFAgent) sendEvent(event SecurityEvent) {
	// Apply basic filter (category, UID, process name, path)
	if !a.filter.ShouldInclude(&event) {
		return
	}

	// Process-lineage enrichment, SSH hydration, and session tracking run
	// BEFORE the alert/noise filter and rate limiter. The session tracker must
	// observe the full execve stream to attribute in-session commands and
	// (when enabled) capture their redacted argv — the per-rule rate limiter is
	// a host-global throttle on "Process Execution" meant to cap alert volume,
	// not session bookkeeping, and would otherwise starve the tracker on busy
	// hosts. Lineage enrichment here is a cheap process-cache lookup; the
	// heavier container/namespace enrichment stays after the rate limiter so it
	// never runs on events that get dropped.
	if a.processCache != nil {
		a.processCache.Enrich(&event)
	}

	// Stamp SSH source IP when the event is a shell process spawned by
	// sshd. Quietly no-ops for everything else, so calling unconditionally
	// is fine.
	if a.sshHydrator != nil {
		a.sshHydrator.HydrateSSHLogin(&event)
	}

	// Track inbound SSH login sessions: open a session on the login shell
	// (which the hydrator just stamped), and attribute processes run beneath
	// it. Runs after the hydrator so it sees ssh_login/ssh_source_ip. The
	// command-capture toggle gates whether argv is recorded (redacted).
	if a.sshSessionTracker != nil {
		a.sshSessionTracker.OnEvent(&event, a.processCache, a.GetNativeConfig().SSHSessionCommandCapture)
	}

	// Apply alert filter (semantic filtering - drops noise like signal 0)
	if !a.alertFilter.ShouldAlert(&event) {
		return
	}

	// Apply per-rule rate limiting (high-priority events bypass rate limiting).
	// Session start/heartbeat events are stamped high-priority so they bypass
	// this; ordinary in-session command events may be dropped from emission
	// here, but their command was already captured by OnEvent above.
	if !event.IsHighPriority() && !a.rateLimiter.Allow(event.Rule) {
		return
	}

	// Enrich with container and namespace info
	a.enricher.Enrich(&event)

	// For network events, stamp is_ssh_port=true when src/dst port matches
	// any port sshd is listening on. Endpoint matchers consult this flag
	// instead of literal 22, so a non-default SSHD Port (2222, 2200, etc.)
	// is correctly classified as SSH traffic.
	if a.sshdConfig != nil && event.Category == "network" {
		snap := a.sshdConfig.Snapshot()
		dport, hasDPort := lookupRawPort(event.RawFields, "dport")
		sport, hasSPort := lookupRawPort(event.RawFields, "sport")
		isSSH := false
		if hasDPort && snap.HasPort(int(dport)) {
			isSSH = true
		}
		if hasSPort && snap.HasPort(int(sport)) {
			isSSH = true
		}
		if isSSH {
			if event.RawFields == nil {
				event.RawFields = make(map[string]interface{})
			}
			event.RawFields["is_ssh_port"] = true
		}
	}

	// Send event to channel (non-blocking)
	// Note: All alert rules, compliance logic, and priority elevation
	// is handled by apapi after receiving the event
	select {
	case a.eventChan <- event:
		if logger.IsSectionEnabled(logger.SectionEBPF) {
			nativeLog.Debug().Msgf("Sent event: %s (pid=%d, priority=%s)", event.Rule, event.Process.PID, event.Priority)
		}
	default:
		a.recordDroppedEvent()
	}
}

// recordDroppedEvent tallies one event dropped because eventChan was full.
// The count is logged in aggregate by reportDroppedEvents on the maintenance
// tick — never per drop — so a saturated channel can't flood the journal.
func (a *NativeEBPFAgent) recordDroppedEvent() {
	a.droppedEvents.Add(1)
}

// reportDroppedEvents emits a single aggregated warning for events dropped
// since the last call, and resets the counter. No-op when nothing was dropped.
func (a *NativeEBPFAgent) reportDroppedEvents(window time.Duration) {
	if n := a.droppedEvents.Swap(0); n > 0 {
		nativeLog.Warn().
			Uint64("dropped", n).
			Dur("window", window).
			Msg("Event channel saturated — dropping events (aggregated)")
	}
}

// GetFilterStats returns the filter statistics (total events, filtered events)
func (a *NativeEBPFAgent) GetFilterStats() (total, filtered uint64) {
	return a.filter.Stats()
}

// GetAlertFilterStats returns the alert filter statistics
func (a *NativeEBPFAgent) GetAlertFilterStats() AlertFilterStats {
	return a.alertFilter.Stats()
}

// GetRateLimiterStats returns per-rule rate limiting statistics
func (a *NativeEBPFAgent) GetRateLimiterStats() RateLimiterStats {
	return a.rateLimiter.Stats()
}

// GetEnrichmentStats returns enrichment cache statistics
func (a *NativeEBPFAgent) GetEnrichmentStats() (containerCacheSize, namespaceCacheSize int) {
	return a.enricher.CacheSize()
}

// containerInventoryRefreshInterval is how often the enricher relists running
// containers to refresh its name inventory.
const containerInventoryRefreshInterval = 30 * time.Second

// runInventoryRefresh periodically rebuilds the enricher's container inventory
// so per-event enrichment never forks a `docker inspect`. It warms the cache
// once up front, then refreshes on a ticker until shutdown.
func (a *NativeEBPFAgent) runInventoryRefresh() {
	if a.enricher == nil {
		return
	}
	refresh := func() {
		if !a.enricher.IsEnabled() {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		a.enricher.RefreshInventory(ctx)
	}
	refresh()

	ticker := time.NewTicker(containerInventoryRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-a.shutdownChan:
			return
		case <-ticker.C:
			refresh()
		}
	}
}

// runCacheCleanup periodically cleans up the enrichment cache
func (a *NativeEBPFAgent) runCacheCleanup() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.shutdownChan:
			return
		case <-ticker.C:
			a.enricher.CleanupCache()
			a.reportDroppedEvents(60 * time.Second)
			if logger.IsSectionEnabled(logger.SectionEBPF) {
				containers, namespaces := a.enricher.CacheSize()
				nativeLog.Debug().Int("containers", containers).Int("namespaces", namespaces).Msg("Cleaned enrichment cache")
			}
		}
	}
}

// lookupRawPort coerces the raw_fields port representation into a
// uint16. eBPF parsers stuff ports in as int32/uint16/etc. depending on
// the syscall; this helper covers every shape the agent emits.
func lookupRawPort(fields map[string]interface{}, key string) (uint16, bool) {
	v, ok := fields[key]
	if !ok {
		return 0, false
	}
	switch p := v.(type) {
	case uint16:
		return p, true
	case int:
		return uint16(p), true
	case int32:
		return uint16(p), true
	case int64:
		return uint16(p), true
	case uint32:
		return uint16(p), true
	case uint64:
		return uint16(p), true
	case float64:
		return uint16(p), true
	}
	return 0, false
}

// runSSHDConfigRefresh re-parses sshd_config on a ticker so a Port edit
// followed by sshd reload is picked up by the agent without restart. The
// refresh interval is long (5 min) because sshd_config changes are rare
// and parsing is cheap when nothing changed.
func (a *NativeEBPFAgent) runSSHDConfigRefresh() {
	defer a.readerWg.Done()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-a.shutdownChan:
			return
		case <-ticker.C:
			snap, err := a.sshdConfig.Refresh()
			if err != nil {
				if logger.IsSectionEnabled(logger.SectionEBPF) {
					nativeLog.Debug().Err(err).Msg("sshd_config refresh failed; retaining last snapshot")
				}
				continue
			}
			if snap != nil {
				if logger.IsSectionEnabled(logger.SectionEBPF) {
					nativeLog.Debug().Ints("ports", snap.Ports).Msg("sshd_config refreshed")
				}
				a.fireSSHDConfigCallbacks(snap)
			}
		}
	}
}

// runSSHSessionHeartbeat periodically re-emits each tracked SSH login session
// so its lifecycle (process count, last activity, and eventual logout/duration)
// stays current on the dashboard — the API upserts these on the session uuid.
// Closed sessions are evicted by sweep. Panic-recovered so a bug in session
// bookkeeping can never take down the agent (the 1.7.x serial-consumer lesson).
func (a *NativeEBPFAgent) runSSHSessionHeartbeat() {
	defer func() {
		if r := recover(); r != nil {
			nativeLog.Error().Interface("panic", r).Msg("SSH session heartbeat panicked; sessions will not refresh until restart")
		}
	}()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.shutdownChan:
			return
		case <-ticker.C:
			if a.sshSessionTracker == nil {
				continue
			}
			capture := a.GetNativeConfig().SSHSessionCommandCapture
			events := a.sshSessionTracker.sweep(time.Now(), a.processCache, capture)
			for i := range events {
				// Emit directly to the channel (non-blocking, same backpressure
				// as sendEvent) — these are synthetic audit events and must not
				// run the source filters that drop ordinary noise.
				select {
				case a.eventChan <- events[i]:
				default:
					a.recordDroppedEvent()
				}
			}
		}
	}
}

// runProcessCacheCleanup periodically cleans expired entries from the process cache
func (a *NativeEBPFAgent) runProcessCacheCleanup() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.shutdownChan:
			return
		case <-ticker.C:
			if a.processCache != nil {
				a.processCache.Cleanup()
				if logger.IsSectionEnabled(logger.SectionEBPF) {
					nativeLog.Debug().Int("entries", a.processCache.CacheSize()).Msg("Process cache cleanup complete")
				}
			}
		}
	}
}

// readExecveEvents reads events from the execve ring buffer
func (a *NativeEBPFAgent) readExecveEvents() {
	defer a.readerWg.Done()
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Starting execve event reader")
	}

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		data, err := a.execveReader.Read()
		if err != nil {
			if errors.Is(err, ErrReaderClosed) {
				return
			}
			nativeLog.Warn().Err(err).Msg("Error reading from execve ring buffer")
			continue
		}

		event, err := a.parseExecveEvent(data)
		if err != nil {
			if logger.IsSectionEnabled(logger.SectionEBPF) {
				nativeLog.Debug().Err(err).Msg("Error parsing execve event")
			}
			continue
		}

		a.sendEvent(event)

		// Queue the executable for YARA scanning (no-op unless configured).
		a.yaraScan(event.Process.ExePath)
	}
}

// readFileopsEvents reads events from the fileops ring buffer
func (a *NativeEBPFAgent) readFileopsEvents() {
	defer a.readerWg.Done()
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Starting fileops event reader")
	}

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		data, err := a.fileopsReader.Read()
		if err != nil {
			if errors.Is(err, ErrReaderClosed) {
				return
			}
			nativeLog.Warn().Err(err).Msg("Error reading from fileops ring buffer")
			continue
		}

		event, err := a.parseFileopsEvent(data)
		if err != nil {
			if logger.IsSectionEnabled(logger.SectionEBPF) {
				nativeLog.Debug().Err(err).Msg("Error parsing fileops event")
			}
			continue
		}

		a.sendEvent(event)

		// Route write-ish events on baselined paths to the integrity monitor,
		// which debounces and re-hashes to detect content changes.
		a.fimNotify(&event)
	}
}

// readNetworkEvents reads events from the network ring buffer
func (a *NativeEBPFAgent) readNetworkEvents() {
	defer a.readerWg.Done()
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Starting network event reader")
	}

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		data, err := a.networkReader.Read()
		if err != nil {
			if errors.Is(err, ErrReaderClosed) {
				return
			}
			nativeLog.Warn().Err(err).Msg("Error reading from network ring buffer")
			continue
		}

		event, err := a.parseNetworkEvent(data)
		if err != nil {
			if logger.IsSectionEnabled(logger.SectionEBPF) {
				nativeLog.Debug().Err(err).Msg("Error parsing network event")
			}
			continue
		}

		a.sendEvent(event)
	}
}

// readProcessEvents reads events from the process ring buffer
func (a *NativeEBPFAgent) readProcessEvents() {
	defer a.readerWg.Done()
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Starting process event reader")
	}

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		data, err := a.processReader.Read()
		if err != nil {
			if errors.Is(err, ErrReaderClosed) {
				return
			}
			nativeLog.Warn().Err(err).Msg("Error reading from process ring buffer")
			continue
		}

		event, err := a.parseProcessEvent(data)
		if err != nil {
			if logger.IsSectionEnabled(logger.SectionEBPF) {
				nativeLog.Debug().Err(err).Msg("Error parsing process event")
			}
			continue
		}

		a.sendEvent(event)
	}
}

// readPrivilegeEvents reads events from the privilege ring buffer
func (a *NativeEBPFAgent) readPrivilegeEvents() {
	defer a.readerWg.Done()
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Starting privilege event reader")
	}

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		data, err := a.privilegeReader.Read()
		if err != nil {
			if errors.Is(err, ErrReaderClosed) {
				return
			}
			nativeLog.Warn().Err(err).Msg("Error reading from privilege ring buffer")
			continue
		}

		event, err := a.parsePrivilegeEvent(data)
		if err != nil {
			if logger.IsSectionEnabled(logger.SectionEBPF) {
				nativeLog.Debug().Err(err).Msg("Error parsing privilege event")
			}
			continue
		}

		a.sendEvent(event)
	}
}

// readMountEvents reads events from the mount ring buffer
func (a *NativeEBPFAgent) readMountEvents() {
	defer a.readerWg.Done()
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Starting mount event reader")
	}

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		data, err := a.mountReader.Read()
		if err != nil {
			if errors.Is(err, ErrReaderClosed) {
				return
			}
			nativeLog.Warn().Err(err).Msg("Error reading from mount ring buffer")
			continue
		}

		event, err := a.parseMountEvent(data)
		if err != nil {
			if logger.IsSectionEnabled(logger.SectionEBPF) {
				nativeLog.Debug().Err(err).Msg("Error parsing mount event")
			}
			continue
		}

		a.sendEvent(event)
	}
}

// readModuleEvents reads events from the module ring buffer
func (a *NativeEBPFAgent) readModuleEvents() {
	defer a.readerWg.Done()
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Starting module event reader")
	}

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		data, err := a.moduleReader.Read()
		if err != nil {
			if errors.Is(err, ErrReaderClosed) {
				return
			}
			nativeLog.Warn().Err(err).Msg("Error reading from module ring buffer")
			continue
		}

		event, err := a.parseModuleEvent(data)
		if err != nil {
			if logger.IsSectionEnabled(logger.SectionEBPF) {
				nativeLog.Debug().Err(err).Msg("Error parsing module event")
			}
			continue
		}

		a.sendEvent(event)
	}
}

// readMemoryEvents reads events from the memory ring buffer
func (a *NativeEBPFAgent) readMemoryEvents() {
	defer a.readerWg.Done()
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Starting memory event reader")
	}

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		data, err := a.memoryReader.Read()
		if err != nil {
			if errors.Is(err, ErrReaderClosed) {
				return
			}
			nativeLog.Warn().Err(err).Msg("Error reading from memory ring buffer")
			continue
		}

		event, err := a.parseMemoryEvent(data)
		if err != nil {
			if logger.IsSectionEnabled(logger.SectionEBPF) {
				nativeLog.Debug().Err(err).Msg("Error parsing memory event")
			}
			continue
		}

		a.sendEvent(event)
	}
}

// readDnsEvents reads events from the DNS ring buffer
func (a *NativeEBPFAgent) readDnsEvents() {
	defer a.readerWg.Done()
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Starting DNS event reader")
	}

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		data, err := a.dnsReader.Read()
		if err != nil {
			if errors.Is(err, ErrReaderClosed) {
				return
			}
			nativeLog.Warn().Err(err).Msg("Error reading from DNS ring buffer")
			continue
		}

		event, err := a.parseDnsEvent(data)
		if err != nil {
			if logger.IsSectionEnabled(logger.SectionEBPF) {
				nativeLog.Debug().Err(err).Msg("Error parsing DNS event")
			}
			continue
		}

		a.sendEvent(event)
	}
}

// readImdsEvents reads events from the IMDS ring buffer
func (a *NativeEBPFAgent) readImdsEvents() {
	defer a.readerWg.Done()
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Starting IMDS event reader")
	}

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		data, err := a.imdsReader.Read()
		if err != nil {
			if errors.Is(err, ErrReaderClosed) {
				return
			}
			nativeLog.Warn().Err(err).Msg("Error reading from IMDS ring buffer")
			continue
		}

		event, err := a.parseImdsEvent(data)
		if err != nil {
			if logger.IsSectionEnabled(logger.SectionEBPF) {
				nativeLog.Debug().Err(err).Msg("Error parsing IMDS event")
			}
			continue
		}

		a.sendEvent(event)
	}
}

// readBpfSyscallEvents reads events from the BPF syscall ring buffer
func (a *NativeEBPFAgent) readBpfSyscallEvents() {
	defer a.readerWg.Done()
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Starting BPF syscall event reader")
	}

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		data, err := a.bpfsyscallReader.Read()
		if err != nil {
			if errors.Is(err, ErrReaderClosed) {
				return
			}
			nativeLog.Warn().Err(err).Msg("Error reading from BPF syscall ring buffer")
			continue
		}

		event, err := a.parseBpfSyscallEvent(data)
		if err != nil {
			if logger.IsSectionEnabled(logger.SectionEBPF) {
				nativeLog.Debug().Err(err).Msg("Error parsing BPF syscall event")
			}
			continue
		}

		a.sendEvent(event)
	}
}

// readMemfdEvents reads events from the memfd/execveat ring buffer
func (a *NativeEBPFAgent) readMemfdEvents() {
	defer a.readerWg.Done()
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Starting memfd/execveat event reader")
	}

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		data, err := a.memfdReader.Read()
		if err != nil {
			if errors.Is(err, ErrReaderClosed) {
				return
			}
			nativeLog.Warn().Err(err).Msg("Error reading from memfd ring buffer")
			continue
		}

		event, err := a.parseMemfdEvent(data)
		if err != nil {
			if logger.IsSectionEnabled(logger.SectionEBPF) {
				nativeLog.Debug().Err(err).Msg("Error parsing memfd event")
			}
			continue
		}

		a.sendEvent(event)
	}
}

// readIouringEvents reads events from the io_uring ring buffer
func (a *NativeEBPFAgent) readIouringEvents() {
	defer a.readerWg.Done()
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Starting io_uring event reader")
	}

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		data, err := a.iouringReader.Read()
		if err != nil {
			if errors.Is(err, ErrReaderClosed) {
				return
			}
			nativeLog.Warn().Err(err).Msg("Error reading from io_uring ring buffer")
			continue
		}

		event, err := a.parseIouringEvent(data)
		if err != nil {
			if logger.IsSectionEnabled(logger.SectionEBPF) {
				nativeLog.Debug().Err(err).Msg("Error parsing io_uring event")
			}
			continue
		}

		a.sendEvent(event)
	}
}

// readNamespaceEvents reads events from the namespace ring buffer
func (a *NativeEBPFAgent) readNamespaceEvents() {
	defer a.readerWg.Done()
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Starting namespace event reader")
	}

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		data, err := a.namespaceReader.Read()
		if err != nil {
			if errors.Is(err, ErrReaderClosed) {
				return
			}
			nativeLog.Warn().Err(err).Msg("Error reading from namespace ring buffer")
			continue
		}

		event, err := a.parseNamespaceEvent(data)
		if err != nil {
			if logger.IsSectionEnabled(logger.SectionEBPF) {
				nativeLog.Debug().Err(err).Msg("Error parsing namespace event")
			}
			continue
		}

		a.sendEvent(event)
	}
}

// readCapsEvents reads events from the capability ring buffer
func (a *NativeEBPFAgent) readCapsEvents() {
	defer a.readerWg.Done()
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Starting capability event reader")
	}

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		data, err := a.capsReader.Read()
		if err != nil {
			if errors.Is(err, ErrReaderClosed) {
				return
			}
			nativeLog.Warn().Err(err).Msg("Error reading from capability ring buffer")
			continue
		}

		event, err := a.parseCapsEvent(data)
		if err != nil {
			if logger.IsSectionEnabled(logger.SectionEBPF) {
				nativeLog.Debug().Err(err).Msg("Error parsing capability event")
			}
			continue
		}

		a.sendEvent(event)
	}
}

// readDataexfilEvents reads events from the data exfiltration ring buffer
func (a *NativeEBPFAgent) readDataexfilEvents() {
	defer a.readerWg.Done()
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Starting data exfiltration event reader")
	}

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		data, err := a.dataexfilReader.Read()
		if err != nil {
			if errors.Is(err, ErrReaderClosed) {
				return
			}
			nativeLog.Warn().Err(err).Msg("Error reading from dataexfil ring buffer")
			continue
		}

		event, err := a.parseDataexfilEvent(data)
		if err != nil {
			if logger.IsSectionEnabled(logger.SectionEBPF) {
				nativeLog.Debug().Err(err).Msg("Error parsing dataexfil event")
			}
			continue
		}

		a.sendEvent(event)
	}
}

// readDiropsEvents reads events from the directory operations ring buffer
func (a *NativeEBPFAgent) readDiropsEvents() {
	defer a.readerWg.Done()
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Starting directory operations event reader")
	}

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		data, err := a.diropsReader.Read()
		if err != nil {
			if errors.Is(err, ErrReaderClosed) {
				return
			}
			nativeLog.Warn().Err(err).Msg("Error reading from dirops ring buffer")
			continue
		}

		event, err := a.parseDiropsEvent(data)
		if err != nil {
			if logger.IsSectionEnabled(logger.SectionEBPF) {
				nativeLog.Debug().Err(err).Msg("Error parsing dirops event")
			}
			continue
		}

		a.sendEvent(event)
	}
}

// readVfshooksEvents reads events from the VFS hooks kprobe ring buffer
func (a *NativeEBPFAgent) readVfshooksEvents() {
	defer a.readerWg.Done()
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Starting VFS hooks event reader")
	}

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		data, err := a.vfshooksReader.Read()
		if err != nil {
			if errors.Is(err, ErrReaderClosed) {
				return
			}
			nativeLog.Warn().Err(err).Msg("Error reading from VFS hooks ring buffer")
			continue
		}

		event, err := a.parseVfshooksEvent(data)
		if err != nil {
			if logger.IsSectionEnabled(logger.SectionEBPF) {
				nativeLog.Debug().Err(err).Msg("Error parsing VFS hooks event")
			}
			continue
		}

		a.sendEvent(event)
	}
}

// readCredhooksEvents reads events from the credential hooks kprobe ring buffer
func (a *NativeEBPFAgent) readCredhooksEvents() {
	defer a.readerWg.Done()
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Starting credential hooks event reader")
	}

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		data, err := a.credhooksReader.Read()
		if err != nil {
			if errors.Is(err, ErrReaderClosed) {
				return
			}
			nativeLog.Warn().Err(err).Msg("Error reading from credential hooks ring buffer")
			continue
		}

		event, err := a.parseCredhooksEvent(data)
		if err != nil {
			if logger.IsSectionEnabled(logger.SectionEBPF) {
				nativeLog.Debug().Err(err).Msg("Error parsing credential hooks event")
			}
			continue
		}

		a.sendEvent(event)
	}
}

// readIoctlEvents reads events from the ioctl ring buffer
func (a *NativeEBPFAgent) readIoctlEvents() {
	defer a.readerWg.Done()
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Starting ioctl event reader")
	}

	for {
		select {
		case <-a.shutdownChan:
			return
		default:
		}

		data, err := a.ioctlReader.Read()
		if err != nil {
			if errors.Is(err, ErrReaderClosed) {
				return
			}
			nativeLog.Warn().Err(err).Msg("Error reading from ioctl ring buffer")
			continue
		}

		event, err := a.parseIoctlEvent(data)
		if err != nil {
			if logger.IsSectionEnabled(logger.SectionEBPF) {
				nativeLog.Debug().Err(err).Msg("Error parsing ioctl event")
			}
			continue
		}

		a.sendEvent(event)
	}
}

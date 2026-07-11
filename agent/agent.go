package agent

import (
	"akagent/checker"
	"akagent/checks"
	"akagent/client"
	"akagent/config"
	"akagent/internal/api"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"encoding/gob"
	"os"

	"github.com/rs/zerolog"
)

const (
	checkResultQueueFile = "check_results_queue.bin"
)

func init() {
	gob.Register(api.CheckMetricParams{})
	gob.Register(api.MetricGroup{})
	gob.Register(api.Metric{})
}

type agent struct {
	conn               *client.Pool
	agentToken         string
	AgentID            string
	AgentName          string
	Subdomain          string
	Tenant             string
	timeout            int
	heartbeatInterval  int
	sentHeartbeatCount int
	debug              bool
	checkerManager     *checker.CheckerManager
	wg                 sync.WaitGroup
	log                zerolog.Logger
	shutdown           chan struct{}
	ctx                context.Context
	cancelFunc         context.CancelFunc

	// Check result queue
	checkResultQueue        []api.CheckMetricParams
	checkResultQueueMutex   sync.Mutex
	checkResultMaxQueueSize int

	// Agent version (injected at build time)
	version string

	// Platform-specific fields (populated in agent_ebpf_linux.go)
	platformData platformAgentData
}

func NewAgentClient(conf *config.Config, kernalVersion string, log zerolog.Logger, version string) (*agent, error) {

	RPCConn := client.NewPool(conf, log, version)
	ctx, cancel := context.WithCancel(context.Background())

	a := agent{
		log:                     log,
		conn:                    RPCConn,
		AgentID:                 conf.AgentID,
		AgentName:               conf.AgentName,
		Subdomain:               conf.Subdomain,
		Tenant:                  conf.Subdomain,
		agentToken:              conf.AgentToken,
		version:                 version,
		heartbeatInterval:       10,
		sentHeartbeatCount:      0,
		timeout:                 10,
		ctx:                     ctx,
		cancelFunc:              cancel,
		checkResultQueue:        make([]api.CheckMetricParams, 0, 1000),
		checkResultMaxQueueSize: 1000,
	}

	a.platformData = newPlatformAgentData()

	if conf.Debug {
		a.debug = true
		a.log.Debug().Msgf("agent.NewAgentClient - debug value: %t", a.debug)
	} else {
		a.debug = false
	}

	// Load any saved check results
	if err := a.loadCheckResultQueue(); err != nil {
		a.log.Warn().Err(err).Msg("agent.NewAgentClient - failed to load saved check results")
	}

	return &a, nil
}

// Run starts the agent
func (a *agent) Run(shutdown chan struct{}) error {
	a.shutdown = shutdown
	ctx, cancel := context.WithCancel(context.Background())
	a.ctx = ctx
	a.cancelFunc = cancel
	defer cancel()

	a.log.Debug().Msg("agent.Run - start")

	requestWatcherShutdown := make(chan struct{})
	a.wg.Add(1)
	go a.StartWatchingServerRequests(requestWatcherShutdown, &a.wg)

	a.log.Debug().Msg("agent.Run - starting checker manager")
	baseChecks := checks.BaseConfiguredChecks()
	a.checkerManager = checker.NewCheckerManager(ctx, baseChecks, a.debug)
	a.wg.Add(1)
	go a.StartResultSender(shutdown, &a.wg)
	go a.checkerManager.Start()

	// Initialize platform-specific eBPF agent (Linux only, no-op on other platforms)
	a.initEBPF(ctx)

	// Start platform-specific eBPF event sender
	ebpfShutdown := make(chan struct{})
	a.startEBPFSender(ebpfShutdown)

	// Wait for shutdown signal
	<-shutdown
	close(ebpfShutdown)
	a.log.Debug().Msg("agent.Run - Shutdown signal received")
	a.shutdownEBPF(ctx)

	a.log.Debug().Msg("agent.Run - Shutdown signal received, shutting down")
	close(requestWatcherShutdown)
	cancel()
	a.Shutdown()
	a.wg.Wait()
	return nil
}

// Shutdown closes the rpc connection
func (a *agent) Shutdown() error {
	// Save any pending check results
	if err := a.saveCheckResultQueue(); err != nil {
		a.log.Warn().Err(err).Msg("agent.Shutdown - failed to save check results queue")
	}

	a.log.Info().Msg("agent.Shutdown - shutting down eBPF events watcher...")
	a.log.Info().Msg("agent.Shutdown - shutting down open connections...")
	return a.conn.Close()
}

// ServerReqHandler - watches ServerReqChan of conn and handles server requests depending on method of the request
func (a *agent) StartWatchingServerRequests(requestWatcherShutdown chan struct{}, wg *sync.WaitGroup) {
	a.log.Debug().Msg("agent.StartWatchingServerRequests - start")
	defer wg.Done()

	for {
		select {
		case <-requestWatcherShutdown:
			a.log.Debug().Msg("agent.StartWatchingServerRequests - stopping")
			return
		case req := <-a.conn.ServerReqChan:
			err := a.HandleServerRequest(req)
			if err != nil {
				a.log.Err(err).Msg("agent.StartWatchingServerRequests - error handling message")
			}
		}
	}
}

// HandleServerRequest - handles requests from the server.
func (a *agent) HandleServerRequest(req client.Request) error {
	a.log.Info().Msgf("agent.HandleServerRequest - received request with method: %s", req.Method)
	a.log.Debug().Msgf("agent.HandleServerRequest - request: %v", req)

	switch req.Method {
	case "system.info":
		a.log.Debug().Msg("agent.HandleServerRequest - received system.info request")
		a.handleSystemInfoRequest(req)
		a.CheckScheduleGet()
		// Fetch/apply of the stored native config can take a while (and once
		// deadlocked outright); run it off the dispatcher goroutine so a slow
		// apply can never freeze handling of every subsequent server request.
		a.goHandle("system.info.stored-config", req, a.onSystemInfo)
	case "agent.refresh_check_profiles":
		a.log.Debug().Msg("agent.HandleServerRequest - received refresh_check_profiles request")
		a.handleRefreshCheckProfilesRequest(req)
	case "agent.refresh_checks":
		a.log.Debug().Msg("agent.HandleServerRequest - received refresh_checks request")
		a.handleRefreshChecksRequest(req)
	case "agent.restart":
		a.log.Info().Msg("agent.HandleServerRequest - received restart request")
		a.handleAgentRestartRequest(req)
	case "host_info_types.get":
		a.log.Debug().Msg("agent.HandleServerRequest - received host_info_types.get request")
	default:
		// Try platform-specific eBPF handlers (Linux only)
		if !a.handleEBPFRequest(req) {
			a.log.Warn().Msgf("agent.HandleServerRequest - unknown method: %s", req.Method)
			a.handleUnknownMethod(req)
		}
	}
	return nil
}

func (a *agent) handleUnknownMethod(req client.Request) {
	a.log.Warn().Msgf("agent.handleUnknownMethod - unknown method: %s", req.Method)
	msg := client.Response{
		Version:   "1",
		ID:        req.ID,
		Target:    "agent",
		Source:    a.AgentID,
		Tenant:    a.Subdomain,
		Subdomain: a.Subdomain,
		Result:    json.RawMessage("{\"error\": \"unknown method\"}"),
	}
	err := a.conn.SendJSONMessageNoResponse(msg)
	if err != nil {
		a.log.Err(err).Msg("agent.handleUnknownMethod - error during unknown method submit")
	}
}

func (a *agent) handleSystemInfoRequest(req client.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	a.log.Debug().Msg("agent.handleSystemInfoRequest - collecting systemInfo")
	systemInfo := checks.CollectSystemInfo(ctx)

	msg := client.Response{
		Version:   "1",
		ID:        req.ID,
		Target:    "system.info",
		Source:    a.AgentID,
		Tenant:    a.Subdomain,
		Subdomain: a.Subdomain,
		Result:    json.RawMessage(systemInfo.String()),
	}

	err := a.conn.SendJSONMessageNoResponse(msg)
	if err != nil {
		a.log.Err(err).Msg("agent.handleSystemInfoRequest - error during systemInfo submit")
		return
	}
}

func (a *agent) handleRefreshCheckProfilesRequest(req client.Request) {
	a.log.Debug().Msg("agent.handleRefreshCheckProfilesRequest - received refresh_check_profiles request")
	a.CheckScheduleGet()

	response := client.GeneralCommandResponse{
		Message: "Check profiles updated",
		Status:  "success",
		Error:   "",
	}

	msg := client.Response{
		Version:   "1",
		ID:        req.ID,
		Target:    "agent.refresh_check_profiles",
		Source:    a.AgentID,
		Tenant:    a.Subdomain,
		Subdomain: a.Subdomain,
		Result:    json.RawMessage(response.String()),
	}

	err := a.conn.SendJSONMessageNoResponse(msg)
	if err != nil {
		a.log.Err(err).Msg("agent.handleRefreshCheckProfilesRequest - error during `refresh_check_profiles` submit")
		return
	}
}

func (a *agent) handleRefreshChecksRequest(req client.Request) {
	a.log.Debug().Msg("agent.handleRefreshChecksRequest - received refresh_checks request")
	a.CheckScheduleGet()

	response := client.GeneralCommandResponse{
		Message: "Check profiles updated",
		Status:  "success",
		Error:   "",
	}

	msg := client.Response{
		Version:   "1",
		ID:        req.ID,
		Target:    "agent.refresh_checks",
		Source:    a.AgentID,
		Tenant:    a.Subdomain,
		Subdomain: a.Subdomain,
		Result:    json.RawMessage(response.String()),
	}

	err := a.conn.SendJSONMessageNoResponse(msg)
	if err != nil {
		a.log.Err(err).Msg("agent.handleRefreshChecksRequest - error during `refresh_checks` submit")
		return
	}
}

// handleAgentRestartRequest acks the restart command and then exits the
// process so systemd's Restart=always brings it back up. The 500ms sleep
// before exit gives the websocket frame time to flush — without it the API
// sees the command stuck in "pending" because the connection drops mid-write.
//
// Non-systemd installs (dev/macOS/Windows) won't auto-recover; documented as
// a known limitation.
func (a *agent) handleAgentRestartRequest(req client.Request) {
	a.log.Info().Msg("agent.handleAgentRestartRequest - acking restart, will exit shortly")

	response := client.GeneralCommandResponse{
		Message: "Agent restarting",
		Status:  "success",
		Error:   "",
	}

	msg := client.Response{
		Version:   "1",
		ID:        req.ID,
		Target:    "agent.restart",
		Source:    a.AgentID,
		Tenant:    a.Subdomain,
		Subdomain: a.Subdomain,
		Result:    json.RawMessage(response.String()),
	}

	if err := a.conn.SendJSONMessageNoResponse(msg); err != nil {
		// Log but proceed with the exit — the operator asked for a restart
		// and we shouldn't refuse just because the ack didn't make it through.
		a.log.Err(err).Msg("agent.handleAgentRestartRequest - ack send failed; restarting anyway")
	}

	go func() {
		time.Sleep(500 * time.Millisecond)
		a.log.Info().Msg("agent.handleAgentRestartRequest - exiting for systemd restart")
		os.Exit(0)
	}()
}

func (a *agent) CheckScheduleGet() error {
	msg := &client.Request{
		Version:   "1",
		ID:        "1",
		Target:    "agent",
		Source:    a.AgentID,
		Tenant:    a.Subdomain,
		Subdomain: a.Subdomain,
		Method:    "agent_checks.get",
	}

	requestID, responseCh, err := a.conn.SendJSONMessage(msg)
	if err != nil {
		a.log.Err(err).Msg("agent.CheckScheduleGet - error during agent_checks.get")
		return err
	}

	select {
	case response, ok := <-responseCh:
		if !ok {
			err = errors.New("response channel closed unexpectedly")
			a.log.Err(err).Msg("agent.CheckScheduleGet - error during agent_checks.get response. bailing out.")
			return err
		}
		a.log.Debug().Msgf("agent.CheckScheduleGet - received response for Request ID: %s, Response ID: %s", requestID, response.ID)
		if response.Err.Message != "" {
			err = errors.New(response.Err.Message)
			a.log.Err(err).Msg("agent.CheckScheduleGet - agent_checks.get failure")
			return err
		}
		var agentChecks api.AgentChecks
		err := json.Unmarshal(response.Result, &agentChecks)
		if err != nil {
			a.log.Err(err).Msg("agent.CheckScheduleGet - error unmarshalling agent_checks.get response")
			return err
		}
		a.checkerManager.ConfigureChecks(agentChecks.Checks)
		a.log.Debug().Msgf("agent.CheckScheduleGet - writing agent checks to file: %s", filepath.Join(config.ConfigDir, "agent_checks.json"))
		err = config.WriteAgentChecks(agentChecks)
		if err != nil {
			a.log.Err(err).Msg("agent.CheckScheduleGet - error writing agent checks to file")
			return err
		}

	case <-time.After(time.Duration(a.timeout) * time.Second):
		err = errors.New("agent_checks.get response timeout")
		a.log.Err(err).Msgf("agent.CheckScheduleGet - response timeout for requestID:%s", requestID)
		return err
	}
	return nil
}

func (a *agent) saveCheckResultQueue() error {
	a.checkResultQueueMutex.Lock()
	defer a.checkResultQueueMutex.Unlock()

	if len(a.checkResultQueue) == 0 {
		return nil
	}

	queuePath := filepath.Join(config.ConfigDir, checkResultQueueFile)
	file, err := os.Create(queuePath)
	if err != nil {
		return fmt.Errorf("agent.saveCheckResultQueue - failed to create queue file: %w", err)
	}
	defer file.Close()

	encoder := gob.NewEncoder(file)
	if err := encoder.Encode(a.checkResultQueue); err != nil {
		return fmt.Errorf("agent.saveCheckResultQueue - failed to encode queue: %w", err)
	}

	a.log.Debug().Msgf("Saved %d check results to %s", len(a.checkResultQueue), queuePath)
	return nil
}

func (a *agent) loadCheckResultQueue() error {
	queuePath := filepath.Join(config.ConfigDir, checkResultQueueFile)

	file, err := os.Open(queuePath)
	if os.IsNotExist(err) {
		a.log.Debug().Msg("agent.loadCheckResultQueue - no saved check results queue found")
		return nil
	} else if err != nil {
		return fmt.Errorf("agent.loadCheckResultQueue - failed to open queue file: %w", err)
	}
	defer file.Close()

	a.checkResultQueueMutex.Lock()
	defer a.checkResultQueueMutex.Unlock()

	decoder := gob.NewDecoder(file)
	if err := decoder.Decode(&a.checkResultQueue); err != nil {
		return fmt.Errorf("agent.loadCheckResultQueue - failed to decode queue: %w", err)
	}

	a.log.Debug().Msgf("Loaded %d check results from %s", len(a.checkResultQueue), queuePath)

	// Clean up the file after successful load
	os.Remove(queuePath)
	return nil
}

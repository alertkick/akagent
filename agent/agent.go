package agent

import (
	"apagent/checker"
	"apagent/checks"
	"apagent/client"
	"apagent/config"
	"apagent/ebpf"
	"apagent/internal/api"
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
	conn               *client.Connection
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

	// Native eBPF agent support
	nativeAgent               *ebpf.NativeEBPFAgent
	securityEventQueue        []ebpf.SecurityEvent
	securityEventQueueMutex   sync.Mutex
	securityEventMaxQueueSize int
}

func NewAgentClient(conf *config.Config, kernalVersion string, log zerolog.Logger, version string) (*agent, error) {

	RPCConn := client.NewConnection(conf, log, version)
	ctx, cancel := context.WithCancel(context.Background())

	agent := agent{
		log:                       log,
		conn:                      RPCConn,
		AgentID:                   conf.AgentID,
		AgentName:                 conf.AgentName,
		Subdomain:                 conf.Subdomain,
		Tenant:                    conf.Subdomain,
		agentToken:                conf.AgentToken,
		version:                   version,
		heartbeatInterval:         10,
		sentHeartbeatCount:        0,
		timeout:                   10,
		ctx:                       ctx,
		cancelFunc:                cancel,
		checkResultQueue:          make([]api.CheckMetricParams, 0, 1000),
		securityEventQueue:        make([]ebpf.SecurityEvent, 0, 1000),
		checkResultMaxQueueSize:   1000,
		securityEventMaxQueueSize: 1000,
	}

	if conf.Debug {
		agent.debug = true
		agent.log.Debug().Msgf("agent.NewAgentClient - debug value: %t", agent.debug)
	} else {
		agent.debug = false
	}

	// Load any saved check results
	if err := agent.loadCheckResultQueue(); err != nil {
		agent.log.Warn().Err(err).Msg("agent.NewAgentClient - failed to load saved check results")
	}

	return &agent, nil
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

	// Initialize native eBPF agent (but DO NOT start it - wait for profile)
	a.log.Info().Msg("agent.Run - initializing native eBPF agent (disabled by default)")
	nativeAgent, err := ebpf.NewNativeAgent()
	if err != nil {
		a.log.Warn().Err(err).Msg("agent.Run - failed to create native eBPF agent")
	} else {
		a.nativeAgent = nativeAgent
		// Only start if explicitly enabled in config (rare - usually profile triggers it)
		nativeConfig := a.nativeAgent.GetNativeConfig()
		if nativeConfig.Enabled {
			if err := a.nativeAgent.Start(ctx); err != nil {
				a.log.Warn().Err(err).Msg("agent.Run - failed to start native eBPF agent")
			} else if err := a.nativeAgent.StartEventListener(ctx); err != nil {
				a.log.Warn().Err(err).Msg("agent.Run - failed to start native eBPF event listener")
			}
		} else {
			a.log.Info().Msg("agent.Run - eBPF agent initialized but not started (waiting for profile)")
		}
	}

	// Start eBPF event sender
	ebpfShutdown := make(chan struct{})
	a.wg.Add(1)
	go a.StartEBPFEventSender(ebpfShutdown, &a.wg)

	// Wait for shutdown signal
	<-shutdown
	close(ebpfShutdown)
	a.log.Debug().Msg("agent.Run - Shutdown signal received, shutting down native eBPF agent")
	if a.nativeAgent != nil {
		if err := a.nativeAgent.StopEventListener(); err != nil {
			a.log.Warn().Err(err).Msg("agent.Run - error stopping native eBPF event listener")
		}
		if err := a.nativeAgent.Stop(ctx); err != nil {
			a.log.Warn().Err(err).Msg("agent.Run - error stopping native eBPF agent")
		}
	}

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
		// Fetch stored native agent config from server (if any)
		if err := a.NativeConfigGetStored(); err != nil {
			a.log.Warn().Err(err).Msg("agent.HandleServerRequest - failed to get stored native config")
		}
	case "agent.refresh_check_profiles":
		a.log.Debug().Msg("agent.HandleServerRequest - received refresh_check_profiles request")
		a.handleRefreshCheckProfilesRequest(req)
	case "agent.refresh_checks":
		a.log.Debug().Msg("agent.HandleServerRequest - received refresh_checks request")
		a.handleRefreshChecksRequest(req)
	case "host_info_types.get":
		a.log.Debug().Msg("agent.HandleServerRequest - received host_info_types.get request")
	// Native eBPF agent handlers
	case "native_config.get":
		a.log.Debug().Msg("agent.HandleServerRequest - received native_config.get request")
		a.handleNativeConfigGetRequest(req)
	case "native_config.update":
		a.log.Debug().Msg("agent.HandleServerRequest - received native_config.update request")
		a.handleNativeConfigUpdateRequest(req)
	case "enable_native_agent":
		a.log.Debug().Msg("agent.HandleServerRequest - received enable_native_agent request")
		a.handleEnableNativeAgentRequest(req)
	case "disable_native_agent":
		a.log.Debug().Msg("agent.HandleServerRequest - received disable_native_agent request")
		a.handleDisableNativeAgentRequest(req)
	case "native_agent.status":
		a.log.Debug().Msg("agent.HandleServerRequest - received native_agent.status request")
		a.handleNativeAgentStatusRequest(req)
	case "refresh_native_config":
		a.log.Debug().Msg("agent.HandleServerRequest - received refresh_native_config request")
		a.handleRefreshNativeConfigRequest(req)
	case "agent.refresh_compliance":
		a.log.Debug().Msg("agent.HandleServerRequest - received refresh_compliance request")
		a.handleRefreshComplianceRequest(req)
	case "update_agent":
		a.log.Info().Msg("agent.HandleServerRequest - received update_agent request")
		go a.handleUpdateAgentRequest(req)
	default:
		a.log.Warn().Msgf("agent.HandleServerRequest - unknown method: %s", req.Method)
		a.handleUnknownMethod(req)
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

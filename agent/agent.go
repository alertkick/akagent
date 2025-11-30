package agent

import (
	"akagent/checker"
	"akagent/checks"
	"akagent/client"
	"akagent/config"
	"akagent/falco_manager"
	"akagent/internal/api"
	"akagent/internal/systemd"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"encoding/gob"
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

const (
	checkResultQueueFile = "check_results_queue.bin"
)

func init() {
	gob.Register(api.CheckMetricParams{})
	gob.Register(api.MetricGroup{})
	gob.Register(api.Metric{})
	// Register any other types used within CheckMetricParams if needed
}

type agent struct {
	conn               *client.Connection
	agentToken         string
	AgentID            string
	AgentName          string
	FalcoEnabled       bool
	Subdomain          string
	Tenant             string
	timeout            int
	heartbeatInterval  int // seconds
	sentHeartbeatCount int
	debug              bool
	falcoManager       *falco_manager.FalcoManager
	checkerManager     *checker.CheckerManager
	wg                 sync.WaitGroup
	log                zerolog.Logger
	shutdown           chan struct{}
	falcoShutdown      chan struct{}

	falcoEventQueue         []falco_manager.FalcoEventPayload
	falcoEventQueueMutex    sync.Mutex
	falcoEventMaxQueueSize  int
	checkResultQueue        []api.CheckMetricParams
	checkResultQueueMutex   sync.Mutex
	checkResultMaxQueueSize int
}

func NewAgentClient(conf *config.Config, kernalVersion string, log zerolog.Logger) (*agent, error) {

	RPCConn := client.NewConnection(conf, log)
	agent := agent{
		log:                     log,
		conn:                    RPCConn,
		AgentID:                 conf.AgentID,
		AgentName:               conf.AgentName,
		Subdomain:               conf.Subdomain,
		Tenant:                  conf.Subdomain,
		agentToken:              conf.AgentToken,
		FalcoEnabled:            conf.FalcoEnabled,
		heartbeatInterval:       10,
		sentHeartbeatCount:      0,
		timeout:                 10,
		falcoEventQueue:         make([]falco_manager.FalcoEventPayload, 0, 1000),
		checkResultQueue:        make([]api.CheckMetricParams, 0, 1000),
		falcoEventMaxQueueSize:  1000,
		checkResultMaxQueueSize: 1000,
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

	// Start falco manager if falco is enabled
	a.falcoManager = falco_manager.NewFalcoManager()
	if a.FalcoEnabled {
		a.StartFalcoListener()
		a.log.Info().Msg("agent.Run - falco listener started")
	} else {
		a.log.Info().Msg("agent.Run - falco listener not started because falco is not enabled")
	}

	falcoShutdown := make(chan struct{})
	a.wg.Add(1)
	go a.StartFalcoEventSender(falcoShutdown, &a.wg)

	// Wait for shutdown signal
	<-shutdown
	a.StopFalcoListener()
	close(falcoShutdown)
	a.log.Debug().Msg("agent.Run - Shutdown signal received, shutting down")
	close(requestWatcherShutdown)
	cancel()
	a.Shutdown()
	a.wg.Wait()
	return nil
}

func (a *agent) StartFalcoListener() {
	if a.falcoManager != nil && !a.falcoManager.Listening() {
		go a.falcoManager.StartListener()
		a.log.Info().Msg("agent.StartFalcoListener - falco listener started")
	}
}

func (a *agent) StopFalcoListener() {
	if a.falcoManager != nil && a.falcoManager.Listening() {
		a.falcoManager.StopListener()
		a.log.Info().Msg("agent.StopFalcoListener - falco listener shutdown")
	}
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
// we can add more cases for additional commands coming from server.
func (a *agent) HandleServerRequest(req client.Request) error {
	a.log.Info().Msgf("agent.HandleServerRequest - received request with method: %s", req.Method)
	a.log.Debug().Msgf("agent.HandleServerRequest - request: %v", req)
	// It's a request, add it to serverReqChan.
	switch req.Method {
	case "system.info":
		a.log.Debug().Msg("agent.HandleServerRequest - received system.info request")
		a.handleSystemInfoRequest(req)
		a.CheckScheduleGet()
	case "falco_files.info":
		a.log.Debug().Msg("agent.HandleServerRequest - received falco_files.info request")
		a.handleFalcoConfigRequest(req)
		if a.FalcoEnabled {
			a.log.Debug().Msg("agent.HandleServerRequest - getting falco rules from server")
			a.GetFalcoRuleFiles()
		} else {
			a.log.Warn().Msg("agent.HandleServerRequest - falco is not enabled, skipping getting falco rules")
		}
	case "enable_falco":
		a.log.Debug().Msg("agent.HandleServerRequest - received enable_falco request")
		a.handleEnableFalcoRequest(req)
	case "disable_falco":
		a.log.Debug().Msg("agent.HandleServerRequest - received disable_falco request")
		a.handleDisableFalcoRequest(req)
	case "agent.refresh_check_profiles":
		a.log.Debug().Msg("agent.HandleServerRequest - received refresh_check_profiles or refresh_checks request")
		a.handleRefreshCheckProfilesRequest(req)
	case "agent.refresh_checks":
		a.log.Debug().Msg("agent.HandleServerRequest - received refresh_checks request")
		a.handleRefreshChecksRequest(req)
	case "host_info_types.get":
		a.log.Debug().Msg("agent.HandleServerRequest - received host_info_types.get request")
		// handleMethod2(req)
	case "refresh_falco_rules":
		a.log.Debug().Msg("agent.HandleServerRequest - received refresh_falco_rules request")
		a.handleRefreshFalcoRulesRequest(req)
	default:
		// we need to send a response to the server to indicate that the request is not supported
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

func (a *agent) handleEnableFalcoRequest(req client.Request) {
	a.log.Info().Msg("agent.handleEnableFalcoRequest - START")
	a.FalcoEnabled = true
	a.log.Info().Msgf("agent.handleEnableFalcoRequest - FalcoEnabled: %t", a.FalcoEnabled)
	falcoToggleStatus := client.FalcoToggleStatus{
		Enabled: false,
	}

	// update the agent config file with the new falco enabled value
	currentConfig := config.GetConfig(a.log)
	currentConfig.FalcoEnabled = true
	config.UpdateConfigFileWithOption(currentConfig)
	a.log.Info().Msgf("agent.handleEnableFalcoRequest - config updated,FalcoEnabled: %t", a.FalcoEnabled)
	falcoConfigFilePath := "/etc/falco/falco.yaml"
	v := viper.New()
	v.SetConfigFile(falcoConfigFilePath)

	if err := v.ReadInConfig(); err != nil {
		falcoToggleStatus.Error = fmt.Sprintf("{\"error\": \"%s\"}", err.Error())
		a.log.Err(err).Msg("agent.handleEnableFalcoRequest - error reading falco config")
	}

	v.Set("json_output", true)
	v.Set("http_output.enabled", true)
	v.Set("http_output.url", "http://127.0.0.1:2801")
	v.Set("http_output.insecure", true)

	// create the rules.alertkick directory if it doesn't exist
	rulesAlertkickDir := "/etc/falco/rules.alertkick"
	if _, err := os.Stat(rulesAlertkickDir); os.IsNotExist(err) {
		os.MkdirAll(rulesAlertkickDir, 0755)
	}

	// create the rules.d directory if it doesn't exist
	rulesDirs := "/etc/falco/rules.d"
	if _, err := os.Stat(rulesDirs); os.IsNotExist(err) {
		os.MkdirAll(rulesDirs, 0755)
	}

	ruleFilesDirs := v.GetStringSlice("rules_files")
	if ruleFilesDirs == nil {
		ruleFilesDirs = []string{
			"/etc/falco/falco_rules.yaml",
			"/etc/falco/falco_rules.local.yaml",
			"/etc/falco/rules.d",
			"/etc/falco/rules.alertkick",
		}
	} else {
		// check if the rules.alertkick is missing in ruleFilesDirs, and add it.
		if !slices.Contains(ruleFilesDirs, "/etc/falco/rules.alertkick") {
			ruleFilesDirs = append(ruleFilesDirs, "/etc/falco/rules.alertkick")
		}
	}
	v.Set("rules_files", ruleFilesDirs)

	if err := v.WriteConfig(); err != nil {
		falcoToggleStatus.Error = fmt.Sprintf("{\"error\": \"%s\"}", err.Error())
		a.log.Err(err).Msg("agent.handleEnableFalcoRequest - error writing falco config")
	}
	falcoToggleStatus.Enabled = true

	returnCode := systemd.RestartService("falco-modern-bpf.service")
	if returnCode != 0 {
		falcoToggleStatus.Error = fmt.Sprintf("{\"error\": \"failed to restart Falco service, return code: %d\"}", returnCode)
		a.log.Err(fmt.Errorf("agent.handleEnableFalcoRequest - failed to restart Falco service, return code: %d", returnCode)).Msg("error during enable_falco request")
	}

	msg := client.Response{
		Version:   "1",
		ID:        req.ID,
		Target:    "falco.toggle",
		Source:    a.AgentID,
		Tenant:    a.Subdomain,
		Subdomain: a.Subdomain,
		Result:    json.RawMessage(falcoToggleStatus.String()),
		Err:       client.Error{Message: falcoToggleStatus.Error},
	}

	a.log.Info().Msgf("agent.handleEnableFalcoRequest - Sending response for enable_falco request: %v", msg)
	err := a.conn.SendJSONMessageNoResponse(msg)
	if err != nil {
		a.log.Err(err).Msg("agent.handleEnableFalcoRequest - error during `enable_falco` submit")
		// Send an empty Results message to leave the endpoint channel waiting
		emptyMsg := client.Response{
			Version:   "1",
			ID:        req.ID,
			Target:    "falco.toggle",
			Source:    a.AgentID,
			Tenant:    a.Subdomain,
			Subdomain: a.Subdomain,
			Result:    json.RawMessage("{}"),
			Err:       client.Error{Message: err.Error()},
		}
		if err := a.conn.SendJSONMessageNoResponse(emptyMsg); err != nil {
			a.log.Err(err).Msg("agent.handleEnableFalcoRequest - error sending empty response for enable_falco request")
		}
		return
	}
	a.StartFalcoListener()
	serviceStatus := a.falcoManager.FalcoServiceAgentRunning()
	a.UpdateFalcoAgentServiceStatus(serviceStatus)
	a.log.Info().Msgf("agent.handleEnableFalcoRequest - END - Sent response for enable_falco request: %v", msg)
}

func (a *agent) handleDisableFalcoRequest(req client.Request) {
	a.log.Info().Msg("agent.handleDisableFalcoRequest - START")
	a.FalcoEnabled = false

	// update the agent config file with the new falco enabled value
	currentConfig := config.GetConfig(a.log)
	currentConfig.FalcoEnabled = false
	config.UpdateConfigFileWithOption(currentConfig)
	a.log.Info().Msgf("agent.handleDisableFalcoRequest - config updated,FalcoEnabled: %t", a.FalcoEnabled)

	falcoToggleStatus := client.FalcoToggleStatus{
		Enabled: false,
	}

	a.log.Info().Msg("agent.handleDisableFalcoRequest - stopping Falco service")
	returnCode := systemd.StopService("falco-modern-bpf.service")
	if returnCode != 0 {
		falcoToggleStatus.Error = fmt.Sprintf("{\"error\": \"failed to stop Falco service, return code: %d\"}", returnCode)
		a.log.Err(fmt.Errorf("agent.handleDisableFalcoRequest - failed to stop Falco service, return code: %d", returnCode)).Msg("error during disable_falco request")
	}

	msg := client.Response{
		Version:   "1",
		ID:        req.ID,
		Target:    "falco.toggle",
		Source:    a.AgentID,
		Tenant:    a.Subdomain,
		Subdomain: a.Subdomain,
		Result:    json.RawMessage(falcoToggleStatus.String()),
	}

	err := a.conn.SendJSONMessageNoResponse(msg)
	if err != nil {
		a.log.Err(err).Msg("agent.handleDisableFalcoRequest - error during `disable_falco` submit")
		return
	}
	a.StopFalcoListener()

	serviceStatus := a.falcoManager.FalcoServiceAgentRunning()
	a.UpdateFalcoAgentServiceStatus(serviceStatus)
	a.log.Info().Msg("agent.handleDisableFalcoRequest - END")
}

func (a *agent) handleRefreshFalcoRulesRequest(req client.Request) {
	a.log.Info().Msg("agent.handleRefreshFalcoRulesRequest - START")
	response := client.GeneralCommandResponse{
		Message: "Falco rules refreshed",
		Status:  "success",
		Error:   "",
	}

	msg := client.Response{
		Version:   "1",
		ID:        req.ID,
		Target:    "falco.refresh_rules",
		Source:    a.AgentID,
		Tenant:    a.Subdomain,
		Subdomain: a.Subdomain,
		Result:    json.RawMessage(response.String()),
	}

	err := a.conn.SendJSONMessageNoResponse(msg)
	if err != nil {
		a.log.Err(err).Msg("agent.handleRefreshFalcoRulesRequest - error during `refresh_falco_rules` submit")
		return
	}

	a.GetFalcoRuleFiles()
	a.log.Info().Msg("agent.handleRefreshFalcoRulesRequest - END")
}

func (a *agent) UpdateFalcoAgentServiceStatus(status string) {
	params := api.CheckMetricParams{
		CheckID: "falco.service_status",
		State:   status,
	}

	msg := client.CheckResultsPost{
		Version:   "1",
		ID:        "1",
		Target:    "agent",
		Source:    a.AgentID,
		Tenant:    a.Subdomain,
		Subdomain: a.Subdomain,
		Method:    "falco.service_status.post",
		Params:    params,
	}

	err := a.conn.CheckResultsPost(msg)
	if err != nil {
		a.log.Err(err).Msg("agent.UpdateFalcoAgentServiceStatus - error during falco.service_status_post submit")
	}
}

func (a *agent) handleSystemInfoRequest(req client.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	a.log.Debug().Msg("agent.handleSystemInfoRequest - collecting systemInfo")
	systemInfo := checks.CollectSystemInfo(ctx)

	// a.log.Debug().Msgf("systemInfo: %s", systemInfo.String())

	msg := client.Response{
		Version:   "1",
		ID:        req.ID,
		Target:    "agent",
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

func (a *agent) handleFalcoConfigRequest(req client.Request) {
	var data []byte
	var err error

	if a.FalcoEnabled && a.falcoManager != nil {
		data, err = a.falcoManager.RuleFilesDataJson()
		if err != nil {
			a.log.Err(err).Msg("agent.handleFalcoConfigRequest - error marshalling Falco rule files data")
			return
		}
	}

	msg := client.Response{
		Version:   "1",
		ID:        req.ID,
		Target:    "agent",
		Source:    a.AgentID,
		Tenant:    a.Subdomain,
		Subdomain: a.Subdomain,
		Result:    json.RawMessage(data),
	}

	err = a.conn.SendJSONMessageNoResponse(msg)
	if err != nil {
		a.log.Err(err).Msg("agent.handleFalcoConfigRequest - error during falco_config.get submit")
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
	// log.Println("CheckScheduleGet")

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
	// Wait for the response from the server with the specified timeout
	select {
	case response, ok := <-responseCh:
		if !ok {
			err = errors.New("response channel closed unexpectedly")
			a.log.Err(err).Msg("agent.CheckScheduleGet - error during agent_checks.get response. bailing out.")
			return err
		}
		a.log.Debug().Msgf("agent.CheckScheduleGet - received response for Request ID: %s, Response ID: %s", requestID, response.ID)
		// a.log.Debug().Msgf("agent.CheckScheduleGet - response: %v", response)
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

func (a *agent) GetFalcoRuleFiles() error {

	msg := &client.Request{
		Version:   "1",
		ID:        "1",
		Target:    "agent",
		Source:    a.AgentID,
		Tenant:    a.Subdomain,
		Subdomain: a.Subdomain,
		Method:    "falco_files.get",
	}

	requestID, responseCh, err := a.conn.SendJSONMessage(msg)
	if err != nil {
		a.log.Err(err).Msg("agent.GetFalcoRuleFiles - error during falco_files.get")
		return err
	}
	// Wait for the response from the server with the specified timeout
	select {
	case response, ok := <-responseCh:
		if !ok {
			err = errors.New("response channel closed unexpectedly")
			a.log.Err(err).Msg("agent.GetFalcoRuleFiles - error during falco_files.get response. bailing out.")
			return err
		}
		a.log.Debug().Msgf("agent.GetFalcoRuleFiles - received falco_files.get response for rqid: %s, resp id: %s", requestID, response.ID)
		if response.Err.Message != "" {
			err = errors.New(response.Err.Message)
			a.log.Err(err).Msg("agent.GetFalcoRuleFiles - falco_files.get failure")
			return err
		}
		var falcoFilesGetResult falco_manager.FalcoFilesGetResult
		err := json.Unmarshal(response.Result, &falcoFilesGetResult)
		if err != nil {
			a.log.Err(err).Msg("agent.GetFalcoRuleFiles - error unmarshalling falco_files.get response")
			return err
		}

		a.falcoManager.UpdateRuleFiles(falcoFilesGetResult.FalcoFiles)
		serviceStatus := a.falcoManager.FalcoServiceAgentRunning()
		a.UpdateFalcoAgentServiceStatus(serviceStatus)

	case <-time.After(time.Duration(a.timeout) * time.Second):
		err = errors.New("falco_files.get response timeout")
		a.log.Err(err).Msgf("agent.GetFalcoRuleFiles - response timeout for requestID:%s", requestID)
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

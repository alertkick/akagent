package agent

import (
	"encoding/json"
	"errors"
	"time"

	"apagent/client"
	"apagent/ebpf"
	"apagent/ebpf/agents/native"
)

// GetNativeAgentConfig requests the native agent config from apweb
func (a *agent) GetNativeAgentConfig() error {
	if a.ebpfManager == nil {
		return errors.New("ebpf manager not initialized")
	}

	// Check if native agent is available
	nativeAgent, exists := a.ebpfManager.GetAgent(ebpf.AgentTypeNative)
	if !exists {
		a.log.Debug().Msg("agent.GetNativeAgentConfig - native agent not available")
		return nil
	}

	if !nativeAgent.IsInstalled() {
		a.log.Debug().Msg("agent.GetNativeAgentConfig - native agent not installed")
		return nil
	}

	msg := &client.Request{
		Version:   "1",
		ID:        "1",
		Target:    "agent",
		Source:    a.AgentID,
		Tenant:    a.Subdomain,
		Subdomain: a.Subdomain,
		Method:    "native_config.get",
	}

	requestID, responseCh, err := a.conn.SendJSONMessage(msg)
	if err != nil {
		a.log.Err(err).Msg("agent.GetNativeAgentConfig - error during native_config.get")
		return err
	}

	// Wait for the response from the server with the specified timeout
	select {
	case response, ok := <-responseCh:
		if !ok {
			err = errors.New("response channel closed unexpectedly")
			a.log.Err(err).Msg("agent.GetNativeAgentConfig - response channel closed")
			return err
		}
		a.log.Debug().Msgf("agent.GetNativeAgentConfig - received response for rqid: %s", requestID)

		if response.Err.Message != "" {
			// If apweb doesn't have config yet, that's okay - use defaults
			if response.Err.Code == 404 {
				a.log.Debug().Msg("agent.GetNativeAgentConfig - no config on server, using defaults")
				return nil
			}
			err = errors.New(response.Err.Message)
			a.log.Err(err).Msg("agent.GetNativeAgentConfig - server error")
			return err
		}

		var configResponse client.NativeAgentConfigResponse
		if err := json.Unmarshal(response.Result, &configResponse); err != nil {
			a.log.Err(err).Msg("agent.GetNativeAgentConfig - error unmarshalling response")
			return err
		}

		if configResponse.Status != "success" {
			a.log.Warn().Str("status", configResponse.Status).Msg("agent.GetNativeAgentConfig - non-success status")
			return nil
		}

		// Apply the config to the native agent
		if err := a.applyNativeAgentConfig(configResponse.Config); err != nil {
			a.log.Err(err).Msg("agent.GetNativeAgentConfig - error applying config")
			return err
		}

		a.log.Info().Msg("agent.GetNativeAgentConfig - successfully applied config from apweb")

	case <-time.After(time.Duration(a.timeout) * time.Second):
		err = errors.New("native_config.get response timeout")
		a.log.Err(err).Msgf("agent.GetNativeAgentConfig - timeout for requestID:%s", requestID)
		return err
	}

	return nil
}

// applyNativeAgentConfig applies the config received from apweb to the native agent
func (a *agent) applyNativeAgentConfig(webConfig client.NativeAgentConfig) error {
	nativeAgent, exists := a.ebpfManager.GetAgent(ebpf.AgentTypeNative)
	if !exists {
		return errors.New("native agent not found")
	}

	// Type assert to access native-specific methods
	na, ok := nativeAgent.(*native.NativeEBPFAgent)
	if !ok {
		return errors.New("failed to cast to NativeEBPFAgent")
	}

	// Convert web config to native config
	nativeConfig := convertWebConfigToNative(webConfig)

	// Update the native agent config
	if err := na.UpdateNativeConfig(nativeConfig); err != nil {
		return err
	}

	return nil
}

// convertWebConfigToNative converts the web API config format to native agent config
func convertWebConfigToNative(webConfig client.NativeAgentConfig) native.Config {
	config := native.DefaultConfig()

	// Apply settings from web config
	config.Enabled = webConfig.Enabled

	// UID filtering
	config.FilterUIDs = webConfig.FilterUIDs
	config.ExcludeUIDs = webConfig.ExcludeUIDs

	// Process name filtering
	config.FilterComms = webConfig.FilterComms
	config.ExcludeComms = webConfig.ExcludeComms

	// Path filtering
	if len(webConfig.ExcludePaths) > 0 {
		config.ExcludePaths = webConfig.ExcludePaths
	}

	// Category filtering
	config.EnableProcess = webConfig.EnableProcess
	config.EnableFile = webConfig.EnableFile
	config.EnableNetwork = webConfig.EnableNetwork

	// Compliance categories
	config.EnablePrivilege = webConfig.EnablePrivilege
	config.EnableFilesystem = webConfig.EnableFilesystem
	config.EnableKernel = webConfig.EnableKernel
	config.EnableMemory = webConfig.EnableMemory

	// Enrichment
	config.EnableEnrichment = webConfig.EnableEnrichment
	if webConfig.EnrichmentCacheTTLSeconds > 0 {
		config.EnrichmentCacheTTLSeconds = webConfig.EnrichmentCacheTTLSeconds
	}

	// Alerting
	config.EnableAlerts = webConfig.EnableAlerts
	if len(webConfig.AlertRules) > 0 {
		config.AlertRules = convertWebAlertRules(webConfig.AlertRules)
	}

	return config
}

// convertWebAlertRules converts web API alert rules to native alert rules
func convertWebAlertRules(webRules []client.NativeAgentAlertRule) []native.AlertRule {
	rules := make([]native.AlertRule, len(webRules))
	for i, wr := range webRules {
		rules[i] = native.AlertRule{
			Name:        wr.Name,
			Description: wr.Description,
			Enabled:     wr.Enabled,
			Conditions: native.RuleConditions{
				Category:         wr.Conditions.Category,
				EventTypes:       wr.Conditions.EventTypes,
				ProcessNames:     wr.Conditions.ProcessNames,
				ProcessNamesRegex: wr.Conditions.ProcessNamesRegex,
				UIDs:             wr.Conditions.UIDs,
				RootOnly:         wr.Conditions.RootOnly,
				PathPatterns:     wr.Conditions.PathPatterns,
				ContainerOnly:    wr.Conditions.ContainerOnly,
				PrivilegeEscalationToRoot: wr.Conditions.PrivilegeEscalationToRoot,
			},
			Priority: convertPriority(wr.Priority),
			Tags:     wr.Tags,
			Action:   convertAction(wr.Action),
		}
	}
	return rules
}

// convertPriority converts string priority to ebpf.PriorityLevel
func convertPriority(p string) ebpf.PriorityLevel {
	switch p {
	case "critical":
		return ebpf.PriorityCritical
	case "error":
		return ebpf.PriorityError
	case "warning":
		return ebpf.PriorityWarning
	case "notice":
		return ebpf.PriorityNotice
	case "informational", "info":
		return ebpf.PriorityInformational
	case "debug":
		return ebpf.PriorityDebug
	default:
		return ebpf.PriorityInformational
	}
}

// convertAction converts string action to native.AlertAction
func convertAction(a string) native.AlertAction {
	switch a {
	case "drop":
		return native.AlertActionDrop
	case "elevate":
		return native.AlertActionElevate
	case "tag":
		return native.AlertActionTag
	default:
		return native.AlertActionTag
	}
}

// handleNativeConfigGetRequest handles the native_config.get request from apweb
func (a *agent) handleNativeConfigGetRequest(req client.Request) {
	a.log.Debug().Msg("agent.handleNativeConfigGetRequest - processing request")

	response := client.NativeAgentConfigResponse{
		Status: "success",
	}

	// Get native agent
	if a.ebpfManager == nil {
		response.Status = "failed"
		response.Error = "ebpf manager not initialized"
		a.sendNativeConfigResponse(req, response)
		return
	}

	nativeAgent, exists := a.ebpfManager.GetAgent(ebpf.AgentTypeNative)
	if !exists {
		response.Status = "failed"
		response.Error = "native agent not found"
		a.sendNativeConfigResponse(req, response)
		return
	}

	na, ok := nativeAgent.(*native.NativeEBPFAgent)
	if !ok {
		response.Status = "failed"
		response.Error = "failed to cast to NativeEBPFAgent"
		a.sendNativeConfigResponse(req, response)
		return
	}

	// Get current config
	config := na.GetNativeConfig()
	response.Config = convertNativeConfigToWeb(config)

	a.sendNativeConfigResponse(req, response)
}

// convertNativeConfigToWeb converts native config to web API format
func convertNativeConfigToWeb(config native.Config) client.NativeAgentConfig {
	webConfig := client.NativeAgentConfig{
		Enabled:                   config.Enabled,
		FilterUIDs:                config.FilterUIDs,
		ExcludeUIDs:               config.ExcludeUIDs,
		FilterComms:               config.FilterComms,
		ExcludeComms:              config.ExcludeComms,
		ExcludePaths:              config.ExcludePaths,
		EnableProcess:             config.EnableProcess,
		EnableFile:                config.EnableFile,
		EnableNetwork:             config.EnableNetwork,
		EnablePrivilege:           config.EnablePrivilege,
		EnableFilesystem:          config.EnableFilesystem,
		EnableKernel:              config.EnableKernel,
		EnableMemory:              config.EnableMemory,
		EnableEnrichment:          config.EnableEnrichment,
		EnrichmentCacheTTLSeconds: config.EnrichmentCacheTTLSeconds,
		EnableAlerts:              config.EnableAlerts,
	}

	if len(config.AlertRules) > 0 {
		webConfig.AlertRules = convertNativeAlertRulesToWeb(config.AlertRules)
	}

	return webConfig
}

// convertNativeAlertRulesToWeb converts native alert rules to web API format
func convertNativeAlertRulesToWeb(rules []native.AlertRule) []client.NativeAgentAlertRule {
	webRules := make([]client.NativeAgentAlertRule, len(rules))
	for i, r := range rules {
		webRules[i] = client.NativeAgentAlertRule{
			Name:        r.Name,
			Description: r.Description,
			Enabled:     r.Enabled,
			Conditions: client.NativeAgentRuleCondition{
				Category:                  r.Conditions.Category,
				EventTypes:                r.Conditions.EventTypes,
				ProcessNames:              r.Conditions.ProcessNames,
				ProcessNamesRegex:         r.Conditions.ProcessNamesRegex,
				UIDs:                      r.Conditions.UIDs,
				RootOnly:                  r.Conditions.RootOnly,
				PathPatterns:              r.Conditions.PathPatterns,
				ContainerOnly:             r.Conditions.ContainerOnly,
				PrivilegeEscalationToRoot: r.Conditions.PrivilegeEscalationToRoot,
			},
			Priority: priorityToString(r.Priority),
			Tags:     r.Tags,
			Action:   string(r.Action),
		}
	}
	return webRules
}

// priorityToString converts ebpf.PriorityLevel to string
func priorityToString(p ebpf.PriorityLevel) string {
	switch p {
	case ebpf.PriorityCritical:
		return "critical"
	case ebpf.PriorityError:
		return "error"
	case ebpf.PriorityWarning:
		return "warning"
	case ebpf.PriorityNotice:
		return "notice"
	case ebpf.PriorityInformational:
		return "informational"
	case ebpf.PriorityDebug:
		return "debug"
	default:
		return "informational"
	}
}

func (a *agent) sendNativeConfigResponse(req client.Request, response client.NativeAgentConfigResponse) {
	result, err := json.Marshal(response)
	if err != nil {
		a.log.Err(err).Msg("agent.sendNativeConfigResponse - error marshalling response")
		return
	}

	resp := client.Response{
		ID:            req.ID,
		Version:       "1",
		Target:        req.Source,
		Source:        a.AgentID,
		Tenant:        a.Subdomain,
		Subdomain:     a.Subdomain,
		Result:        result,
		CorrelationID: req.CorrelationID,
	}

	if err := a.conn.SendJSONMessageNoResponse(resp); err != nil {
		a.log.Err(err).Msg("agent.sendNativeConfigResponse - error sending response")
	}
}

// handleNativeConfigUpdateRequest handles the native_config.update request from apweb
func (a *agent) handleNativeConfigUpdateRequest(req client.Request) {
	a.log.Debug().Msg("agent.handleNativeConfigUpdateRequest - processing request")

	response := client.NativeAgentConfigResponse{
		Status: "success",
	}

	// Parse the config from request params
	var webConfig client.NativeAgentConfig
	if err := json.Unmarshal(req.Params, &webConfig); err != nil {
		response.Status = "failed"
		response.Error = "failed to parse config: " + err.Error()
		a.sendNativeConfigResponse(req, response)
		return
	}

	// Apply the config
	if err := a.applyNativeAgentConfig(webConfig); err != nil {
		response.Status = "failed"
		response.Error = err.Error()
		a.sendNativeConfigResponse(req, response)
		return
	}

	response.Message = "config updated successfully"
	response.Config = webConfig
	a.sendNativeConfigResponse(req, response)
}

// handleEnableNativeAgentRequest handles the enable_native_agent request
func (a *agent) handleEnableNativeAgentRequest(req client.Request) {
	a.log.Info().Msg("agent.handleEnableNativeAgentRequest - enabling native agent")

	response := client.EBPFAgentResponse{
		Action:    "enable",
		AgentType: "native",
		Status:    "success",
	}

	if err := a.EnableEBPFAgent("native"); err != nil {
		response.Status = "failed"
		response.Error = err.Error()
	} else {
		response.ServiceStatus = "running"
		response.Message = "native agent enabled successfully"
	}

	a.sendEBPFAgentResponse(req, response)
}

// handleDisableNativeAgentRequest handles the disable_native_agent request
func (a *agent) handleDisableNativeAgentRequest(req client.Request) {
	a.log.Info().Msg("agent.handleDisableNativeAgentRequest - disabling native agent")

	response := client.EBPFAgentResponse{
		Action:    "disable",
		AgentType: "native",
		Status:    "success",
	}

	if err := a.DisableEBPFAgent("native"); err != nil {
		response.Status = "failed"
		response.Error = err.Error()
	} else {
		response.ServiceStatus = "stopped"
		response.Message = "native agent disabled successfully"
	}

	a.sendEBPFAgentResponse(req, response)
}

// handleNativeAgentStatusRequest handles the native_agent.status request
func (a *agent) handleNativeAgentStatusRequest(req client.Request) {
	a.log.Debug().Msg("agent.handleNativeAgentStatusRequest - processing request")

	status := a.getNativeAgentStatus()

	result, err := json.Marshal(status)
	if err != nil {
		a.log.Err(err).Msg("agent.handleNativeAgentStatusRequest - error marshalling status")
		return
	}

	resp := client.Response{
		ID:            req.ID,
		Version:       "1",
		Target:        req.Source,
		Source:        a.AgentID,
		Tenant:        a.Subdomain,
		Subdomain:     a.Subdomain,
		Result:        result,
		CorrelationID: req.CorrelationID,
	}

	if err := a.conn.SendJSONMessageNoResponse(resp); err != nil {
		a.log.Err(err).Msg("agent.handleNativeAgentStatusRequest - error sending response")
	}
}

// getNativeAgentStatus gets the current status of the native agent
func (a *agent) getNativeAgentStatus() client.NativeAgentStatus {
	status := client.NativeAgentStatus{
		Enabled:    false,
		Running:    false,
		Listening:  false,
		Version:    "",
		ConfigPath: native.DefaultConfigPath,
	}

	if a.ebpfManager == nil {
		return status
	}

	nativeAgent, exists := a.ebpfManager.GetAgent(ebpf.AgentTypeNative)
	if !exists {
		return status
	}

	na, ok := nativeAgent.(*native.NativeEBPFAgent)
	if !ok {
		return status
	}

	status.Enabled = a.ebpfManager.IsEnabled(ebpf.AgentTypeNative)
	status.Running = na.IsRunning()
	status.Listening = na.IsListening()

	version, _ := na.Version()
	status.Version = version
	status.ConfigPath = na.GetConfigPath()

	// Get filter stats
	total, filtered := na.GetFilterStats()
	status.FilterStats = client.FilterStats{
		TotalProcessed: total,
		FilteredOut:    filtered,
	}
	if total > 0 {
		status.FilterStats.FilterRate = float64(filtered) / float64(total) * 100
	}

	// Get alert stats
	evaluated, matched := na.GetAlertStats()
	status.AlertStats = client.AlertStats{
		RulesEvaluated: evaluated,
		RulesMatched:   matched,
	}

	// Get category status from config
	config := na.GetNativeConfig()
	status.Categories = client.CategoryStats{
		Process:    config.EnableProcess,
		File:       config.EnableFile,
		Network:    config.EnableNetwork,
		Privilege:  config.EnablePrivilege,
		Filesystem: config.EnableFilesystem,
		Kernel:     config.EnableKernel,
		Memory:     config.EnableMemory,
	}

	return status
}

// sendEBPFAgentResponse sends an eBPF agent operation response
func (a *agent) sendEBPFAgentResponse(req client.Request, response client.EBPFAgentResponse) {
	result, err := json.Marshal(response)
	if err != nil {
		a.log.Err(err).Msg("agent.sendEBPFAgentResponse - error marshalling response")
		return
	}

	resp := client.Response{
		ID:            req.ID,
		Version:       "1",
		Target:        req.Source,
		Source:        a.AgentID,
		Tenant:        a.Subdomain,
		Subdomain:     a.Subdomain,
		Result:        result,
		CorrelationID: req.CorrelationID,
	}

	if err := a.conn.SendJSONMessageNoResponse(resp); err != nil {
		a.log.Err(err).Msg("agent.sendEBPFAgentResponse - error sending response")
	}
}

// handleRefreshNativeConfigRequest handles the refresh_native_config request
func (a *agent) handleRefreshNativeConfigRequest(req client.Request) {
	a.log.Info().Msg("agent.handleRefreshNativeConfigRequest - refreshing native agent config")

	response := client.GeneralCommandResponse{
		Status: "success",
	}

	if err := a.GetNativeAgentConfig(); err != nil {
		response.Status = "failed"
		response.Error = err.Error()
	} else {
		response.Message = "native agent config refreshed successfully"
	}

	result, _ := json.Marshal(response)
	resp := client.Response{
		ID:            req.ID,
		Version:       "1",
		Target:        req.Source,
		Source:        a.AgentID,
		Tenant:        a.Subdomain,
		Subdomain:     a.Subdomain,
		Result:        result,
		CorrelationID: req.CorrelationID,
	}

	if err := a.conn.SendJSONMessageNoResponse(resp); err != nil {
		a.log.Err(err).Msg("agent.handleRefreshNativeConfigRequest - error sending response")
	}
}

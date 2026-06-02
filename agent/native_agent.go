//go:build linux

package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"akagent/client"
	"akagent/ebpf"
)

// NativeConfigGetStored fetches the stored native agent config from the API on startup
// This allows the agent to restore its configuration without relying on local files
func (a *agent) NativeConfigGetStored() error {
	if a.platformData.nativeAgent == nil {
		a.log.Debug().Msg("agent.NativeConfigGetStored - native agent not initialized, skipping")
		return nil
	}

	a.log.Info().Msg("agent.NativeConfigGetStored - fetching stored native config from server")

	msg := &client.Request{
		Version:   "1",
		ID:        "1",
		Target:    "agent",
		Source:    a.AgentID,
		Tenant:    a.Subdomain,
		Subdomain: a.Subdomain,
		Method:    "native_config.get_stored",
	}

	requestID, responseCh, err := a.conn.SendJSONMessage(msg)
	if err != nil {
		a.log.Err(err).Msg("agent.NativeConfigGetStored - error sending request")
		return err
	}

	select {
	case response, ok := <-responseCh:
		if !ok {
			err = errors.New("response channel closed unexpectedly")
			a.log.Err(err).Msg("agent.NativeConfigGetStored - response channel closed")
			return err
		}
		a.log.Debug().Msgf("agent.NativeConfigGetStored - received response for rqid: %s", requestID)

		if response.Err.Message != "" {
			a.log.Warn().Str("error", response.Err.Message).Msg("agent.NativeConfigGetStored - server returned error, using defaults")
			return nil
		}

		var configResult client.NativeConfigGetStoredResult
		if err := json.Unmarshal(response.Result, &configResult); err != nil {
			a.log.Err(err).Msg("agent.NativeConfigGetStored - error unmarshalling response")
			return err
		}

		if !configResult.Found {
			a.log.Info().Msg("agent.NativeConfigGetStored - no stored config found, using defaults")
			return nil
		}

		// Apply the stored config
		if configResult.Config != nil {
			a.log.Info().Msg("agent.NativeConfigGetStored - applying stored config from server")
			if err := a.applyNativeAgentConfig(*configResult.Config); err != nil {
				a.log.Err(err).Msg("agent.NativeConfigGetStored - error applying config")
				return err
			}
			a.log.Info().Msg("agent.NativeConfigGetStored - successfully applied stored config")
		}

	case <-time.After(time.Duration(a.timeout) * time.Second):
		err = errors.New("native_config.get_stored response timeout")
		a.log.Err(err).Msgf("agent.NativeConfigGetStored - timeout for requestID:%s", requestID)
		return err
	}

	return nil
}

// GetNativeAgentConfig requests the native agent config from alertkick-ui
func (a *agent) GetNativeAgentConfig() error {
	if a.platformData.nativeAgent == nil {
		return errors.New("native agent not initialized")
	}

	if !a.platformData.nativeAgent.IsInstalled() {
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
			// If alertkick-ui doesn't have config yet, that's okay - use defaults
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

		a.log.Info().Msg("agent.GetNativeAgentConfig - successfully applied config from alertkick-ui")

	case <-time.After(time.Duration(a.timeout) * time.Second):
		err = errors.New("native_config.get response timeout")
		a.log.Err(err).Msgf("agent.GetNativeAgentConfig - timeout for requestID:%s", requestID)
		return err
	}

	return nil
}

// applyNativeAgentConfig applies the config received from alertkick-ui to the native agent
func (a *agent) applyNativeAgentConfig(webConfig client.NativeAgentConfig) error {
	if a.platformData.nativeAgent == nil {
		return errors.New("native agent not initialized")
	}

	// Convert web config to native config
	nativeConfig := convertWebConfigToNative(webConfig)

	// Update the native agent config
	if err := a.platformData.nativeAgent.UpdateNativeConfig(nativeConfig); err != nil {
		return err
	}

	return nil
}

// convertWebConfigToNative converts the web API config format to native agent config
func convertWebConfigToNative(webConfig client.NativeAgentConfig) ebpf.NativeConfig {
	config := ebpf.DefaultNativeConfig()

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

	// Derived categories - these must follow policy probes, not stay at defaults
	config.EnableCaps = webConfig.EnableCaps
	config.EnableNamespace = webConfig.EnableNamespace

	// Enrichment
	config.EnableEnrichment = webConfig.EnableEnrichment
	if webConfig.EnrichmentCacheTTLSeconds > 0 {
		config.EnrichmentCacheTTLSeconds = webConfig.EnrichmentCacheTTLSeconds
	}

	// Event channel buffer (per-host, takes effect on restart). Keep the
	// default when unset; Validate() floors it.
	if webConfig.EventChannelSize > 0 {
		config.EventChannelSize = webConfig.EventChannelSize
	}

	// Event scoping watch-sets. Override the agent defaults only when the
	// endpoint pushes its own non-empty lists.
	if fm := webConfig.FileMonitor; fm != nil && (len(fm.WriteDirs) > 0 || len(fm.ReadFiles) > 0) {
		config.FileMonitor = ebpf.FileMonitorConfig{
			WriteDirs: fm.WriteDirs,
			ReadFiles: fm.ReadFiles,
		}
	}
	if sm := webConfig.SignalMonitor; sm != nil && len(sm.EmitSignals) > 0 {
		config.SignalMonitor = ebpf.SignalMonitorConfig{EmitSignals: sm.EmitSignals}
	}

	return config
}

// handleNativeConfigGetRequest handles the native_config.get request from alertkick-ui
func (a *agent) handleNativeConfigGetRequest(req client.Request) {
	a.log.Debug().Msg("agent.handleNativeConfigGetRequest - processing request")

	response := client.NativeAgentConfigResponse{
		Status: "success",
	}

	// Get native agent
	if a.platformData.nativeAgent == nil {
		response.Status = "failed"
		response.Error = "native agent not initialized"
		a.sendNativeConfigResponse(req, response)
		return
	}

	// Get current config
	config := a.platformData.nativeAgent.GetNativeConfig()
	response.Config = convertNativeConfigToWeb(config)

	a.sendNativeConfigResponse(req, response)
}

// convertNativeConfigToWeb converts native config to web API format
func convertNativeConfigToWeb(config ebpf.NativeConfig) client.NativeAgentConfig {
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
		EnableCaps:                config.EnableCaps,
		EnableNamespace:           config.EnableNamespace,
		EnableEnrichment:          config.EnableEnrichment,
		EnrichmentCacheTTLSeconds: config.EnrichmentCacheTTLSeconds,
		EventChannelSize:          config.EventChannelSize,
		FileMonitor: &client.NativeFileMonitorConfig{
			WriteDirs: config.FileMonitor.WriteDirs,
			ReadFiles: config.FileMonitor.ReadFiles,
		},
		SignalMonitor: &client.NativeSignalMonitorConfig{
			EmitSignals: config.SignalMonitor.EmitSignals,
		},
	}

	return webConfig
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

// handleNativeConfigUpdateRequest handles the native_config.update request from alertkick-ui
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

	// Check current running state before applying config
	wasRunning := a.platformData.nativeAgent != nil && a.platformData.nativeAgent.IsRunning()

	// Apply the config
	if err := a.applyNativeAgentConfig(webConfig); err != nil {
		response.Status = "failed"
		response.Error = err.Error()
		a.sendNativeConfigResponse(req, response)
		return
	}

	// Handle eBPF lifecycle based on enabled flag
	if !webConfig.Enabled && wasRunning {
		// Security monitoring disabled - unload all eBPF programs
		a.log.Info().Msg("agent.handleNativeConfigUpdateRequest - enabled=false, stopping eBPF agent and unloading programs")
		if err := a.DisableNativeAgent(); err != nil {
			a.log.Error().Err(err).Msg("agent.handleNativeConfigUpdateRequest - failed to disable eBPF agent")
			response.Status = "failed"
			response.Error = "config saved but failed to stop eBPF: " + err.Error()
			a.sendNativeConfigResponse(req, response)
			return
		}
		response.Message = "config updated, eBPF agent stopped and programs unloaded"
	} else if webConfig.Enabled && !wasRunning {
		// Security monitoring enabled - load and start eBPF programs
		a.log.Info().Msg("agent.handleNativeConfigUpdateRequest - enabled=true, starting eBPF agent and loading programs")
		if err := a.EnableNativeAgent(); err != nil {
			a.log.Error().Err(err).Msg("agent.handleNativeConfigUpdateRequest - failed to enable eBPF agent")
			response.Status = "failed"
			response.Error = "config saved but failed to start eBPF: " + err.Error()
			a.sendNativeConfigResponse(req, response)
			return
		}
		response.Message = "config updated, eBPF agent started"
	} else {
		response.Message = "config updated successfully"
	}

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

	if err := a.EnableNativeAgent(); err != nil {
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

	if err := a.DisableNativeAgent(); err != nil {
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
		ConfigPath: ebpf.DefaultConfigPath,
	}

	if a.platformData.nativeAgent == nil {
		return status
	}

	status.Enabled = a.platformData.nativeAgent.IsRunning()
	status.Running = a.platformData.nativeAgent.IsRunning()
	status.Listening = a.platformData.nativeAgent.IsListening()

	version, _ := a.platformData.nativeAgent.Version()
	status.Version = version
	status.ConfigPath = a.platformData.nativeAgent.GetConfigPath()

	// Get filter stats
	total, filtered := a.platformData.nativeAgent.GetFilterStats()
	status.FilterStats = client.FilterStats{
		TotalProcessed: total,
		FilteredOut:    filtered,
	}
	if total > 0 {
		status.FilterStats.FilterRate = float64(filtered) / float64(total) * 100
	}

	// Alert stats are now handled by apapi, not the agent
	// Leave AlertStats as zero values

	// Get rate limiter stats
	rlStats := a.platformData.nativeAgent.GetRateLimiterStats()
	status.RateLimiterStats = client.RateLimiterStats{
		Enabled:      rlStats.Enabled,
		TotalAllowed: rlStats.TotalAllowed,
		TotalDropped: rlStats.TotalDropped,
	}

	// Get category status from config
	config := a.platformData.nativeAgent.GetNativeConfig()
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

// handleRefreshComplianceRequest handles the agent.refresh_compliance command
// This command is sent when a compliance profile is assigned/updated for this host
func (a *agent) handleRefreshComplianceRequest(req client.Request) {
	a.log.Info().Msg("agent.handleRefreshComplianceRequest - received refresh_compliance command")

	response := client.GeneralCommandResponse{
		Status: "success",
	}

	// Parse the resolved compliance config from API
	var resolvedConfig struct {
		Metadata struct {
			Profiles []string `json:"profiles"`
		} `json:"metadata"`
		Lists  map[string][]string `json:"lists"`
		Macros map[string]string   `json:"macros"`
		Rules  []struct {
			Name      string `json:"name"`
			Condition string `json:"condition"`
			Priority  string `json:"priority"`
			Enabled   bool   `json:"enabled"`
		} `json:"rules"`
	}

	if err := json.Unmarshal(req.Params, &resolvedConfig); err != nil {
		a.log.Error().Err(err).Msg("agent.handleRefreshComplianceRequest - failed to parse compliance config")
		response.Status = "failed"
		response.Error = "failed to parse compliance config: " + err.Error()
		a.sendRefreshComplianceResponse(req, response)
		return
	}

	// Determine if eBPF should be enabled (profiles assigned = enabled)
	shouldEnable := len(resolvedConfig.Metadata.Profiles) > 0

	if shouldEnable {
		a.log.Info().Strs("profiles", resolvedConfig.Metadata.Profiles).Msg("agent.handleRefreshComplianceRequest - profiles assigned, enabling eBPF")

		// Update rule engine with new config
		if a.platformData.nativeAgent != nil {
			if err := a.platformData.nativeAgent.UpdateComplianceConfig(req.Params); err != nil {
				a.log.Warn().Err(err).Msg("agent.handleRefreshComplianceRequest - failed to update compliance config")
				// Continue anyway - we still want to enable eBPF
			}

			// Enable eBPF if not already running
			if !a.platformData.nativeAgent.IsRunning() {
				if err := a.EnableNativeAgent(); err != nil {
					a.log.Error().Err(err).Msg("agent.handleRefreshComplianceRequest - failed to enable eBPF agent")
					response.Status = "failed"
					response.Error = "failed to enable eBPF agent: " + err.Error()
					a.sendRefreshComplianceResponse(req, response)
					return
				}
				response.Message = "compliance config applied, eBPF agent enabled"
			} else {
				response.Message = "compliance config applied, eBPF agent already running"
			}
		} else {
			response.Status = "failed"
			response.Error = "native agent not initialized"
		}
	} else {
		a.log.Info().Msg("agent.handleRefreshComplianceRequest - no profiles assigned, disabling eBPF")
		if a.platformData.nativeAgent != nil && a.platformData.nativeAgent.IsRunning() {
			if err := a.DisableNativeAgent(); err != nil {
				a.log.Warn().Err(err).Msg("agent.handleRefreshComplianceRequest - failed to disable eBPF agent")
			}
		}
		response.Message = "no profiles assigned, eBPF agent disabled"
	}

	a.sendRefreshComplianceResponse(req, response)
}

// handleNativeRulesUpdateRequest handles the native_rules.update command
// This command pushes compiled YAML detection rules from the API to the agent
func (a *agent) handleNativeRulesUpdateRequest(req client.Request) {
	a.log.Info().Msg("agent.handleNativeRulesUpdateRequest - received native_rules.update command")

	response := client.GeneralCommandResponse{
		Status: "success",
	}

	// Parse the YAML from command params
	var rulesPayload struct {
		YAML      string   `json:"yaml"`
		Hash      string   `json:"hash"`
		Policies  []string `json:"policies"`
		RuleCount int      `json:"ruleCount"`
	}

	if err := json.Unmarshal(req.Params, &rulesPayload); err != nil {
		a.log.Error().Err(err).Msg("agent.handleNativeRulesUpdateRequest - failed to parse rules payload")
		response.Status = "failed"
		response.Error = "failed to parse rules payload: " + err.Error()
		a.sendRefreshComplianceResponse(req, response)
		return
	}

	if a.platformData.nativeAgent == nil {
		response.Status = "failed"
		response.Error = "native agent not initialized"
		a.sendRefreshComplianceResponse(req, response)
		return
	}

	// Update the rule engine with the new YAML
	if err := a.platformData.nativeAgent.UpdateRulesFromYAML([]byte(rulesPayload.YAML)); err != nil {
		a.log.Error().Err(err).Msg("agent.handleNativeRulesUpdateRequest - failed to update rules")
		response.Status = "failed"
		response.Error = "failed to update rules: " + err.Error()
		a.sendRefreshComplianceResponse(req, response)
		return
	}

	hashPrefix := rulesPayload.Hash
	if len(hashPrefix) > 8 {
		hashPrefix = hashPrefix[:8]
	}

	response.Message = fmt.Sprintf("rules updated: %d rules from %d policies (hash: %s)",
		rulesPayload.RuleCount, len(rulesPayload.Policies), hashPrefix)

	a.log.Info().
		Int("rule_count", rulesPayload.RuleCount).
		Strs("policies", rulesPayload.Policies).
		Str("hash", hashPrefix).
		Msg("agent.handleNativeRulesUpdateRequest - rules updated successfully")

	a.sendRefreshComplianceResponse(req, response)
}

// sendRefreshComplianceResponse sends a response for the refresh_compliance command
func (a *agent) sendRefreshComplianceResponse(req client.Request, response client.GeneralCommandResponse) {
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
		a.log.Err(err).Msg("agent.sendRefreshComplianceResponse - error sending response")
	}
}


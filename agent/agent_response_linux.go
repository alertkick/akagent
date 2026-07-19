//go:build linux

package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"akagent/agent/responder"
	"akagent/client"
)

// responderConfig resolves the active-response enforcement settings. Once the
// control plane has pushed a native config (nativeConfigReceived), the pushed
// response_enforce/response_allowlist are authoritative — this is what makes the
// per-host enforce toggle and the tenant kill switch work without an agent
// restart. Before the first config (headless installs with no control plane),
// it falls back to the RESPONSE_ENFORCE/RESPONSE_ALLOWLIST env vars.
func (a *agent) responderConfig() responder.Config {
	if a.platformData.nativeConfigReceived.Load() && a.platformData.nativeAgent != nil {
		nc := a.platformData.nativeAgent.GetNativeConfig()
		return responder.Config{
			DryRun:    !nc.ResponseEnforce,
			Allowlist: nc.ResponseAllowlist,
		}
	}
	return responder.Config{
		DryRun:    os.Getenv("RESPONSE_ENFORCE") != "true",
		Allowlist: splitCSV(os.Getenv("RESPONSE_ALLOWLIST")),
	}
}

// getResponder lazily constructs the active-response handler on first use,
// seeding it from responderConfig (pushed config if present, else env). It
// defaults to dry-run: nothing is enforced until response_enforce is true (or
// RESPONSE_ENFORCE=true on a headless host).
func (a *agent) getResponder() *responder.Responder {
	a.platformData.responderMu.Lock()
	defer a.platformData.responderMu.Unlock()
	if a.platformData.responder == nil {
		a.platformData.responder = responder.New(a.responderConfig(), func(action, target, result string) {
			a.log.Info().Str("action", action).Str("target", target).Str("result", result).Msg("active-response")
		})
	}
	return a.platformData.responder
}

// refreshResponderConfig live-updates the responder's enforcement settings from
// the current native config. Called after a native config is applied so an
// enforce/kill-switch change takes effect without an agent restart. No-op if the
// responder hasn't been constructed yet — getResponder seeds it from the current
// config on first use.
func (a *agent) refreshResponderConfig() {
	a.platformData.responderMu.Lock()
	defer a.platformData.responderMu.Unlock()
	if a.platformData.responder != nil {
		a.platformData.responder.UpdateConfig(a.responderConfig())
	}
}

type responseBlockIPRequest struct {
	IP              string `json:"ip"`
	DurationSeconds int    `json:"duration_seconds"`
}

type responseKillRequest struct {
	PID int `json:"pid"`
}

func (a *agent) handleResponseBlockIPRequest(req client.Request) {
	resp := client.GeneralCommandResponse{Status: "success"}
	var body responseBlockIPRequest
	if err := json.Unmarshal(req.Params, &body); err != nil {
		a.sendCommandResponse(req, failResp("parse: "+err.Error()))
		return
	}
	if body.IP == "" {
		a.sendCommandResponse(req, failResp("ip is required"))
		return
	}
	if err := a.getResponder().BlockIP(body.IP, body.DurationSeconds); err != nil {
		a.sendCommandResponse(req, failResp(err.Error()))
		return
	}
	resp.Message = fmt.Sprintf("block_ip %s issued", body.IP)
	a.sendCommandResponse(req, resp)
}

func (a *agent) handleResponseUnblockIPRequest(req client.Request) {
	var body responseBlockIPRequest
	if err := json.Unmarshal(req.Params, &body); err != nil {
		a.sendCommandResponse(req, failResp("parse: "+err.Error()))
		return
	}
	if body.IP == "" {
		a.sendCommandResponse(req, failResp("ip is required"))
		return
	}
	if err := a.getResponder().UnblockIP(body.IP); err != nil {
		a.sendCommandResponse(req, failResp(err.Error()))
		return
	}
	a.sendCommandResponse(req, client.GeneralCommandResponse{Status: "success", Message: "unblock_ip " + body.IP + " issued"})
}

func (a *agent) handleResponseKillProcessRequest(req client.Request) {
	var body responseKillRequest
	if err := json.Unmarshal(req.Params, &body); err != nil {
		a.sendCommandResponse(req, failResp("parse: "+err.Error()))
		return
	}
	if err := a.getResponder().KillProcess(body.PID); err != nil {
		a.sendCommandResponse(req, failResp(err.Error()))
		return
	}
	a.sendCommandResponse(req, client.GeneralCommandResponse{Status: "success", Message: fmt.Sprintf("kill_process %d issued", body.PID)})
}

func failResp(msg string) client.GeneralCommandResponse {
	return client.GeneralCommandResponse{Status: "failed", Error: msg}
}

// sendCommandResponse is the generic command reply used by the response
// handlers (mirrors sendFIMResponse).
func (a *agent) sendCommandResponse(req client.Request, response client.GeneralCommandResponse) {
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
		a.log.Err(err).Msg("agent.sendCommandResponse - error sending response")
	}
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

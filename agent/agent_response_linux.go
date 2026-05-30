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

// getResponder lazily constructs the active-response handler. It defaults to
// dry-run; an operator turns on real enforcement by setting RESPONSE_ENFORCE=true,
// and protects extra addresses via RESPONSE_ALLOWLIST (comma-separated IPs/CIDRs).
func (a *agent) getResponder() *responder.Responder {
	a.platformData.responderOnce.Do(func() {
		cfg := responder.Config{
			DryRun:    os.Getenv("RESPONSE_ENFORCE") != "true",
			Allowlist: splitCSV(os.Getenv("RESPONSE_ALLOWLIST")),
		}
		a.platformData.responder = responder.New(cfg, func(action, target, result string) {
			a.log.Info().Str("action", action).Str("target", target).Str("result", result).Msg("active-response")
		})
	})
	return a.platformData.responder
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

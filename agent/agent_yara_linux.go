//go:build linux

package agent

import (
	"encoding/json"

	"akagent/client"
)

// yaraSyncRulesRequest is the payload for the yara.sync_rules command: the
// assembled ruleset bundle (curated base pack + tenant custom rules) the
// control plane wants the scanner to use, plus an opaque content version for
// logging/debugging.
type yaraSyncRulesRequest struct {
	Content string `json:"content"`
	Version string `json:"version"`
}

// handleYaraSyncRulesRequest writes the pushed ruleset to disk and hot-swaps
// the scanner. Delivering rules over the command channel (rather than an HTTP
// pull) means no tenant API key has to live on the host.
func (a *agent) handleYaraSyncRulesRequest(req client.Request) {
	resp := client.GeneralCommandResponse{Status: "success"}
	var body yaraSyncRulesRequest
	if err := json.Unmarshal(req.Params, &body); err != nil {
		resp.Status = "failed"
		resp.Error = "parse: " + err.Error()
		a.sendYaraResponse(req, resp)
		return
	}
	if a.platformData.nativeAgent == nil {
		resp.Status = "failed"
		resp.Error = "native agent not running on this host"
		a.sendYaraResponse(req, resp)
		return
	}
	if err := a.platformData.nativeAgent.YaraApplyRules(body.Content); err != nil {
		resp.Status = "failed"
		resp.Error = "apply rules: " + err.Error()
		a.sendYaraResponse(req, resp)
		return
	}
	resp.Message = "yara ruleset applied"
	a.sendYaraResponse(req, resp)
}

func (a *agent) sendYaraResponse(req client.Request, response client.GeneralCommandResponse) {
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
		a.log.Err(err).Msg("agent.sendYaraResponse - error sending response")
	}
}

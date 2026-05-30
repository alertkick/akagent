//go:build linux

package agent

import (
	"encoding/json"
	"fmt"

	"akagent/client"
)

// fimApprovePathsRequest is the payload for the fim.approve_paths command:
// the operator-reviewed paths whose current on-disk content should become the
// new known-good baseline.
type fimApprovePathsRequest struct {
	Paths []string `json:"paths"`
}

// handleFIMApprovePathsRequest re-baselines the approved paths so they are no
// longer flagged as changed.
func (a *agent) handleFIMApprovePathsRequest(req client.Request) {
	resp := client.GeneralCommandResponse{Status: "success"}
	var body fimApprovePathsRequest
	if err := json.Unmarshal(req.Params, &body); err != nil {
		resp.Status = "failed"
		resp.Error = "parse: " + err.Error()
		a.sendFIMResponse(req, resp)
		return
	}
	if a.platformData.nativeAgent == nil {
		resp.Status = "failed"
		resp.Error = "native agent not running on this host"
		a.sendFIMResponse(req, resp)
		return
	}
	if len(body.Paths) == 0 {
		resp.Status = "failed"
		resp.Error = "paths must not be empty"
		a.sendFIMResponse(req, resp)
		return
	}
	a.platformData.nativeAgent.FIMApprovePaths(body.Paths)
	resp.Message = fmt.Sprintf("approved %d path(s)", len(body.Paths))
	a.sendFIMResponse(req, resp)
}

// handleFIMRebaselineRequest rescans every monitored path and accepts current
// disk state as the new baseline. The scan can be slow, so it runs in the
// background and the command returns immediately.
func (a *agent) handleFIMRebaselineRequest(req client.Request) {
	resp := client.GeneralCommandResponse{Status: "success"}
	if a.platformData.nativeAgent == nil {
		resp.Status = "failed"
		resp.Error = "native agent not running on this host"
		a.sendFIMResponse(req, resp)
		return
	}
	go a.platformData.nativeAgent.FIMRebaseline()
	resp.Message = "rebaseline started"
	a.sendFIMResponse(req, resp)
}

func (a *agent) sendFIMResponse(req client.Request, response client.GeneralCommandResponse) {
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
		a.log.Err(err).Msg("agent.sendFIMResponse - error sending response")
	}
}

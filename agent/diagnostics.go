package agent

import (
	"context"
	"encoding/json"
	"time"

	"akagent/client"
	"akagent/diagnostics"
)

// Diagnostics command family: read-only, fixed-catalog host inspection for
// the cloud SRE agent (Kicker). Enforcement of "is this tenant/host allowed
// to run diagnostics" happens API-side before a command is ever queued; the
// agent's job is argument validation, read-only execution, and output caps.
// See the diagnostics package for the catalog rules.

// handleDiagnosticsRequest dispatches diagnostics.* methods. Returns false
// when the method is not a diagnostics command.
func (a *agent) handleDiagnosticsRequest(req client.Request) bool {
	switch req.Method {
	case "diagnostics.bundle", "diagnostics.journal", "diagnostics.processes":
		a.goHandle(req.Method, req, a.runDiagnostics)
		return true
	default:
		return false
	}
}

func (a *agent) runDiagnostics(req client.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	var (
		result diagnostics.Result
		err    error
	)
	switch req.Method {
	case "diagnostics.journal":
		var args diagnostics.JournalArgs
		if err = json.Unmarshal(orEmptyObject(req.Params), &args); err == nil {
			result, err = diagnostics.Journal(ctx, args)
		}
	case "diagnostics.processes":
		var args diagnostics.ProcessesArgs
		if err = json.Unmarshal(orEmptyObject(req.Params), &args); err == nil {
			result, err = diagnostics.Processes(ctx, args)
		}
	case "diagnostics.bundle":
		var args diagnostics.BundleArgs
		if err = json.Unmarshal(orEmptyObject(req.Params), &args); err == nil {
			result, err = diagnostics.Bundle(ctx, args)
		}
	}

	var payload []byte
	if err != nil {
		a.log.Warn().Err(err).Str("method", req.Method).Msg("agent.runDiagnostics - failed")
		payload, _ = json.Marshal(map[string]string{"error": err.Error()})
	} else {
		a.log.Info().Str("method", req.Method).Int("output_bytes", len(result.Output)).
			Msg("agent.runDiagnostics - complete")
		payload, _ = json.Marshal(result)
	}

	msg := client.Response{
		Version:   "1",
		ID:        req.ID,
		Target:    "agent",
		Source:    a.AgentID,
		Tenant:    a.Subdomain,
		Subdomain: a.Subdomain,
		Result:    json.RawMessage(payload),
	}
	if sendErr := a.conn.SendJSONMessageNoResponse(msg); sendErr != nil {
		a.log.Err(sendErr).Str("method", req.Method).Msg("agent.runDiagnostics - response send failed")
	}
}

func orEmptyObject(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("{}")
	}
	return raw
}

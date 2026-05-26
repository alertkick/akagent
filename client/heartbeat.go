package client

import (
	"akagent/logger"
	"encoding/json"
	"errors"
	"time"
)

var (
	hbLog = logger.Sublogger("heartbeat")
)

// NewHeartbeatMsg - generate a new Heartbeat type msg.
func (c *Connection) NewHeartbeatMsg() *Request {

	heartbeat := HeartbeatMessage{
		Timestamp: time.Now().UnixNano() / int64(time.Millisecond),
		CheckID:   "agent.heartbeat",
		CheckType: "agent.heartbeat",
		State:     "ok",
		Status:    "ok",
	}

	paramsJSON, err := json.Marshal(heartbeat)
	if err != nil {
		hbLog.Error().Err(err).Msg("Connection.NewHeartbeatMsg - error in generating paramsJSON")
	}
	hbLog.Debug().Msgf("Connection.NewHeartbeatMsg - heartbeat params: %s", string(paramsJSON))

	return &Request{
		Version:   "1",
		ID:        "1",
		Target:    "agent",
		Source:    c.agentID,
		Tenant:    c.subdomain,
		Subdomain: c.subdomain,
		Method:    "heartbeat.post",
		Params:    json.RawMessage(paramsJSON),
	}
}

func (c *Connection) doHeartbeat() error {
	// log.Println("sendHeartbeat")
	msg := c.NewHeartbeatMsg() //TODO: make heartbeat message generation efficient.
	requestID, responseCh, err := c.SendJSONMessage(msg)
	if err != nil {
		hbLog.Err(err).Msg("Connection.doHeartbeat - error during heartbeat submit.")
		return err
	}
	hbLog.Debug().Msgf("Connection.doHeartbeat - heartbeat sent as requestID: %s", requestID)
	// Wait for the response from the server with the specified timeout
	select {
	case response, ok := <-responseCh:
		if !ok {
			err = errors.New("Connection.doHeartbeat - response channel closed unexpectedly")
			hbLog.Err(err).Msg("Connection.doHeartbeat - error during heartbeat response. bailing out.")
			return err
		}
		hbLog.Debug().Msgf("Connection.doHeartbeat - heartbeat received response for requestID: %s, responseID: %s", requestID, response.ID)
		var heartbeat HeartbeatMessage
		err = json.Unmarshal(response.Result, &heartbeat)
		if err != nil {
			hbLog.Error().Err(err).Msg("Connection.doHeartbeat - error in unmarshal of response.Result")
			return err
		}
		latency := time.Now().UnixNano()/int64(time.Millisecond) - int64(heartbeat.Timestamp)
		hbLog.Info().Msgf("Connection.doHeartbeat - got heartbeat pong in %d ms", latency)

	case <-time.After(time.Duration(c.timeout) * time.Second):
		err = errors.New("Connection.doHeartbeat - heartbeat response timeout")
		hbLog.Err(err).Msgf("Connection.doHeartbeat - response timeout for Request ID:%s", requestID)
		return err
	}
	return nil
}

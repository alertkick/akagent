package client

import (
	"encoding/json"
	"errors"
	"time"
)

// NewHandshakeHelloMsg - generates a new HandlshakeHello msg
func (c *Connection) NewHandshakeHelloMsg() *Request {
	params := map[string]string{
		"agent_id":        c.agentID,
		"agent_name":      c.agentName,
		"agent_token":     c.agentToken,
		"process_version": "v1.0.0",
		"bundle_version":  "v1.0.0",
	}

	paramsJSON, err := json.Marshal(params)
	if err != nil {
		c.log.Error().Err(err).Msg("error in generating paramsJSON")
	}

	return &Request{
		Version:   "1",
		ID:        "10",
		Target:    "agent",
		Source:    c.agentID,
		Tenant:    c.subdomain,
		Subdomain: c.subdomain,
		Method:    "initial_handshake",
		Params:    json.RawMessage(paramsJSON),
	}
}

func (c *Connection) doHandshake() error {
	msg := c.NewHandshakeHelloMsg()
	requestID, responseCh, err := c.SendJSONMessage(msg)
	if err != nil {
		c.log.Err(err).Msg("error during handshake submit")
		return err
	}
	c.log.Debug().Msgf("handshake sent as requestID: %s", requestID)
	// Wait for the response from the server with the specified timeout
	select {
	case response, ok := <-responseCh:
		if !ok {
			err = errors.New("response channel closed unexpectedly")
			c.log.Err(err).Msg("error during handshake response. bailing out.")
			return err
		}
		c.log.Debug().Msgf("handshake received response for requestID: %s, responseID: %s", requestID, response.ID)
		c.log.Debug().Msgf("handshake response: %v", response)
		if response.Err.Message != "" {
			err = errors.New(response.Err.Message)
			c.log.Err(err).Msg(err.Error())
			return err
		}

	case <-time.After(time.Duration(c.timeout) * time.Second):
		err = errors.New("handshake response timeout")
		c.log.Err(err).Msgf("response timeout for request id:%s", requestID)
		return err
	}
	return nil
}

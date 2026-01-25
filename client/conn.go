package client

import (
	"apagent/certs"
	"apagent/config"
	"apagent/logger"
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// Define states for the connection
const (
	StateDisconnected = iota
	StateConnecting
	StateConnected
	StateShuttingDown
)

var (
	ErrNotConnected = errors.New("not connected")
)

type Connection struct {
	agentID            string
	agentName          string
	subdomain          string
	tenant             string
	TLSInsecure        bool
	TLSCAFilePath      string
	ServerReqChan      chan Request
	agentToken         string
	log                zerolog.Logger
	endpointAddr       string
	conn               *tls.Conn
	state              int
	messageChan        chan []byte
	responseChan       chan Response
	requests           map[string]chan Response // Map of request IDs to response channels
	requestLock        sync.Mutex               // Mutex for concurrent access to requests map
	wg                 sync.WaitGroup           // WaitGroup for graceful shutdown
	nextRequestID      int                      // Counter for generating unique request IDs
	timeout            int                      // Timeout for requests in seconds. Default is 30 seconds
	sentHeartbeatCount int                      // Count of heartbeats sent on this connection.
	heartbeatInterval  int                      // Heartbeat interval in seconds.
	version            string                   // Agent version
}

func (c *Connection) Close() error {
	if logger.IsSectionEnabled(logger.SectionConnection) {
		c.log.Debug().Msg("Connection.Close - closing connection, state = StateShuttingDown")
	}
	c.state = StateShuttingDown
	close(c.ServerReqChan) // close this channel otherwise agent watcher loop keeps waiting.
	if c.conn != nil {
		return c.conn.Close()
	} else {
		return nil
	}
}

// State returns the current state of the connection
func (c *Connection) State() int {
	return c.state
}

func (c *Connection) IsConnected() bool {
	return c.state == StateConnected
}

func NewConnection(conf *config.Config, log zerolog.Logger, version string) *Connection {
	// Create agent-contextualized logger with agent_id and subdomain
	agentLog := log.With().
		Str("agent_id", conf.AgentID).
		Str("subdomain", conf.Subdomain).
		Str("component", "connection").
		Logger()

	connection := &Connection{
		endpointAddr:      conf.Endpoint,
		agentID:           conf.AgentID,
		agentName:         conf.AgentName,
		subdomain:         conf.Subdomain,
		tenant:            conf.Subdomain,
		agentToken:        conf.AgentToken,
		TLSInsecure:       conf.TLSInsecure,
		TLSCAFilePath:     conf.TLSCAFilePath,
		state:             StateDisconnected,
		heartbeatInterval: 10,
		nextRequestID:     100,
		messageChan:       make(chan []byte),
		responseChan:      make(chan Response),
		requests:          make(map[string]chan Response),
		ServerReqChan:     make(chan Request),
		timeout:           20,
		log:               agentLog,
		version:           version,
	}
	go connection.StartConnection()
	return connection
}

func (c *Connection) StartConnection() {
	// Load CA certificate
	c.log.Info().Msg("Starting TLS connection setup")
	caCertPool := x509.NewCertPool()

	// first load the default CA certificate
	if !caCertPool.AppendCertsFromPEM(certs.CACert) {
		c.log.Error().Msg("Failed to append the default CA certificate")
		return
	}
	c.log.Info().Msg("Successfully loaded the default CA certificate")

	// then load all the additional CA certificates from the file if it exists
	if c.TLSCAFilePath != "" {
		caCert, err := os.ReadFile(c.TLSCAFilePath)
		if err != nil {
			c.log.Error().Err(err).Msg("Failed to read additional CA certificate file")
			return
		}
		if !caCertPool.AppendCertsFromPEM(caCert) {
			c.log.Error().Msg("Failed to append additional CA certificate")
			return
		}
		c.log.Info().Msg("Successfully loaded additional CA certificate from file")
	} else {
		c.log.Info().Msg("No additional CA certificate file provided, using only the default CA certificate")
	}

	config := &tls.Config{
		InsecureSkipVerify: c.TLSInsecure, // Change this to 'false' for production use
		RootCAs:            caCertPool,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			c.log.Info().Int("numCerts", len(rawCerts)).Msg("Received server certificates")
			for i, rawCert := range rawCerts {
				cert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					c.log.Error().Err(err).Int("certIndex", i).Msg("Failed to parse server certificate")
					return err
				}
				c.log.Info().Str("subject", cert.Subject.String()).Str("issuer", cert.Issuer.String()).Msg("Server certificate details")
			}
			return nil
		},
	}

	// Continuously try to connect to the RPC server until successful or we are in shutdown state
	delay := time.Second
	for c.State() == StateDisconnected && c.State() != StateShuttingDown {
		c.log.Info().Msg("Connection.StartConnection - Connecting to RPC server")
		c.log.Info().Str("endpoint", c.endpointAddr).Bool("insecure", c.TLSInsecure).Msg("Attempting to connect")
		d := tls.Dialer{
			Config: config,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := d.DialContext(ctx, "tcp", c.endpointAddr)
		if err != nil {
			if hostnameErr, ok := err.(*x509.HostnameError); ok {
				c.log.Error().
					Err(err).
					Str("expected", hostnameErr.Host).
					Str("got", hostnameErr.Certificate.Subject.CommonName).
					Msg("Connection.StartConnection - TLS hostname verification failed")
			} else if authorityErr, ok := err.(*x509.UnknownAuthorityError); ok {
				c.log.Error().
					Err(err).
					Str("authority", authorityErr.Cert.Issuer.String()).
					Str("endpoint", c.endpointAddr).
					Msg("Connection.StartConnection - Server certificate not signed by our CA")
			} else if certErr, ok := err.(*x509.CertificateInvalidError); ok {
				c.log.Error().
					Err(err).
					Int("reason", int(certErr.Reason)).
					Str("endpoint", c.endpointAddr).
					Msg("Connection.StartConnection - Server certificate is invalid")
			} else {
				c.log.Error().
					Err(err).
					Str("endpoint", c.endpointAddr).
					Msg("Connection.StartConnection - Error connecting to RPC server")
			}
			c.state = StateDisconnected
			c.log.Info().
				Err(err).
				Str("endpoint", c.endpointAddr).
				Msg("Connection.StartConnection - Waiting before retrying")
			time.Sleep(delay)
			if delay < 10*time.Minute {
				delay = delay * 2
			}
			continue
		} else {
			c.log.Info().Msg("Connection.StartConnection - Connected to RPC server, doing handshake messaging")
			c.conn = conn.(*tls.Conn)
			c.state = StateConnecting
			c.wg.Add(2)
			go c.connReaderLoop(&c.wg)
			go c.processMessageBytesLoop(&c.wg)

			if logger.IsSectionEnabled(logger.SectionConnection) {
				c.log.Debug().Msg("Connection.StartConnection - Sending handshake message")
			}
			err := c.doHandshake()
			if err != nil {
				c.log.Err(err).Msg("Connection.StartConnection - Error during connection handshake")
				c.state = StateDisconnected
				c.log.Info().Msgf("Connection.StartConnection - Waiting %s before retrying", delay)
				time.Sleep(delay)
				// Exponential backoff not more than 10 minutes
				if delay < 10*time.Minute {
					delay = delay * 2
				}
				continue
			} else {
				c.log.Info().Msg("Connection.StartConnection - Handshake successful, starting heartbeat ticker")
				c.state = StateConnected
				c.wg.Add(1)
				go c.startHeartbeatLoop(&c.wg)
				delay = time.Second
			}
		}
		if logger.IsSectionEnabled(logger.SectionConnection) {
			c.log.Debug().Msg("Connection.StartConnection - waiting for connReaderLoop, processMessageBytesLoop, and heartbeatLoop to finish")
		}
		c.wg.Wait()
		if logger.IsSectionEnabled(logger.SectionConnection) {
			c.log.Debug().Msg("Connection.StartConnection - Connection loops are all closed, retrying")
		}
	}
}

func (c *Connection) generateRequestID() string {
	c.requestLock.Lock()
	defer c.requestLock.Unlock()
	c.nextRequestID++
	return fmt.Sprintf("%d", c.nextRequestID)
}

func (c *Connection) SendJSONMessage(req *Request) (string, chan Response, error) {
	requestID := c.generateRequestID()
	req.ID = requestID

	// Generate correlation ID if not already set
	if req.CorrelationID == "" {
		req.CorrelationID = GenerateCorrelationID()
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		c.log.Err(err).Msg("SendJSONMessage - Error marshalling request")
		return "0", nil, err
	}

	responseCh := make(chan Response, 1)

	// Lock to safely add the response channel to the map
	c.requestLock.Lock()
	c.requests[requestID] = responseCh
	c.requestLock.Unlock()

	// Flow logging with [SEND] prefix (only when protocol section is enabled)
	if logger.IsSectionEnabled(logger.SectionProtocol) {
		c.log.Debug().
			Str("correlation_id", req.CorrelationID).
			Str("id", req.ID).
			Str("method", req.Method).
			Msg("[SEND] request")

		if logger.VerboseLevel > 0 {
			c.log.Debug().Str("data", logger.FormatBytes(jsonData)).Msg("[SEND] request data")
		}
	}
	_, err = c.conn.Write(jsonData)
	if err != nil {
		// Remove the response channel from the map on error
		c.requestLock.Lock()
		delete(c.requests, requestID)
		c.requestLock.Unlock()
		close(responseCh)
		return "0", nil, err
	}

	return requestID, responseCh, nil

}

// SendJSONMessageNoResponse sends a JSON message without expecting a response
func (c *Connection) SendJSONMessageNoResponse(msg Response) error {
	jsonData, err := json.Marshal(msg)
	if err != nil {
		c.log.Err(err).Msg("[SEND] Error marshalling response")
		return err
	}

	if logger.IsSectionEnabled(logger.SectionProtocol) {
		c.log.Debug().
			Str("id", msg.ID).
			Str("correlation_id", msg.CorrelationID).
			Msg("[SEND] response (no-reply)")

		if logger.VerboseLevel > 0 {
			c.log.Debug().Str("data", logger.FormatBytes(jsonData)).Msg("[SEND] response data")
		}
	}
	_, err = c.conn.Write(jsonData)
	if err != nil {
		c.log.Err(err).Msg("[SEND] Error sending response")
		return err
	}

	return nil
}

// CheckResultsPost sends a JSON message without expecting a response
func (c *Connection) CheckResultsPost(msg CheckResultsPost) error {
	if logger.IsSectionEnabled(logger.SectionMetrics) {
		c.log.Debug().Msgf("Connection.CheckResultsPost: ID: %s, Target: %s, method: %s", msg.ID, msg.Target, msg.Method)
	}
	if c.State() != StateConnected {
		return errors.New("not connected")
	}

	jsonData, err := json.Marshal(msg)
	if err != nil {
		c.log.Err(err).Msg("Connection.CheckResultsPost - Error marshalling CheckResultsPost")
		return err
	}

	if logger.VerboseLevel > 0 && logger.IsSectionEnabled(logger.SectionMetrics) {
		c.log.Debug().Str("data", logger.FormatBytes(jsonData)).Msg("CheckResultsPost - Sending")
	}
	_, err = c.conn.Write(jsonData)
	if err != nil {
		c.log.Err(err).Msg("Connection.CheckResultsPost - Error sending CheckResultsPost")
		return err
	}

	return nil
}

func (c *Connection) FalcoEventsPost(msg FalcoEventsPost) error {
	if logger.IsSectionEnabled(logger.SectionFalco) {
		c.log.Debug().Msgf("Connection.FalcoEventsPost: ID: %s, method: %s", msg.ID, msg.Method)
	}
	if c.State() != StateConnected {
		return errors.New("not connected")
	}

	jsonData, err := json.Marshal(msg)
	if err != nil {
		c.log.Err(err).Msg("Connection.FalcoEventsPost - Error marshalling FalcoEventsPost")
		return err
	}

	if logger.VerboseLevel > 0 && logger.IsSectionEnabled(logger.SectionFalco) {
		c.log.Debug().Str("data", logger.FormatBytes(jsonData)).Msg("FalcoEventsPost - Sending")
	}

	_, err = c.conn.Write(jsonData)
	if err != nil {
		c.log.Err(err).Msg("Connection.FalcoEventsPost - Error sending FalcoEventsPost")
		return err
	}

	return nil
}

// SecurityEventsPost sends a unified security event from any eBPF agent
func (c *Connection) SecurityEventsPost(msg SecurityEventsPost) error {
	if logger.IsSectionEnabled(logger.SectionFalco) {
		c.log.Debug().Msgf("Connection.SecurityEventsPost: ID: %s, method: %s, agent_type: %s", msg.ID, msg.Method, msg.AgentType)
	}
	if c.State() != StateConnected {
		return ErrNotConnected
	}

	jsonData, err := json.Marshal(msg)
	if err != nil {
		c.log.Err(err).Msg("Connection.SecurityEventsPost - Error marshalling SecurityEventsPost")
		return err
	}

	if logger.VerboseLevel > 0 && logger.IsSectionEnabled(logger.SectionFalco) {
		c.log.Debug().Str("data", logger.FormatBytes(jsonData)).Msg("SecurityEventsPost - Sending")
	}

	_, err = c.conn.Write(jsonData)
	if err != nil {
		c.log.Err(err).Msg("Connection.SecurityEventsPost - Error sending SecurityEventsPost")
		return err
	}

	return nil
}

func (c *Connection) processMessageBytes(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("Connection.processMessageBytes - data is nil")
	}

	if string(data) == "Connection closed\n" {
		if logger.IsSectionEnabled(logger.SectionConnection) {
			c.log.Debug().Msg("Connection.processMessageBytes - received `Connection closed` message")
		}
		c.state = StateDisconnected
		return errors.New("connection closed")
	}

	// First decode into request.
	var req Request
	var resp Response
	err := json.Unmarshal(data, &req)
	if err != nil {
		c.log.Error().Err(err).Msg("processMessageBytes - failed to unmarshal request")
		if logger.VerboseLevel > 0 && logger.IsSectionEnabled(logger.SectionProtocol) {
			c.log.Debug().Str("data", logger.FormatBytes(data)).Msg("processMessageBytes - raw message")
		}
		return err
	}

	// Log received message with [RECV] prefix and correlation ID
	if logger.IsSectionEnabled(logger.SectionProtocol) {
		c.log.Debug().
			Str("id", req.ID).
			Str("method", req.Method).
			Str("correlation_id", req.CorrelationID).
			Msg("[RECV] message")
	}
	if logger.VerboseLevel > 0 && logger.IsSectionEnabled(logger.SectionProtocol) {
		c.log.Debug().Str("data", logger.FormatBytes(data)).Msg("[RECV] message data")
	}

	// Check if it's a response
	if req.Method == "" {
		// It's a response, Unmarshal it and send to the corresponding request channel
		err := json.Unmarshal(data, &resp)
		if err != nil {
			c.log.Err(err).Msg("[RECV] failed to unmarshal response")
		}
		c.requestLock.Lock()
		requestCh, exists := c.requests[req.ID]
		if exists {
			if logger.IsSectionEnabled(logger.SectionProtocol) {
				c.log.Debug().
					Str("id", req.ID).
					Str("correlation_id", resp.CorrelationID).
					Msg("[RECV] response matched")
			}
			requestCh <- resp
			close(requestCh)
			delete(c.requests, req.ID)
		} else {
			c.log.Warn().
				Str("id", req.ID).
				Str("correlation_id", resp.CorrelationID).
				Msg("[RECV] orphan response, no matching request")
		}
		c.requestLock.Unlock()
	} else {
		if logger.IsSectionEnabled(logger.SectionProtocol) {
			c.log.Debug().
				Str("method", req.Method).
				Str("id", req.ID).
				Str("correlation_id", req.CorrelationID).
				Msg("[RECV] request, forwarding to handler")
		}
		// It's a request, add it to serverReqChan.
		c.ServerReqChan <- req
	}

	return nil
}

func (c *Connection) connReaderLoop(wg *sync.WaitGroup) {
	reader := bufio.NewReader(c.conn)

	if logger.IsSectionEnabled(logger.SectionConnection) {
		c.log.Debug().Msg("connReaderLoop - start")
	}

	for c.State() == StateConnected || c.State() == StateConnecting {
		message, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				c.log.Info().Msg("Connection.connReaderLoop - Connection closed by remote")
				break
			}
			c.log.Err(err).Msg("Connection.connReaderLoop - Error reading message")
			break
		}
		// Send the received message to the message channel
		c.messageChan <- []byte(message)
	}
	if logger.IsSectionEnabled(logger.SectionConnection) {
		c.log.Debug().Msg("connReaderLoop - sending Connection closed message to messageChan")
	}
	c.messageChan <- []byte("Connection closed\n")
	if logger.IsSectionEnabled(logger.SectionConnection) {
		c.log.Debug().Msg("connReaderLoop - done")
	}
	wg.Done()
}

// processMessageBytesLoop - reads messages from the message channel and processes them
func (c *Connection) processMessageBytesLoop(wg *sync.WaitGroup) {
	if logger.IsSectionEnabled(logger.SectionConnection) {
		c.log.Debug().Msg("processMessageBytesLoop - start")
	}
	for c.State() == StateConnected || c.State() == StateConnecting {
		message := <-c.messageChan // <- blocks for loop.
		// add select/switch if more than one use case
		err := c.processMessageBytes(message)
		if err != nil {
			c.log.Err(err).Msg("Connection.processMessageBytesLoop - Error handling message")
		}
	}
	if logger.IsSectionEnabled(logger.SectionConnection) {
		c.log.Debug().Msg("Connection.processMessageBytesLoop - done")
	}
	wg.Done()
}

// StartHeartbeatLoop - starts the heartbeat loop
func (c *Connection) startHeartbeatLoop(wg *sync.WaitGroup) {
	// we need to watch for failures and after 3 failures, we need to mark connection as disconnected
	failureCount := 0
	if logger.IsSectionEnabled(logger.SectionHeartbeat) {
		c.log.Debug().Msg("Connection.startHeartbeatLoop - start")
	}
	duration := time.Duration(c.heartbeatInterval) * time.Second
	if logger.IsSectionEnabled(logger.SectionHeartbeat) {
		c.log.Debug().Msgf("Connection.startHeartbeatLoop - Heartbeat interval: %f seconds", duration.Seconds())
	}
	for c.State() == StateConnected {
		err := c.doHeartbeat()
		if err != nil {
			duration = duration * 2
			c.log.Err(err).Msgf("Connection.startHeartbeatLoop - Error sending heartbeat, backing off, next try in %f seconds", duration.Seconds())
			failureCount++
			if failureCount > 3 {
				c.log.Err(err).Msgf("Connection.startHeartbeatLoop - Error sending heartbeat, backing off, next try in %f seconds", duration.Seconds())
				c.state = StateDisconnected
				break
			}
		}
		time.Sleep(duration)
	}
	if logger.IsSectionEnabled(logger.SectionHeartbeat) {
		c.log.Debug().Msg("Connection.startHeartbeatLoop - done")
	}
	wg.Done()
}

package client

import (
	"apagent/config"
	"sync"

	"github.com/rs/zerolog"
)

// Pool manages multiple Connection instances so the agent can maintain
// simultaneous links to several regional endpoints (e.g.
// eu-endpoint.alertpriority.com and us-endpoint.alertpriority.com).
//
// Behaviour:
//   - All connections heartbeat independently — each region knows the agent
//     is alive.
//   - Metrics, security events, and outbound requests are sent to the
//     **primary** connection only (the region matching the tenant's home
//     region). This avoids duplicate writes across regional databases.
//   - Incoming server requests can come from any connection. The Pool fans
//     them into a single ServerReqChan and remembers which connection
//     received each request so the matching response routes back to the
//     same place.
//
// Backward compatibility: callers that previously held a *Connection can
// switch to *Pool with no method-signature changes — Pool exposes the same
// surface (ServerReqChan, Close, IsConnected, CheckResultsPost,
// SecurityEventsPost, SecurityEventsBatchPost, SendJSONMessage,
// SendJSONMessageNoResponse).
type Pool struct {
	conns   []*Connection
	primary *Connection
	log     zerolog.Logger

	// requestSource maps inbound request IDs to the connection that received
	// them, so SendJSONMessageNoResponse can route the reply back on the
	// originating connection.
	requestSourceLock sync.Mutex
	requestSource     map[string]*Connection

	// ServerReqChan is the fan-in channel that surfaces requests from every
	// underlying connection's own ServerReqChan. Callers read from this and
	// dispatch handlers exactly as they did with a single Connection.
	ServerReqChan chan Request

	closeOnce sync.Once
}

// NewPool builds a Pool from the agent config. If conf.Endpoints is set it
// uses that list; otherwise it falls back to a single-element list containing
// conf.Endpoint (legacy behaviour).
func NewPool(conf *config.Config, log zerolog.Logger, version string) *Pool {
	endpoints := append([]string(nil), conf.Endpoints...)
	if len(endpoints) == 0 && conf.Endpoint != "" {
		endpoints = []string{conf.Endpoint}
	}

	primaryAddr := conf.PrimaryEndpoint
	if primaryAddr == "" && len(endpoints) > 0 {
		primaryAddr = endpoints[0]
	}

	p := &Pool{
		log:           log.With().Str("component", "pool").Logger(),
		requestSource: make(map[string]*Connection),
		ServerReqChan: make(chan Request),
	}

	for _, ep := range endpoints {
		c := NewConnectionForEndpoint(conf, ep, log, version)
		p.conns = append(p.conns, c)
		if ep == primaryAddr {
			p.primary = c
		}
		go p.fanIn(c)
	}
	if p.primary == nil && len(p.conns) > 0 {
		p.primary = p.conns[0]
	}

	if p.primary != nil {
		p.log.Info().
			Int("connection_count", len(p.conns)).
			Str("primary_endpoint", p.primary.Endpoint()).
			Msg("Pool initialized")
	} else {
		p.log.Warn().Msg("Pool initialized with zero connections")
	}

	return p
}

// fanIn forwards a single connection's ServerReqChan into the pool's shared
// channel, recording the source for later response routing.
func (p *Pool) fanIn(c *Connection) {
	for req := range c.ServerReqChan {
		p.requestSourceLock.Lock()
		p.requestSource[req.ID] = c
		p.requestSourceLock.Unlock()
		p.ServerReqChan <- req
	}
}

// Connections returns all underlying connections (for tests / introspection).
func (p *Pool) Connections() []*Connection { return p.conns }

// Primary returns the primary connection (the one used for metric posting).
func (p *Pool) Primary() *Connection { return p.primary }

// IsConnected reports whether the primary connection is currently healthy.
// Heartbeat success on the primary is what determines whether the agent is
// "online" from the data-storing region's point of view.
func (p *Pool) IsConnected() bool {
	return p.primary != nil && p.primary.IsConnected()
}

// State returns the primary connection's state code (StateDisconnected,
// StateConnecting, StateConnected, StateShuttingDown). Provided for parity
// with *Connection so callers can drop-in replace it with *Pool.
func (p *Pool) State() int {
	if p.primary == nil {
		return StateDisconnected
	}
	return p.primary.State()
}

// Close closes every connection. Safe to call multiple times.
func (p *Pool) Close() error {
	var firstErr error
	p.closeOnce.Do(func() {
		for _, c := range p.conns {
			if err := c.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	})
	return firstErr
}

// === Methods routed to the primary connection ===

// CheckResultsPost sends check results to the primary endpoint only.
func (p *Pool) CheckResultsPost(msg CheckResultsPost) error {
	if p.primary == nil {
		return ErrNotConnected
	}
	return p.primary.CheckResultsPost(msg)
}

// SecurityEventsPost sends a single security event to the primary endpoint.
func (p *Pool) SecurityEventsPost(msg SecurityEventsPost) error {
	if p.primary == nil {
		return ErrNotConnected
	}
	return p.primary.SecurityEventsPost(msg)
}

// SecurityEventsBatchPost sends a batch of security events to the primary endpoint.
func (p *Pool) SecurityEventsBatchPost(msg SecurityEventsBatchPost) error {
	if p.primary == nil {
		return ErrNotConnected
	}
	return p.primary.SecurityEventsBatchPost(msg)
}

// SendJSONMessage sends an outbound request expecting a response. Routed to
// the primary connection — agent-initiated requests (e.g. agent_checks.get)
// fetch tenant-scoped data which only the primary region holds.
func (p *Pool) SendJSONMessage(req *Request) (string, chan Response, error) {
	if p.primary == nil {
		return "0", nil, ErrNotConnected
	}
	return p.primary.SendJSONMessage(req)
}

// SendJSONMessageNoResponse sends a fire-and-forget message. If msg.ID matches
// a previously fanned-in request, the reply is routed back to the originating
// connection. Otherwise it falls back to the primary.
func (p *Pool) SendJSONMessageNoResponse(msg Response) error {
	p.requestSourceLock.Lock()
	src, ok := p.requestSource[msg.ID]
	if ok {
		delete(p.requestSource, msg.ID)
	}
	p.requestSourceLock.Unlock()

	if src == nil {
		src = p.primary
	}
	if src == nil {
		return ErrNotConnected
	}
	return src.SendJSONMessageNoResponse(msg)
}

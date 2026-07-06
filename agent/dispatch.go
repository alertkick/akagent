package agent

import "akagent/client"

// goHandle runs a request handler in its own goroutine, with panic recovery.
// The request consumer is serial, so running a handler inline means a slow or
// wedged one pins the consumer and delays every other command. Dispatching
// here keeps the connection's read path live so a slow handler can't trigger
// heartbeat-timeout disconnects, and recovery ensures a panicking handler
// can't take down the agent. Handlers send their own ID-correlated response
// when they finish, so async dispatch is safe.
func (a *agent) goHandle(method string, req client.Request, fn func(client.Request)) {
	a.log.Debug().Str("method", method).Msg("agent.handleEBPFRequest - dispatching handler")
	go func() {
		defer func() {
			if r := recover(); r != nil {
				a.log.Error().
					Interface("panic", r).
					Str("method", method).
					Msg("agent.handleEBPFRequest - recovered panic in handler")
			}
		}()
		fn(req)
	}()
}

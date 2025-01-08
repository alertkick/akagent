package agent

import (
	"akagent/client"
	"akagent/internal/api"
	"sync"
	"time"
)

// StartResultSender - watches StartResultSubmitQueue of new results and sends them to endpoint
func (a *agent) StartResultSender(shutdown chan struct{}, wg *sync.WaitGroup) {
	a.log.Debug().Msg("agent.StartResultSender - starting")
	defer wg.Done()

	// we only send results every 30 seconds.
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-shutdown:
			a.log.Debug().Msg("agent.StartResultSender - stopping")
			return
		case res := <-a.checkerManager.ResultsSubmit:
			a.log.Debug().Msgf("agent.StartResultSender - received result from checkerManager: %v", res)
			a.queueCheckResult(res)
		case <-ticker.C:
			if a.conn.IsConnected() {
				a.processQueuedCheckResults()
			} else {
				a.log.Warn().Msg("agent.StartResultSender - not connected to endpoint, skipping check result sending")
				a.log.Debug().Msgf("agent.StartResultSender - queue size: %d", len(a.checkResultQueue))
			}
		}
	}
}

func (a *agent) queueCheckResult(params api.CheckMetricParams) {
	a.checkResultQueueMutex.Lock()
	defer a.checkResultQueueMutex.Unlock()

	if len(a.checkResultQueue) >= a.checkResultMaxQueueSize {
		// Remove the oldest event if the queue is full
		a.checkResultQueue = a.checkResultQueue[1:]
	}
	a.checkResultQueue = append(a.checkResultQueue, params)
}

func (a *agent) processQueuedCheckResults() {
	a.checkResultQueueMutex.Lock()
	defer a.checkResultQueueMutex.Unlock()

	if len(a.checkResultQueue) == 0 {
		a.log.Debug().Msg("agent.processQueuedCheckResults - no check results to process")
		return
	}

	a.log.Debug().Msgf("agent.processQueuedCheckResults - processing %d check results", len(a.checkResultQueue))
	for len(a.checkResultQueue) > 0 {
		params := a.checkResultQueue[0]
		err := a.SendCheckResults(params)
		if err != nil {
			a.log.Err(err).Msg("agent.processQueuedCheckResults - error during check_results.post")
			return
		}
		a.checkResultQueue = a.checkResultQueue[1:]
	}
}

func (a *agent) SendCheckResults(params api.CheckMetricParams) error {

	msg := client.CheckResultsPost{
		Version:   "1",
		ID:        "1",
		Target:    "agent",
		Source:    a.AgentID,
		Tenant:    a.Subdomain,
		Subdomain: a.Subdomain,
		Method:    "check_results.post",
		Params:    params,
	}

	err := a.conn.CheckResultsPost(msg)
	if err != nil {
		a.log.Err(err).Msg("agent.SendCheckResults - error during check_results.post")
	}
	return err
}

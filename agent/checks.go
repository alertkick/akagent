package agent

import (
	"akagent/client"
	"akagent/internal/api"
	"akagent/logger"
	"sync"
	"time"
)

// StartResultSender - watches StartResultSubmitQueue of new results and sends them to endpoint
func (a *agent) StartResultSender(shutdown chan struct{}, wg *sync.WaitGroup) {
	a.log.Info().Msg("agent.StartResultSender - starting")
	defer wg.Done()

	// we only send results every 30 seconds.
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-shutdown:
			a.log.Info().Msg("agent.StartResultSender - stopping")
			return
		case res := <-a.checkerManager.ResultsSubmit:
			if logger.IsSectionEnabled(logger.SectionMetrics) {
				a.log.Debug().Msgf("agent.StartResultSender - received result from checkerManager: %v", res)
			}
			a.queueCheckResult(res)
		case <-ticker.C:
			if logger.IsSectionEnabled(logger.SectionMetrics) {
				a.log.Debug().Msgf("agent.StartResultSender - ticker fired, checking connection status")
			}
			if a.conn.IsConnected() {
				if logger.IsSectionEnabled(logger.SectionMetrics) {
					a.log.Debug().Msgf("agent.StartResultSender - connected, processing queued check results (queue size: %d)", len(a.checkResultQueue))
				}
				a.processQueuedCheckResults()
			} else {
				a.log.Warn().Msgf("agent.StartResultSender - not connected to endpoint (state: %d), skipping check result sending, queue size: %d", a.conn.State(), len(a.checkResultQueue))
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
		if logger.IsSectionEnabled(logger.SectionMetrics) {
			a.log.Debug().Msg("agent.processQueuedCheckResults - no check results to process")
		}
		return
	}

	queueSize := len(a.checkResultQueue)
	if logger.IsSectionEnabled(logger.SectionMetrics) {
		a.log.Debug().Msgf("agent.processQueuedCheckResults - processing %d check results", queueSize)
	}
	sentCount := 0
	for len(a.checkResultQueue) > 0 {
		params := a.checkResultQueue[0]
		err := a.SendCheckResults(params)
		if err != nil {
			a.log.Err(err).Msgf("agent.processQueuedCheckResults - error during check_results.post, sent %d/%d before failure", sentCount, queueSize)
			return
		}
		a.checkResultQueue = a.checkResultQueue[1:]
		sentCount++
	}
	if logger.IsSectionEnabled(logger.SectionMetrics) {
		a.log.Debug().Msgf("agent.processQueuedCheckResults - successfully sent %d check results to endpoint", sentCount)
	}
}

func (a *agent) SendCheckResults(params api.CheckMetricParams) error {
	if logger.IsSectionEnabled(logger.SectionMetrics) {
		a.log.Debug().Msgf("agent.SendCheckResults - preparing to send check_id: %s, check_type: %s", params.CheckID, params.CheckType)
	}

	msg := client.CheckResultsPost{
		Version:   "1",
		ID:        "900",
		Target:    "agent",
		Source:    a.AgentID,
		Tenant:    a.Subdomain,
		Subdomain: a.Subdomain,
		Method:    "check_results.post",
		Params:    params,
	}

	err := a.conn.CheckResultsPost(msg)
	if err != nil {
		a.log.Err(err).Msgf("agent.SendCheckResults - error during check_results.post for check_id: %s", params.CheckID)
		return err
	}
	if logger.IsSectionEnabled(logger.SectionMetrics) {
		a.log.Debug().Msgf("agent.SendCheckResults - successfully sent check_id: %s to endpoint", params.CheckID)
	}
	return nil
}

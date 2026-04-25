package checker

import (
	"akagent/config"
	"akagent/internal/api"
	"akagent/logger"
	"context"
	"fmt"
	"path/filepath"
	"sync"
)

var (
	log = logger.Sublogger("checker")
)

type CheckerManager struct {
	ConfiguredChecks []api.ConfiguredCheck
	EnabledChecks    []api.EnabledCheck
	Debug            bool
	ResultsSubmit    chan api.CheckMetricParams
	resultsQueue     chan api.CheckMetricParams
	stopCtx          context.Context
}

func NewCheckerManager(stopCtx context.Context, checks []api.ConfiguredCheck, debug bool) *CheckerManager {
	return &CheckerManager{
		ConfiguredChecks: checks,
		Debug:            debug,
		ResultsSubmit:    make(chan api.CheckMetricParams, 10000),
		resultsQueue:     make(chan api.CheckMetricParams, 10000),
		stopCtx:          stopCtx,
	}
}

// Start - starts the Checker
func (cm *CheckerManager) Start() error {
	log.Info().Msg("CheckerManager.Start - starting")

	// load the agent checks from the config file
	log.Debug().Msgf("CheckerManager.Start - loading agent checks from file: %s", filepath.Join(config.LoadedConfigfilePath, "agent_checks.json"))
	agentChecks, err := config.LoadAgentChecks()
	if err != nil {
		// Don't abort - the server will send check schedule via CheckScheduleGet
		log.Warn().Err(err).Msg("CheckerManager.Start - failed to load agent checks from local file, will wait for server config")
	} else {
		// enable the checks from local config
		cm.ConfigureChecks(agentChecks.Checks)
	}

	// Always start the results processor - it's needed to forward results from checks to the agent
	if err := cm.RunResultsProcessor(); err != nil {
		return fmt.Errorf("akagent aborting, got runtime error: %w", err)
	}
	return nil
}

// ConfigureChecks - configure checks we got from the endpoint
func (cm *CheckerManager) ConfigureChecks(agentChecks []api.AgentCheck) {
	log.Debug().Msgf("CheckerManager.ConfigureChecks - checkSchedule: %+v", agentChecks)
	for i, agentCheck := range agentChecks {
		log.Info().Msgf("CheckerManager.ConfigureChecks - enabling check %d: check:%s, enabled:%t, period:%d, timeout:%d",
			i, agentCheck.CheckType, agentCheck.Enabled, agentCheck.Period, agentCheck.Timeout)
		err := cm.EnableCheck(agentCheck)
		if err != nil {
			log.Err(err).Msgf("CheckerManager.ConfigureChecks - error enabling check. error: %s", err.Error())
		}
	}
}

// EnableCheck - enables a single checker
func (cm *CheckerManager) EnableCheck(agentCheck api.AgentCheck) error {
	log.Debug().Msgf("CheckerManager.EnableCheck - enabling check: %s", agentCheck.CheckType)

	log.Debug().Msgf("CheckerManager.EnableCheck - configured checks: %+v", cm.ConfiguredChecks)
	log.Debug().Msgf("CheckerManager.EnableCheck - enabled checks starting: %+v", cm.EnabledChecks)

	// Check if already enabled
	for idx, enabledCheck := range cm.EnabledChecks {
		if enabledCheck.CheckType == agentCheck.CheckType {
			log.Debug().Msgf("CheckerManager.EnableCheck - idx:%d check %s with label %s already enabled", idx, agentCheck.CheckType, enabledCheck.Label)
			return nil
		}
	}

	// Find the check in configured checks
	for _, check := range cm.ConfiguredChecks {
		log.Debug().Msgf("CheckerManager.EnableCheck - checking configured check: %s", check.CheckType)
		if check.CheckType == agentCheck.CheckType {
			log.Debug().Msgf("CheckerManager.EnableCheck - check found: %s", check.CheckType)

			enabledCheck := api.EnabledCheck{
				CheckType: agentCheck.CheckType,
				Check:     check.Check,
				Details:   agentCheck.Details,
				Label:     agentCheck.Label,
			}
			cm.EnabledChecks = append(cm.EnabledChecks, enabledCheck)

			log.Debug().Msgf("CheckerManager.EnableCheck - enabled checks ending: %+v", cm.EnabledChecks)

			// Initialize and start only this newly added check
			log.Debug().Msgf("CheckerManager.EnableCheck - init and start check: %s", check.CheckType)
			err := enabledCheck.Check.Init(cm.resultsQueue, agentCheck)
			if err != nil {
				log.Warn().Msgf("CheckerManager.EnableCheck - failed to initialize the checker: %s", check.CheckType)
				return err
			}
			go enabledCheck.Check.Start(cm.stopCtx, cm.Debug)
			return nil
		}
	}

	log.Warn().Msgf("CheckerManager.EnableCheck - check type not found in configured checks: %s", agentCheck.CheckType)
	return nil
}

func (cm *CheckerManager) RunResultsProcessor() error {
	// We spawn go routine to read and process check results,
	var wg sync.WaitGroup
	defer wg.Wait()

	// Start processing records from perf.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case event := <-cm.resultsQueue:
				cm.ResultsSubmit <- event
				// cm.receiveResult(event)
				// TODO: add metrics
				// resulstsqueuemetrics.Received.Inc()
			case <-cm.stopCtx.Done():
				log.Info().Err(cm.stopCtx.Err()).Msg("CheckerManager.RunResultsProcessor - listening for events completed.")
				log.Info().Msgf("CheckerManager.RunResultsProcessor - unprocessed events in RB queue: %d", len(cm.resultsQueue))
				return
			}
		}
	}()

	// Wait for context to be cancelled and then stop.
	<-cm.stopCtx.Done()
	// we need to stop any monitors here
	return nil
}

func (cm *CheckerManager) receiveResult(event api.CheckMetricParams) {
	log.Debug().Str("checkerType", event.CheckType).Msgf("CheckerManager.receiveResult - checkResult for check:%v", event.CheckID)

	log.Info().Msgf("CheckerManager.receiveResult - received check result for check: %s", event.CheckID)
	switch event.CheckType {
	case "host.cpu":
		log.Debug().Msg("CheckerManager.receiveResult - processing host.cpu check results")
		log.Debug().Msgf("CheckerManager.receiveResult - event:%v", event)
		cm.ResultsSubmit <- event
	case "host.memory":
		log.Debug().Msg("CheckerManager.receiveResult - processing host.memory check results")
		cm.ResultsSubmit <- event
	case "remote.http":
		log.Debug().Msg("CheckerManager.receiveResult - processing remote.http check results")
		cm.ResultsSubmit <- event
	default:
		log.Warn().Str("checkType", event.CheckType).Msgf("CheckerManager.receiveResult - unknown event type: %v", event)
		cm.ResultsSubmit <- event
	}
}

//go:build windows

package main

import (
	"golang.org/x/sys/windows/svc"
)

const windowsServiceName = "AlertKickAgent"

// agentService adapts the agent lifecycle to the Windows Service Control
// Manager protocol. RUNNING is reported before the agent has connected to
// the endpoint: connection setup can block on network/TLS for longer than
// the SCM start timeout, and the agent retries connections internally, so
// "running" here means the process is up, not that it is checked in.
type agentService struct{}

func (s *agentService) Execute(args []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	status <- svc.Status{State: svc.StartPending}

	shutdown := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		runAgent(shutdown)
	}()

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				close(shutdown)
				<-done
				status <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		case <-done:
			// The agent exited without an SCM stop request (fatal error).
			// A non-zero exit code lets service recovery actions restart us.
			status <- svc.Status{State: svc.Stopped}
			return false, 1
		}
	}
}

func runningAsWindowsService() bool {
	isService, err := svc.IsWindowsService()
	return err == nil && isService
}

func runWindowsService() error {
	return svc.Run(windowsServiceName, &agentService{})
}

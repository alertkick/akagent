//go:build linux

package systemd

import (
	"akagent/logger"
	"context"
	"os/exec"
	"strconv"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"
)

var (
	log = logger.Sublogger("service-manager")
)

const (
	exitCodeSuccess                  = 0
	exitCodeFailedToListUnits        = 11
	exitCodeUnitNotFound             = 12
	exitCodeUnitNotInactive          = 13
	exitCodeUnitNotActive            = 14
	exitCodeUnitNotRunning           = 15
	exitCodeUnitNotDead              = 16
	exitCodeErrorWhileWaiting        = 17
	exitCodeTimeoutWaitingForRestart = 18
	exitCodeTimeoutWaitingForStop    = 19
	exitCodeTimeoutWaitingForStart   = 20
	exitCodeFailedToRestart          = 21
	exitCodeFailedToStop             = 22
	exitCodeFailedToStart            = 23
)

func CheckServiceStatus(serviceName string) int {
	ctx := context.Background()
	// Connect to systemd
	// Specifically this will look DBUS_SYSTEM_BUS_ADDRESS environment variable
	// For example: `unix:path=/run/dbus/system_bus_socket`
	systemdConnection, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		log.Error().Err(err).Msgf("failed to connect to systemd: %v", err)
		return exitCodeFailedToListUnits
	}
	defer systemdConnection.Close()

	listOfUnits, err := systemdConnection.ListUnitsContext(ctx)
	if err != nil {
		log.Error().Err(err).Msgf("failed to list units: %v", err)
		return exitCodeFailedToListUnits
	}

	found := false
	targetUnit := dbus.UnitStatus{}
	for _, unit := range listOfUnits {
		if unit.Name == serviceName {
			log.Info().Msgf("found systemd unit %s", serviceName)
			found = true
			targetUnit = unit
			break
		}
	}
	if !found {
		log.Error().Msgf("expected systemd unit %s not found", serviceName)
		return exitCodeUnitNotFound
	}

	// Validate it's current state
	desiredActiveState := "active"
	desiredSubState := "running"
	log.Info().Msgf("unit %s is in state %s and substate %s", targetUnit.Name, targetUnit.ActiveState, targetUnit.SubState)
	if targetUnit.ActiveState != desiredActiveState {
		log.Error().Msgf("expected systemd unit %s to be active, but it is %s", serviceName, targetUnit.ActiveState)
		return exitCodeUnitNotActive
	}

	if targetUnit.SubState != desiredSubState {
		log.Error().Msgf("expected systemd unit %s to be running, but it is %s", serviceName, targetUnit.SubState)
		return exitCodeUnitNotRunning
	}

	return exitCodeSuccess
}

func RestartService(serviceName string) int {
	ctx := context.Background()
	// Connect to systemd
	// Specifically this will look DBUS_SYSTEM_BUS_ADDRESS environment variable
	// For example: `unix:path=/run/dbus/system_bus_socket`
	systemdConnection, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		log.Error().Err(err).Msgf("failed to connect to systemd: %v", err)
		return exitCodeFailedToListUnits
	}
	defer systemdConnection.Close()

	listOfUnits, err := systemdConnection.ListUnitsContext(ctx)
	if err != nil {
		log.Error().Err(err).Msgf("failed to list units: %v", err)
		return exitCodeFailedToListUnits
	}

	found := false
	targetUnit := dbus.UnitStatus{}
	for _, unit := range listOfUnits {
		if unit.Name == serviceName {
			log.Info().Msgf("found systemd unit %s", serviceName)
			found = true
			targetUnit = unit
			break
		}
	}
	if !found {
		log.Error().Msgf("expected systemd unit %s not found", serviceName)
		return exitCodeUnitNotFound
	}

	// Validate it's current state, but don't fail if it's not active or running
	// we'll just attempt to restart it anyway
	desiredActiveState := "active"
	desiredSubState := "running"
	log.Info().Msgf("unit %s is in state %s and substate %s", targetUnit.Name, targetUnit.ActiveState, targetUnit.SubState)
	if targetUnit.ActiveState != desiredActiveState {
		log.Error().Msgf("expected systemd unit %s to be active, but it is %s", serviceName, targetUnit.ActiveState)
		// return exitCodeUnitNotActive
	}

	if targetUnit.SubState != desiredSubState {
		log.Error().Msgf("expected systemd unit %s to be running, but it is %s", serviceName, targetUnit.SubState)
		// return exitCodeUnitNotRunning
	}

	// Restart the service..
	restartMode := "replace"
	// What is the `mode` parameter? TLDR: I think we want replace
	// see: https://www.freedesktop.org/wiki/Software/systemd/dbus/
	// StartUnit() enqeues a start job, and possibly depending jobs. Takes the unit to activate, plus a mode string.
	// The mode needs to be one of replace, fail, isolate, ignore-dependencies, ignore-requirements.
	// If "replace" the call will start the unit and its dependencies, possibly replacing already queued jobs that conflict with this.
	// If "fail" the call will start the unit and its dependencies, but will fail if this would change an already queued job.
	// If "isolate" the call will start the unit in question and terminate all units that aren't dependencies of it.
	// If "ignore-dependencies" it will start a unit but ignore all its dependencies. If "ignore-requirements" it will start a unit
	//  but only ignore the requirement dependencies. It is not recommended to make use of the latter two options. Returns the newly created job object.
	completedRestartCh := make(chan string)

	jobID, err := systemdConnection.RestartUnitContext(
		ctx,
		serviceName,
		restartMode,
		completedRestartCh,
	)

	if err != nil {
		log.Error().Err(err).Msgf("failed to restart unit: %v", err)
		return exitCodeFailedToRestart
	}
	log.Info().Msgf("restart job id: %d", jobID)

	// Wait for the restart to complete
	select {
	case <-completedRestartCh:
		log.Info().Msgf("restart job completed for unit: %s", serviceName)
	case <-time.After(30 * time.Second):
		log.Error().Msgf("timed out waiting for restart job to complete for unit: %s", serviceName)
	}

	// Wait for the service to reach a running state
	channelBuffer := 10

	// Configure which changes we care about
	isRelevantChangeFunc := func(before *dbus.UnitStatus, after *dbus.UnitStatus) bool {
		if before.ActiveState != after.ActiveState {
			log.Info().Msgf("active state changed from %s to %s", before.ActiveState, after.ActiveState)
			return true
		}
		if before.SubState != after.SubState {
			log.Info().Msgf("sub state changed from %s to %s", before.SubState, after.SubState)
			return true
		}
		return false
	}

	// Ignore any services that we don't care about by filtering them out
	filterUnits := func(unit string) bool {
		return unit != serviceName
	}

	// Subscribe to the changes
	changeCh, errorCh := systemdConnection.SubscribeUnitsCustom(time.Millisecond*10, channelBuffer, isRelevantChangeFunc, filterUnits)

	// Wait for the service to be active and running or give up
	for {
		select {
		case changedUnits := <-changeCh:
			unitStatus := changedUnits[serviceName]
			log.Info().Msgf("unit %s has changed", serviceName)
			log.Info().Msgf("unitStatus dump: %+v", unitStatus)
			if unitStatus.ActiveState == desiredActiveState && unitStatus.SubState == desiredSubState {
				log.Info().Msgf("unit %s is now active and running", serviceName)
				return exitCodeSuccess
			}
		case <-errorCh:
			log.Error().Msgf("error while waiting for unit %s to change", serviceName)
			return exitCodeErrorWhileWaiting
		case <-time.After(30 * time.Second):
			log.Error().Msgf("timed out waiting for restart job to complete for unit: %s", serviceName)
			return exitCodeTimeoutWaitingForRestart
		}
	}

}

func StopService(serviceName string) int {
	ctx := context.Background()
	// Connect to systemd
	// Specifically this will look DBUS_SYSTEM_BUS_ADDRESS environment variable
	// For example: `unix:path=/run/dbus/system_bus_socket`
	systemdConnection, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		log.Error().Err(err).Msgf("failed to connect to systemd: %v", err)
		return exitCodeFailedToListUnits
	}
	defer systemdConnection.Close()

	listOfUnits, err := systemdConnection.ListUnitsContext(ctx)
	if err != nil {
		log.Error().Err(err).Msgf("failed to list units: %v", err)
		return exitCodeFailedToListUnits
	}

	found := false
	targetUnit := dbus.UnitStatus{}
	for _, unit := range listOfUnits {
		if unit.Name == serviceName {
			log.Info().Msgf("found systemd unit %s", serviceName)
			found = true
			targetUnit = unit
			break
		}
	}
	if !found {
		log.Error().Msgf("expected systemd unit %s not found", serviceName)
		return exitCodeUnitNotFound
	}

	// Validate if service is running
	log.Info().Msgf("unit %s is in state %s and substate %s", targetUnit.Name, targetUnit.ActiveState, targetUnit.SubState)
	if targetUnit.ActiveState != "active" {
		log.Error().Msgf("expected systemd unit %s to be active, but it is %s", serviceName, targetUnit.ActiveState)
		return exitCodeUnitNotActive
	}

	if targetUnit.SubState != "running" {
		log.Error().Msgf("expected systemd unit %s to be running, but it is %s", serviceName, targetUnit.SubState)
		return exitCodeUnitNotRunning
	}

	completedStopCh := make(chan string)

	jobID, err := systemdConnection.StopUnitContext(
		ctx,
		serviceName,
		"replace",
		completedStopCh,
	)

	if err != nil {
		log.Error().Err(err).Msgf("failed to stop unit: %v", err)
		return exitCodeFailedToStop
	}
	log.Info().Msgf("stop job id: %d", jobID)

	// Wait for the stop to complete
	select {
	case <-completedStopCh:
		log.Info().Msgf("stop job completed for unit: %s", serviceName)
	case <-time.After(30 * time.Second):
		log.Error().Msgf("timed out waiting for stop job to complete for unit: %s", serviceName)
	}

	// Wait for the service to reach a stopped state
	channelBuffer := 10

	// Configure which changes we care about
	isRelevantChangeFunc := func(before *dbus.UnitStatus, after *dbus.UnitStatus) bool {
		if before.ActiveState != after.ActiveState {
			log.Info().Msgf("active state changed from %s to %s", before.ActiveState, after.ActiveState)
			return true
		}
		if before.SubState != after.SubState {
			log.Info().Msgf("sub state changed from %s to %s", before.SubState, after.SubState)
			return true
		}
		return false
	}

	// Ignore any services that we don't care about by filtering them out
	filterUnits := func(unit string) bool {
		return unit != serviceName
	}

	// Subscribe to the changes
	changeCh, errorCh := systemdConnection.SubscribeUnitsCustom(time.Millisecond*10, channelBuffer, isRelevantChangeFunc, filterUnits)

	// Wait for the service to be active and running or give up
	for {
		select {
		case changedUnits := <-changeCh:
			unitStatus := changedUnits[serviceName]
			log.Info().Msgf("unit %s has changed", serviceName)
			log.Info().Msgf("unitStatus dump: %+v", unitStatus)
			if unitStatus.ActiveState == "inactive" && unitStatus.SubState == "dead" {
				log.Info().Msgf("unit %s is now inactive and dead", serviceName)
				return exitCodeSuccess
			}
		case <-errorCh:
			log.Error().Msgf("error while waiting for unit %s to change", serviceName)
			return exitCodeErrorWhileWaiting
		case <-time.After(30 * time.Second):
			log.Error().Msgf("timed out waiting for stop job to complete for unit: %s", serviceName)
			return exitCodeTimeoutWaitingForStop
		}
	}
}

// GetServiceStatus returns the current status of a systemd service
func GetServiceStatus(serviceName string) (string, string, int) {
	ctx := context.Background()
	systemdConnection, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		log.Error().Err(err).Msgf("failed to connect to systemd: %v", err)
		return "", "", exitCodeFailedToListUnits
	}
	defer systemdConnection.Close()

	listOfUnits, err := systemdConnection.ListUnitsContext(ctx)
	if err != nil {
		log.Error().Err(err).Msgf("failed to list units: %v", err)
		return "", "", exitCodeFailedToListUnits
	}

	for _, unit := range listOfUnits {
		if unit.Name == serviceName {
			log.Info().Msgf("unit %s is in state %s and substate %s", unit.Name, unit.ActiveState, unit.SubState)
			return unit.ActiveState, unit.SubState, exitCodeSuccess
		}
	}

	log.Error().Msgf("expected systemd unit %s not found", serviceName)
	return "", "", exitCodeUnitNotFound
}

// GetServiceLogs returns the recent logs for a systemd service using journalctl
func GetServiceLogs(serviceName string, lines int) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if lines <= 0 {
		lines = 100
	}
	if lines > 1000 {
		lines = 1000 // Cap at 1000 lines for safety
	}

	cmd := exec.CommandContext(ctx, "journalctl", "-u", serviceName, "-n", strconv.Itoa(lines), "--no-pager", "--output=short-iso")
	output, err := cmd.Output()
	if err != nil {
		log.Error().Err(err).Msgf("failed to get logs for service %s: %v", serviceName, err)
		return "", err
	}
	return string(output), nil
}

func StartService(serviceName string) int {
	ctx := context.Background()
	// Connect to systemd
	// Specifically this will look DBUS_SYSTEM_BUS_ADDRESS environment variable
	// For example: `unix:path=/run/dbus/system_bus_socket`
	systemdConnection, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		log.Error().Err(err).Msgf("failed to connect to systemd: %v", err)
		return exitCodeFailedToListUnits
	}
	defer systemdConnection.Close()

	listOfUnits, err := systemdConnection.ListUnitsContext(ctx)
	if err != nil {
		log.Error().Err(err).Msgf("failed to list units: %v", err)
		return exitCodeFailedToListUnits
	}

	found := false
	targetUnit := dbus.UnitStatus{}
	for _, unit := range listOfUnits {
		if unit.Name == serviceName {
			log.Info().Msgf("found systemd unit %s", serviceName)
			found = true
			targetUnit = unit
			break
		}
	}
	if !found {
		log.Error().Msgf("expected systemd unit %s not found", serviceName)
		return exitCodeUnitNotFound
	}

	// Validate if service is running
	log.Info().Msgf("unit %s is in state %s and substate %s", targetUnit.Name, targetUnit.ActiveState, targetUnit.SubState)
	if targetUnit.ActiveState != "inactive" {
		log.Error().Msgf("expected systemd unit %s to be inactive, but it is %s", serviceName, targetUnit.ActiveState)
		return exitCodeUnitNotInactive
	}

	if targetUnit.SubState != "dead" {
		log.Error().Msgf("expected systemd unit %s to be dead, but it is %s", serviceName, targetUnit.SubState)
		return exitCodeUnitNotDead
	}

	completedStartCh := make(chan string)

	jobID, err := systemdConnection.StartUnitContext(
		ctx,
		serviceName,
		"replace",
		completedStartCh,
	)

	if err != nil {
		log.Error().Err(err).Msgf("failed to start unit: %v", err)
		return exitCodeFailedToStart
	}
	log.Info().Msgf("start job id: %d", jobID)

	// Wait for the start to complete
	select {
	case <-completedStartCh:
		log.Info().Msgf("start job completed for unit: %s", serviceName)
	case <-time.After(30 * time.Second):
		log.Error().Msgf("timed out waiting for start job to complete for unit: %s", serviceName)
	}

	// Wait for the service to reach a running state
	channelBuffer := 10

	// Configure which changes we care about
	isRelevantChangeFunc := func(before *dbus.UnitStatus, after *dbus.UnitStatus) bool {
		if before.ActiveState != after.ActiveState {
			log.Info().Msgf("active state changed from %s to %s", before.ActiveState, after.ActiveState)
			return true
		}
		if before.SubState != after.SubState {
			log.Info().Msgf("sub state changed from %s to %s", before.SubState, after.SubState)
			return true
		}
		return false
	}

	// Ignore any services that we don't care about by filtering them out
	filterUnits := func(unit string) bool {
		return unit != serviceName
	}

	// Subscribe to the changes
	changeCh, errorCh := systemdConnection.SubscribeUnitsCustom(time.Millisecond*10, channelBuffer, isRelevantChangeFunc, filterUnits)

	// Wait for the service to be active and running or give up
	for {
		select {
		case changedUnits := <-changeCh:
			unitStatus := changedUnits[serviceName]
			log.Info().Msgf("unit %s has changed", serviceName)
			log.Info().Msgf("unitStatus dump: %+v", unitStatus)
			if unitStatus.ActiveState == "inactive" && unitStatus.SubState == "dead" {
				log.Info().Msgf("unit %s is now inactive and dead", serviceName)
				return exitCodeSuccess
			}
		case <-errorCh:
			log.Error().Msgf("error while waiting for unit %s to change", serviceName)
			return exitCodeErrorWhileWaiting
		case <-time.After(30 * time.Second):
			log.Error().Msgf("timed out waiting for start job to complete for unit: %s", serviceName)
			return exitCodeTimeoutWaitingForStart
		}
	}
}

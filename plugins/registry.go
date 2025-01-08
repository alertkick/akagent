package plugins

// ConfiguredChecks - XXX
type ConfiguredChecks struct {
	Name  string
	Check Check
}

// Check - interface
// Check is something which checks for one thing and collects metrics
//
//	and returns results interface or error
type Check interface {

	// Description returns a one-sentence description on the Check
	Description() string

	// returns sample config which this check requires.
	ConfigSample() string

	// Collects metrics and returns a struct with the results
	Collect() (interface{}, error)

	// Start starts the service
	Start() error

	// Stop stops the services and closes any necessary channels and connections
	Stop()
}

// CheckRegistry - check registry
type CheckRegistry func() Check

// Checks - list of all the checks
var Checks = map[string]CheckRegistry{}

// Add - Adds a check to the registry.
func Add(name string, registry CheckRegistry) {
	Checks[name] = registry
}

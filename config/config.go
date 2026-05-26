package config

import (
	"akagent/internal/api"
	"akagent/logger"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/rs/zerolog"
)

// Config struct
type Config struct {
	Debug      bool
	Subdomain  string
	AgentID    string
	AgentName  string
	AgentToken string

	// Endpoint is the legacy single-endpoint address ("host:port"). It is still
	// honoured for backward compatibility — if Endpoints is empty and Endpoint
	// is set, the agent will connect to just that one endpoint.
	Endpoint string

	// Endpoints is the list of regional endpoint addresses ("host:port") the
	// agent should maintain simultaneous connections to. The agent heartbeats
	// to all of them so each region knows the agent is alive, but only sends
	// metrics and security events to the primary endpoint.
	Endpoints []string `json:"endpoints,omitempty"`

	// PrimaryEndpoint must match one of the entries in Endpoints (or equal
	// Endpoint in legacy mode). It identifies which region this tenant's data
	// is stored in. Metrics and security events post here. Defaults to the
	// first Endpoints entry (or Endpoint) if unset.
	PrimaryEndpoint string `json:"primary_endpoint,omitempty"`

	TLSCAFilePath string
	TLSInsecure   bool
	BpfDir            string
	MapDir            string
	TracingPolicy     string
	K8sKubeConfigPath string

	// Logging configuration
	// VerboseLevel: 0=no bytes, 1=truncated, 2=full JSON, 3=hex dump
	VerboseLevel int `json:"verbose_level"`
	// LogSections: comma-separated list of sections to enable (e.g., "protocol,heartbeat")
	// Use "all" to enable all sections. Empty means only basic logs.
	LogSections string `json:"log_sections"`

	ProcFS        string
	KernelVersion string
	BTF           string
	Verbosity     int
	ForceSmallProgs bool
	ForceLargeProgs bool

	EnableProcessNs         bool
	EnableProcessCred       bool
	EnablePolicyFilter      bool
	EnablePolicyFilterDebug bool
	EnableK8s               bool

	DisableKprobeMulti bool

	RBSize      int
	RBSizeTotal int
	RBQueueSize int

	KMods []string

	ProcessCacheSize int
	DataCacheSize    int

	EventQueueSize        uint
	ExposeKernelAddresses bool
}

var LoadedConfigfilePath string
var ConfigDir string
var ConfigFile string
var (
	Option = &Config{
		Debug:                   false,
		ProcFS:                  "/proc",
		KernelVersion:           "",
		BTF:                     "",
		Verbosity:               3,
		ForceSmallProgs:         false,
		ForceLargeProgs:         false,
		EnableProcessNs:         false,
		EnableProcessCred:       false,
		EnablePolicyFilter:      false,
		EnablePolicyFilterDebug: true,
		EnableK8s:               false,
		DisableKprobeMulti:      false,
		TLSInsecure:             false,
		TLSCAFilePath:           "",
		RBSize:                  66560,
		RBSizeTotal:             66560,
		RBQueueSize:             65535,
		KMods:                   []string{},
		ProcessCacheSize:        65536,
		DataCacheSize:           1024,
		EventQueueSize:          10000,
		ExposeKernelAddresses:   false,
	}
	configLock = new(sync.RWMutex)
)

func LoadConfig(configfile string, log zerolog.Logger) {
	LoadedConfigfilePath = configfile
	loadConfig(true, configfile, log)
	watchConfigReloadSignal(configfile, log)
}

func UpdateConfigFileWithOption(config *Config) error {
	// 0600 — the config file holds AgentToken; restrict to the owning user.
	// OpenFile without O_CREATE ignores the mode bits, so we Chmod explicitly
	// to tighten the perms of any pre-existing file.
	file, err := os.OpenFile(LoadedConfigfilePath, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open config file for writing: %v", err)
	}
	defer file.Close()

	if err := os.Chmod(LoadedConfigfilePath, 0600); err != nil {
		return fmt.Errorf("failed to chmod config file: %v", err)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config); err != nil {
		return fmt.Errorf("failed to write config to file: %v", err)
	}

	return nil

}

func loadConfig(fail bool, filepath string, log zerolog.Logger) {
	file, err := os.ReadFile(filepath)
	if err != nil {
		log.Fatal().Err(err).Msg("open config: ")
		if fail {
			os.Exit(1)
		}
	}

	temp := new(Config)
	*temp = *Option
	if err = json.Unmarshal(file, temp); err != nil {
		log.Error().Err(err).Msg("error while parsing config")
		if fail {
			os.Exit(1)
		}
	}
	configLock.Lock()
	Option = temp
	configLock.Unlock()

	// Apply logging configuration from config file
	// Config file settings override environment variables
	if temp.VerboseLevel > 0 {
		logger.SetVerboseLevel(temp.VerboseLevel)
	}
	if temp.LogSections != "" {
		logger.SetLogSections(temp.LogSections)
	}
}

// GetConfig gets the config.
func GetConfig(log zerolog.Logger) *Config {
	configLock.RLock()
	defer configLock.RUnlock()
	log.Debug().Msgf("config: %+v", Option)
	return Option
}

// String redacts secret fields so the Config can be safely printed via %v/%+v.
// Any future log line that formats *Config inherits the redaction.
func (c *Config) String() string {
	if c == nil {
		return "<nil>"
	}
	// Local alias drops the Stringer method so %+v falls back to default
	// reflection formatting (otherwise we'd recurse forever).
	type alias Config
	redacted := alias(*c)
	if redacted.AgentToken != "" {
		redacted.AgentToken = "[REDACTED]"
	}
	return fmt.Sprintf("%+v", redacted)
}

func LoadAgentChecks() (api.AgentChecks, error) {
	file, err := os.ReadFile(filepath.Join(ConfigDir, "agent_checks.json"))
	if err != nil {
		return api.AgentChecks{}, fmt.Errorf("failed to read agent checks file: %v", err)
	}
	var agentChecks api.AgentChecks

	err = json.Unmarshal(file, &agentChecks)
	if err != nil {
		return api.AgentChecks{}, fmt.Errorf("failed to unmarshal agent checks: %v", err)
	}
	return agentChecks, nil
}

func WriteAgentChecks(agentChecks api.AgentChecks) error {
	file, err := json.Marshal(agentChecks)
	if err != nil {
		return fmt.Errorf("failed to marshal agent checks: %v", err)
	}
	formattedFile := formatJSON(file)
	return os.WriteFile(filepath.Join(ConfigDir, "agent_checks.json"), formattedFile, 0644)
}

func formatJSON(file []byte) []byte {
	var formattedJSON bytes.Buffer
	err := json.Indent(&formattedJSON, file, "", "  ")
	if err != nil {
		return file
	}
	return formattedJSON.Bytes()
}

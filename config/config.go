package config

import (
	"akagent/internal/api"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/rs/zerolog"
)

// Config struct
type Config struct {
	Debug             bool
	Subdomain         string
	AgentID           string
	AgentName         string
	AgentToken        string
	FalcoEnabled      bool
	Endpoint          string
	TLSCertFilePath   string
	TLSInsecure       bool
	BpfDir            string
	MapDir            string
	TracingPolicy     string
	K8sKubeConfigPath string

	ProcFS          string
	KernelVersion   string
	HubbleLib       string
	BTF             string
	Verbosity       int
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
		HubbleLib:               "/var/lib/alertkick-agent/",
		BTF:                     "",
		Verbosity:               3,
		ForceSmallProgs:         false,
		ForceLargeProgs:         false,
		FalcoEnabled:            false,
		EnableProcessNs:         false,
		EnableProcessCred:       false,
		EnablePolicyFilter:      false,
		EnablePolicyFilterDebug: true,
		EnableK8s:               false,
		DisableKprobeMulti:      false,

		RBSize:                66560,
		RBSizeTotal:           66560,
		RBQueueSize:           65535,
		KMods:                 []string{},
		ProcessCacheSize:      65536,
		DataCacheSize:         1024,
		EventQueueSize:        10000,
		ExposeKernelAddresses: false,
	}
	configLock = new(sync.RWMutex)
)

func LoadConfig(configfile string, log zerolog.Logger) {
	LoadedConfigfilePath = configfile
	loadConfig(true, configfile, log)
	s := make(chan os.Signal, 1)
	signal.Notify(s, syscall.SIGUSR2)
	go func() {
		for {
			<-s
			loadConfig(false, configfile, log)
		}
	}()
}

func UpdateConfigFileWithOption(config *Config) error {
	file, err := os.OpenFile(LoadedConfigfilePath, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open config file for writing: %v", err)
	}
	defer file.Close()

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
}

// GetConfig gets the config.
func GetConfig(log zerolog.Logger) *Config {
	configLock.RLock()
	defer configLock.RUnlock()
	log.Debug().Msgf("config: %v", Option)
	return Option
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

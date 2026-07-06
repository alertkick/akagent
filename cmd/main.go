package main

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"akagent/agent"
	_ "akagent/checks/all"
	"akagent/common"
	"akagent/config"
	"akagent/logger"
)

var fConfigDir = flag.String("configdir", defaultConfigDir(), "path to config directory")
var fConfigFile = flag.String("config", defaultConfigFile(), "path to config file")
var fDebug = flag.Bool("debug", false, "Starts the agent and displays the metrics sent in the terminal")
var fVersion = flag.Bool("version", false, "display the version")
var fLogFile = flag.String("logfile", defaultLogFile(), "path to log file")
var fSetup = flag.Bool("setup", false, "setup the agent")

// Version - holds the version number
var Version string

func main() {

	flag.Parse()

	config.ConfigDir = *fConfigDir
	config.ConfigFile = *fConfigFile

	if *fVersion {
		v := fmt.Sprintf("AlertKick Monitoring Agent - Version %s", Version)
		fmt.Println(v)
		return
	}

	// When launched by the Windows Service Control Manager, hand control to
	// the service handler, which drives runAgent with an SCM-controlled
	// shutdown channel. Blocks until the service is stopped.
	if runningAsWindowsService() {
		if err := runWindowsService(); err != nil {
			logger.LogFilePath = *fLogFile
			log := logger.Get()
			log.Error().Err(err).Msg("Windows service run failed")
			os.Exit(1)
		}
		return
	}

	if *fSetup {
		logger.LogFilePath = *fLogFile
		Setup()
		return
	}

	shutdown := make(chan struct{})
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	go func() {
		<-signals
		close(shutdown)
	}()

	runAgent(shutdown)
}

// runAgent runs the full agent lifecycle — logging, config, endpoint
// connection — and blocks until the shutdown channel is closed (console:
// SIGINT; Windows service: SCM stop request).
func runAgent(shutdown chan struct{}) {
	fmt.Printf("Log file location: %s \n", *fLogFile)
	logger.LogFilePath = *fLogFile
	logger.SetupLogLevel(*fDebug)

	log := logger.Get()
	log.Info().Msgf("Reading configfile: %s", *fConfigFile)
	config.LoadConfig(*fConfigFile, log)
	conf := config.GetConfig(log)

	logger.SetupLogLevel(conf.Debug || *fDebug)
	log = logger.Get()

	hostname, kv, err := common.Uname()
	if err != nil {
		log.Panic().Msgf("failed to get uname: %s", err)
	}
	log.Info().Msgf("hostname: %s", hostname)
	log.Info().Msgf("kernel version: %s", kv)

	// Platform-specific kernel validation (Linux only, no-op on other platforms)
	validateKernel(log, kv)

	// Create a new agent
	agent, err := agent.NewAgentClient(conf, kv, log, Version)
	if err != nil {
		log.Error().Err(err).Msg("Error creating agent")
		panic(err)
	}

	if len(conf.AgentID) == 0 {
		err := errors.New("missing AgentID. Please define `agent_id` in alertkick-agent.conf")
		log.Fatal().Err(err).Msg("Error creating agent")
	}

	log.Info().Msgf("Agent ID: %s", conf.AgentID)
	log.Info().Msg("Starting AlertKick Agent (Version: " + Version + ")")

	// Run the agent until shutdown (blocking)
	err = agent.Run(shutdown)
	if err != nil {
		log.Error().Err(err).Msg("Error running agent")
		panic(err)
	}
}

func GetUserInput(promptString string) string {
	input := ""
	fmt.Println(promptString)
	fmt.Scanln(&input)
	return strings.TrimSpace(input)
}

func GetUserInputWithDefault(promptString string, defaultValue string) string {
	input := ""
	fmt.Println(promptString)
	fmt.Scanln(&input)
	if input == "" {
		return defaultValue
	}
	return strings.TrimSpace(input)
}

// Setup - sets up the agent
func Setup() {
	log := logger.Get()
	log.Info().Msg("Setting up agent")

	// Check if environment variables are defined
	agentEnv := os.Getenv("AP_AGENT_ENV")
	if agentEnv == "" {
		agentEnv = GetUserInputWithDefault("AP_AGENT_ENV variables not set. Please provide agent environment (staging or production)", "staging")
	}

	// Check if environment variables are defined
	agentToken := os.Getenv("AP_AGENT_TOKEN")
	if agentToken == "" {
		agentToken = GetUserInput("AP_AGENT_TOKEN variables not set. Please provide agent token")
	}

	agentID := os.Getenv("AP_AGENT_ID")
	if agentID == "" {
		agentID = GetUserInput("AP_AGENT_ID variables not set. Please provide agent ID")
	}

	hostLabel := os.Getenv("AP_AGENT_HOST_LABEL")
	if hostLabel == "" {
		defaultHostLabel := fmt.Sprintf("%s-%s", agentID, agentEnv)
		hostLabel = GetUserInputWithDefault("AP_AGENT_HOST_LABEL variables not set. Please provide host label", defaultHostLabel)
	}

	subdomain := os.Getenv("AP_AGENT_SUBDOMAIN")
	if subdomain == "" {
		subdomain = GetUserInput("AP_AGENT_SUBDOMAIN variables not set. Please provide subdomain")
	}

	log.Info().Msgf("Agent ID: %s", agentID)
	log.Info().Msgf("Host Label: %s", hostLabel)
	log.Info().Msgf("Subdomain: %s", subdomain)

	endpoint := os.Getenv("AP_AGENT_ENDPOINT")
	if endpoint == "" {
		if agentEnv == "staging" {
			endpoint = "monit-stg.alertkick.com:8585"
		} else {
			endpoint = "monit.alertkick.com:8585"
		}
	}

	// Verify the agent token by connecting to the endpoint over TLS.
	req, err := http.NewRequest("GET", "https://"+endpoint, nil)
	if err != nil {
		log.Panic().Err(err).Msg("Failed to create request")
	}
	req.Header.Set("Authorization", "Bearer "+agentToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Panic().Err(err).Msg("Failed to connect to endpoint")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Panic().Msgf("Failed to verify agent token, status code: %d", resp.StatusCode)
	}

	// On successful return, create the agent config file in the platform
	// config directory (honours -configdir).
	confContent := fmt.Sprintf(`{
		"AgentToken": "%s",
		"AgentID": "%s",
		"HostLabel": "%s",
		"Subdomain": "%s"
	}`, agentToken, agentID, hostLabel, subdomain)

	// create config directory if it doesn't exist
	confDir := *fConfigDir
	if _, err := os.Stat(confDir); os.IsNotExist(err) {
		os.MkdirAll(confDir, 0755)
	}

	confFilePath := filepath.Join(confDir, "alertkick-agent.conf")
	// 0600 — only the agent's user can read the file (it contains AgentToken).
	// On Windows the mode bits are close to meaningless; the install script
	// restricts the ACL on the config directory instead.
	err = os.WriteFile(confFilePath, []byte(confContent), 0600)
	if err != nil {
		log.Panic().Err(err).Msgf("Failed to update %s", confFilePath)
	}
	// Tighten perms in case the file already existed with a looser mode
	// (WriteFile only applies the mode on creation).
	if err := os.Chmod(confFilePath, 0600); err != nil {
		log.Panic().Err(err).Msgf("Failed to chmod %s", confFilePath)
	}
	log.Info().Msgf("Successfully updated %s", confFilePath)
	log.Info().Msg("Please restart the agent to continue")
}

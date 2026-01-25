package falco

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"apagent/ebpf"
	"apagent/internal/systemd"
	"apagent/logger"

	"github.com/rs/xid"
)

var log = logger.Sublogger("falco-agent")

const (
	defaultListenAddr    = "127.0.0.1"
	defaultListenPort    = 2801
	defaultConfigPath    = "/etc/falco/falco.yaml"
	defaultRulesDir      = "/etc/falco/rules.alertpriority/"
	defaultServiceName   = "falco-modern-bpf.service"
	eventChannelBufferSize = 1000
)

// FalcoAgent implements the EBPFAgent interface for Falco
type FalcoAgent struct {
	mu            sync.RWMutex
	listener      *http.Server
	eventChan     chan ebpf.SecurityEvent
	running       bool
	listening     bool
	listenAddr    string
	listenPort    int
	configPath    string
	rulesDir      string
	serviceName   string
	binaryPath    string
	shutdownChan  chan struct{}
}

// FalcoEventPayload represents the incoming Falco event format
type FalcoEventPayload struct {
	UUID          string                 `json:"uuid,omitempty"`
	Output        string                 `json:"output,omitempty"`
	Priority      string                 `json:"priority,omitempty"`
	Rule          string                 `json:"rule,omitempty"`
	Time          time.Time              `json:"time,omitempty"`
	OutputFields  map[string]interface{} `json:"output_fields,omitempty"`
	Source        string                 `json:"source,omitempty"`
	Tags          []string               `json:"tags,omitempty"`
	Hostname      string                 `json:"hostname,omitempty"`
}

// NewFalcoAgent creates a new Falco agent instance
func NewFalcoAgent() (*FalcoAgent, error) {
	detection := ebpf.DetectAgent(ebpf.AgentTypeFalco)

	configPath := defaultConfigPath
	if detection.ConfigPath != "" {
		configPath = detection.ConfigPath
	}

	rulesDir := defaultRulesDir
	if detection.RulesDir != "" {
		rulesDir = detection.RulesDir
	}

	serviceName := defaultServiceName
	if detection.ServiceName != "" {
		serviceName = detection.ServiceName
	}

	agent := &FalcoAgent{
		eventChan:    make(chan ebpf.SecurityEvent, eventChannelBufferSize),
		listenAddr:   defaultListenAddr,
		listenPort:   defaultListenPort,
		configPath:   configPath,
		rulesDir:     rulesDir,
		serviceName:  serviceName,
		binaryPath:   detection.BinaryPath,
		shutdownChan: make(chan struct{}),
	}

	return agent, nil
}

// Type returns the agent type
func (a *FalcoAgent) Type() ebpf.AgentType {
	return ebpf.AgentTypeFalco
}

// Name returns the human-readable name
func (a *FalcoAgent) Name() string {
	return "Falco"
}

// Version returns the installed version
func (a *FalcoAgent) Version() (string, error) {
	if !a.IsInstalled() {
		return "", fmt.Errorf("falco is not installed")
	}

	detection := ebpf.DetectAgent(ebpf.AgentTypeFalco)
	if detection.Version != "" {
		return detection.Version, nil
	}
	return "unknown", nil
}

// Start starts the Falco agent
func (a *FalcoAgent) Start(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.running {
		return nil
	}

	a.running = true
	log.Info().Msg("Falco agent started")
	return nil
}

// Stop stops the Falco agent
func (a *FalcoAgent) Stop(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.running {
		return nil
	}

	a.running = false
	log.Info().Msg("Falco agent stopped")
	return nil
}

// IsRunning returns whether the agent is running
func (a *FalcoAgent) IsRunning() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.running
}

// StartEventListener starts the HTTP listener for Falco events
func (a *FalcoAgent) StartEventListener(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.listening {
		return nil
	}

	// Ensure rules directory exists
	if err := a.ensureRulesDir(); err != nil {
		log.Warn().Err(err).Msg("Failed to ensure rules directory exists")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleEvent)
	mux.HandleFunc("/ping", a.handlePing)
	mux.HandleFunc("/healthz", a.handleHealth)

	addr := fmt.Sprintf("%s:%d", a.listenAddr, a.listenPort)
	a.listener = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadTimeout:       60 * time.Second,
		ReadHeaderTimeout: 60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	a.listening = true
	a.shutdownChan = make(chan struct{})

	go func() {
		log.Info().Msgf("Starting Falco event listener on %s", addr)
		if err := a.listener.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("Falco event listener error")
		}
	}()

	return nil
}

// StopEventListener stops the HTTP listener
func (a *FalcoAgent) StopEventListener() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.listening {
		return nil
	}

	if a.listener != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := a.listener.Shutdown(ctx); err != nil {
			log.Warn().Err(err).Msg("Error shutting down Falco listener")
		}
		a.listener = nil
	}

	close(a.shutdownChan)
	a.listening = false
	log.Info().Msg("Falco event listener stopped")
	return nil
}

// EventChannel returns the channel for receiving security events
func (a *FalcoAgent) EventChannel() <-chan ebpf.SecurityEvent {
	return a.eventChan
}

// IsListening returns whether the event listener is active
func (a *FalcoAgent) IsListening() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.listening
}

// LoadConfig loads the Falco configuration
func (a *FalcoAgent) LoadConfig() error {
	// Falco config is managed by the Falco service itself
	return nil
}

// UpdateConfig updates the Falco configuration
func (a *FalcoAgent) UpdateConfig(config ebpf.AgentConfig) error {
	// Configuration updates would be handled here
	return nil
}

// GetConfigPath returns the configuration file path
func (a *FalcoAgent) GetConfigPath() string {
	return a.configPath
}

// GetRules returns the list of rule files
func (a *FalcoAgent) GetRules() ([]ebpf.RuleFile, error) {
	files, err := a.listRulesFiles()
	if err != nil {
		return nil, err
	}

	rules := make([]ebpf.RuleFile, 0, len(files))
	for _, filename := range files {
		content, err := a.readRuleFile(filename)
		if err != nil {
			log.Warn().Err(err).Msgf("Error reading rule file: %s", filename)
			continue
		}

		md5sum := md5.Sum([]byte(content))
		encodedContent := base64.StdEncoding.EncodeToString([]byte(content))

		rules = append(rules, ebpf.RuleFile{
			Filename: filename,
			MD5Sum:   fmt.Sprintf("%x", md5sum),
			Content:  encodedContent,
			Size:     int64(len(content)),
		})
	}

	return rules, nil
}

// UpdateRules updates the rule files
func (a *FalcoAgent) UpdateRules(rules []ebpf.RuleFile) error {
	existingFiles, err := a.listRulesFiles()
	if err != nil {
		log.Warn().Err(err).Msg("Error listing existing rules files")
	}

	newFilesMap := make(map[string]bool)

	for _, rule := range rules {
		if rule.Content == "" {
			log.Warn().Msgf("Empty content for rule file: %s", rule.Filename)
			continue
		}

		// Decode base64 content
		cleanContent := strings.TrimSpace(rule.Content)
		decodedContent, err := base64.StdEncoding.DecodeString(cleanContent)
		if err != nil {
			log.Error().Err(err).Msgf("Error decoding rule file: %s", rule.Filename)
			continue
		}

		// Verify MD5
		md5sum := md5.Sum(decodedContent)
		if fmt.Sprintf("%x", md5sum) != rule.MD5Sum {
			log.Error().Msgf("MD5 mismatch for rule file: %s", rule.Filename)
			continue
		}

		// Write rule file
		if err := a.writeRuleFile(rule.Filename, string(decodedContent)); err != nil {
			log.Error().Err(err).Msgf("Error writing rule file: %s", rule.Filename)
			continue
		}

		newFilesMap[rule.Filename] = true
		log.Debug().Msgf("Updated rule file: %s", rule.Filename)
	}

	// Delete stale files
	for _, existingFile := range existingFiles {
		if !newFilesMap[existingFile] {
			log.Info().Msgf("Deleting stale rule file: %s", existingFile)
			if err := a.deleteRuleFile(existingFile); err != nil {
				log.Warn().Err(err).Msgf("Error deleting rule file: %s", existingFile)
			}
		}
	}

	// Restart service to apply changes
	log.Info().Msg("Rules updated, restarting Falco service")
	return a.RestartService()
}

// GetRulesDir returns the rules directory path
func (a *FalcoAgent) GetRulesDir() string {
	return a.rulesDir
}

// ServiceName returns the systemd service name
func (a *FalcoAgent) ServiceName() string {
	return a.serviceName
}

// GetServiceStatus returns the current service status
func (a *FalcoAgent) GetServiceStatus() (ebpf.ServiceStatus, error) {
	activeState, subState, returnCode := systemd.GetServiceStatus(a.serviceName)

	status := ebpf.ServiceStatus{
		ActiveState: activeState,
		SubState:    subState,
		Running:     activeState == "active" && subState == "running",
	}

	if returnCode != 0 {
		status.Error = fmt.Sprintf("failed to get status, return code: %d", returnCode)
	}

	return status, nil
}

// StartService starts the systemd service
func (a *FalcoAgent) StartService() error {
	returnCode := systemd.StartService(a.serviceName)
	if returnCode != 0 {
		return fmt.Errorf("failed to start service, return code: %d", returnCode)
	}
	return nil
}

// StopService stops the systemd service
func (a *FalcoAgent) StopService() error {
	returnCode := systemd.StopService(a.serviceName)
	if returnCode != 0 {
		return fmt.Errorf("failed to stop service, return code: %d", returnCode)
	}
	return nil
}

// RestartService restarts the systemd service
func (a *FalcoAgent) RestartService() error {
	returnCode := systemd.RestartService(a.serviceName)
	if returnCode != 0 {
		return fmt.Errorf("failed to restart service, return code: %d", returnCode)
	}
	return nil
}

// GetServiceLogs returns recent service logs
func (a *FalcoAgent) GetServiceLogs(lines int) (string, error) {
	return systemd.GetServiceLogs(a.serviceName, lines)
}

// IsInstalled returns whether Falco is installed
func (a *FalcoAgent) IsInstalled() bool {
	return a.binaryPath != ""
}

// GetBinaryPath returns the path to the Falco binary
func (a *FalcoAgent) GetBinaryPath() string {
	return a.binaryPath
}

// HTTP Handlers

func (a *FalcoAgent) handleEvent(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		http.Error(w, "empty request body", http.StatusBadRequest)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	event, err := a.parseFalcoPayload(r.Body)
	if err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		log.Debug().Err(err).Msg("Invalid Falco payload")
		return
	}

	// Convert to unified SecurityEvent
	secEvent := a.convertToSecurityEvent(event)

	// Send to channel (non-blocking)
	select {
	case a.eventChan <- secEvent:
		log.Debug().Msgf("Received Falco event: %s", secEvent.Rule)
	default:
		log.Warn().Msg("Event channel full, dropping event")
	}

	w.WriteHeader(http.StatusOK)
}

func (a *FalcoAgent) handlePing(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("pong\n"))
}

func (a *FalcoAgent) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status": "ok"}`))
}

// Helper functions

func (a *FalcoAgent) parseFalcoPayload(body io.Reader) (FalcoEventPayload, error) {
	var payload FalcoEventPayload

	decoder := json.NewDecoder(body)
	decoder.UseNumber()

	if err := decoder.Decode(&payload); err != nil {
		return FalcoEventPayload{}, err
	}

	// Set defaults
	if payload.Rule == "Test rule" {
		payload.Source = "internal"
	}
	if payload.Source == "" {
		payload.Source = "syscall"
	}

	payload.UUID = xid.New().String()

	if len(payload.Tags) > 0 {
		sort.Strings(payload.Tags)
	}

	// Clean output fields
	for key, value := range payload.OutputFields {
		if strings.Contains(key, "[") {
			newKey := strings.ReplaceAll(strings.ReplaceAll(key, "]", ""), "[", "")
			payload.OutputFields[newKey] = value
			delete(payload.OutputFields, key)
		}
	}

	return payload, nil
}

func (a *FalcoAgent) convertToSecurityEvent(payload FalcoEventPayload) ebpf.SecurityEvent {
	event := ebpf.SecurityEvent{
		UUID:      payload.UUID,
		AgentType: ebpf.AgentTypeFalco,
		Timestamp: payload.Time,
		Priority:  ebpf.ParsePriority(payload.Priority),
		Rule:      payload.Rule,
		Source:    payload.Source,
		Output:    payload.Output,
		Tags:      payload.Tags,
		Hostname:  payload.Hostname,
		RawFields: payload.OutputFields,
	}

	// Extract process info from output fields
	if payload.OutputFields != nil {
		if v, ok := payload.OutputFields["proc.name"]; ok {
			event.Process.Name = fmt.Sprintf("%v", v)
		}
		if v, ok := payload.OutputFields["proc.cmdline"]; ok {
			event.Process.Cmdline = fmt.Sprintf("%v", v)
		}
		if v, ok := payload.OutputFields["proc.exepath"]; ok {
			event.Process.ExePath = fmt.Sprintf("%v", v)
		}
		if v, ok := payload.OutputFields["proc.pname"]; ok {
			event.Process.ParentName = fmt.Sprintf("%v", v)
		}
		if v, ok := payload.OutputFields["user.name"]; ok {
			event.Process.Username = fmt.Sprintf("%v", v)
		}
		if v, ok := payload.OutputFields["user.uid"]; ok {
			if uid, ok := v.(json.Number); ok {
				if i, err := uid.Int64(); err == nil {
					event.Process.UID = int(i)
				}
			}
		}
		if v, ok := payload.OutputFields["user.loginuid"]; ok {
			if uid, ok := v.(json.Number); ok {
				if i, err := uid.Int64(); err == nil {
					event.Process.LoginUID = int(i)
				}
			}
		}
		if v, ok := payload.OutputFields["proc.tty"]; ok {
			if tty, ok := v.(json.Number); ok {
				if i, err := tty.Int64(); err == nil {
					event.Process.TTY = int(i)
				}
			}
		}

		// Container info
		if v, ok := payload.OutputFields["container.id"]; ok {
			event.Container.ID = fmt.Sprintf("%v", v)
		}
		if v, ok := payload.OutputFields["container.name"]; ok {
			event.Container.Name = fmt.Sprintf("%v", v)
		}
		if v, ok := payload.OutputFields["container.image"]; ok {
			event.Container.Image = fmt.Sprintf("%v", v)
		}

		// K8s info
		if v, ok := payload.OutputFields["k8s.ns.name"]; ok {
			event.K8s.Namespace = fmt.Sprintf("%v", v)
		}
		if v, ok := payload.OutputFields["k8s.pod.name"]; ok {
			event.K8s.Pod = fmt.Sprintf("%v", v)
		}

		// File info
		if v, ok := payload.OutputFields["fd.name"]; ok {
			event.File.Path = fmt.Sprintf("%v", v)
		}
		if v, ok := payload.OutputFields["evt.type"]; ok {
			event.File.Operation = fmt.Sprintf("%v", v)
		}
	}

	return event
}

func (a *FalcoAgent) ensureRulesDir() error {
	if _, err := os.Stat(a.rulesDir); os.IsNotExist(err) {
		return os.MkdirAll(a.rulesDir, 0755)
	}
	return nil
}

func (a *FalcoAgent) listRulesFiles() ([]string, error) {
	if err := a.ensureRulesDir(); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(a.rulesDir)
	if err != nil {
		return nil, err
	}

	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yaml") {
			files = append(files, entry.Name())
		}
	}
	return files, nil
}

func (a *FalcoAgent) readRuleFile(filename string) (string, error) {
	content, err := os.ReadFile(filepath.Join(a.rulesDir, filename))
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func (a *FalcoAgent) writeRuleFile(filename string, content string) error {
	if err := a.ensureRulesDir(); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(a.rulesDir, filename), []byte(content), 0644)
}

func (a *FalcoAgent) deleteRuleFile(filename string) error {
	return os.Remove(filepath.Join(a.rulesDir, filename))
}

// init registers the Falco agent with the factory
func init() {
	ebpf.Register(ebpf.AgentTypeFalco, func() (ebpf.EBPFAgent, error) {
		return NewFalcoAgent()
	})
}

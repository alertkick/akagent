package pixie

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"apagent/ebpf"
	"apagent/internal/systemd"
	"apagent/logger"

	"github.com/rs/xid"
)

var log = logger.Sublogger("pixie-agent")

const (
	defaultAPIEndpoint      = "http://localhost:11010"
	defaultConfigPath       = "/etc/pixie/config.yaml"
	defaultScriptsDir       = "/etc/pixie/scripts/"
	defaultServiceName      = "vizier-pem.service"
	eventChannelBufferSize  = 1000
)

// PixieAgent implements the EBPFAgent interface for Pixie
type PixieAgent struct {
	mu           sync.RWMutex
	eventChan    chan ebpf.SecurityEvent
	running      bool
	listening    bool
	apiEndpoint  string
	configPath   string
	scriptsDir   string
	serviceName  string
	binaryPath   string
	shutdownChan chan struct{}
	httpClient   *http.Client
}

// PixieEvent represents an incoming Pixie event
type PixieEvent struct {
	Time       string                 `json:"time,omitempty"`
	Table      string                 `json:"table,omitempty"`
	Data       map[string]interface{} `json:"data,omitempty"`
	Columns    []string               `json:"columns,omitempty"`
	RowBatch   [][]interface{}        `json:"row_batch,omitempty"`
}

// PixieHTTPTrace represents HTTP trace data from Pixie
type PixieHTTPTrace struct {
	Time       string `json:"time,omitempty"`
	Upid       string `json:"upid,omitempty"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	TraceRole  int    `json:"trace_role,omitempty"`
	MajorVersion int  `json:"major_version,omitempty"`
	MinorVersion int  `json:"minor_version,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	ReqHeaders map[string]string `json:"req_headers,omitempty"`
	ReqBody    string `json:"req_body,omitempty"`
	ReqMethod  string `json:"req_method,omitempty"`
	ReqPath    string `json:"req_path,omitempty"`
	RespHeaders map[string]string `json:"resp_headers,omitempty"`
	RespBody   string `json:"resp_body,omitempty"`
	RespStatus int    `json:"resp_status,omitempty"`
	Latency    int64  `json:"latency_ns,omitempty"`
	PodName    string `json:"pod,omitempty"`
	Service    string `json:"service,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
}

// PixieConnTrace represents connection trace data from Pixie
type PixieConnTrace struct {
	Time         string `json:"time,omitempty"`
	Upid         string `json:"upid,omitempty"`
	RemoteAddr   string `json:"remote_addr,omitempty"`
	RemotePort   int    `json:"remote_port,omitempty"`
	LocalAddr    string `json:"local_addr,omitempty"`
	LocalPort    int    `json:"local_port,omitempty"`
	Protocol     string `json:"protocol,omitempty"`
	Role         int    `json:"role,omitempty"` // 1=client, 2=server
	ConnOpen     int64  `json:"conn_open,omitempty"`
	ConnClose    int64  `json:"conn_close,omitempty"`
	BytesSent    int64  `json:"bytes_sent,omitempty"`
	BytesRecv    int64  `json:"bytes_recv,omitempty"`
	PodName      string `json:"pod,omitempty"`
	Service      string `json:"service,omitempty"`
	Namespace    string `json:"namespace,omitempty"`
	Cmdline      string `json:"cmdline,omitempty"`
}

// PixieProcessInfo represents process information from Pixie
type PixieProcessInfo struct {
	Upid      string `json:"upid,omitempty"`
	PID       int    `json:"pid,omitempty"`
	Cmdline   string `json:"cmdline,omitempty"`
	Binary    string `json:"binary,omitempty"`
	PodName   string `json:"pod,omitempty"`
	Container string `json:"container,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// NewPixieAgent creates a new Pixie agent instance
func NewPixieAgent() (*PixieAgent, error) {
	detection := ebpf.DetectAgent(ebpf.AgentTypePixie)

	configPath := defaultConfigPath
	if detection.ConfigPath != "" {
		configPath = detection.ConfigPath
	}

	scriptsDir := defaultScriptsDir
	if detection.RulesDir != "" {
		scriptsDir = detection.RulesDir
	}

	serviceName := defaultServiceName
	if detection.ServiceName != "" {
		serviceName = detection.ServiceName
	}

	agent := &PixieAgent{
		eventChan:    make(chan ebpf.SecurityEvent, eventChannelBufferSize),
		apiEndpoint:  defaultAPIEndpoint,
		configPath:   configPath,
		scriptsDir:   scriptsDir,
		serviceName:  serviceName,
		binaryPath:   detection.BinaryPath,
		shutdownChan: make(chan struct{}),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	return agent, nil
}

// Type returns the agent type
func (a *PixieAgent) Type() ebpf.AgentType {
	return ebpf.AgentTypePixie
}

// Name returns the human-readable name
func (a *PixieAgent) Name() string {
	return "Pixie"
}

// Version returns the installed version
func (a *PixieAgent) Version() (string, error) {
	if !a.IsInstalled() {
		return "", fmt.Errorf("pixie is not installed")
	}

	detection := ebpf.DetectAgent(ebpf.AgentTypePixie)
	if detection.Version != "" {
		return detection.Version, nil
	}
	return "unknown", nil
}

// Start starts the Pixie agent
func (a *PixieAgent) Start(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.running {
		return nil
	}

	a.running = true
	log.Info().Msg("Pixie agent started")
	return nil
}

// Stop stops the Pixie agent
func (a *PixieAgent) Stop(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.running {
		return nil
	}

	a.running = false
	log.Info().Msg("Pixie agent stopped")
	return nil
}

// IsRunning returns whether the agent is running
func (a *PixieAgent) IsRunning() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.running
}

// StartEventListener starts polling Pixie's API for events
func (a *PixieAgent) StartEventListener(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.listening {
		return nil
	}

	// Ensure scripts directory exists
	if err := a.ensureScriptsDir(); err != nil {
		log.Warn().Err(err).Msg("Failed to ensure scripts directory exists")
	}

	a.listening = true
	a.shutdownChan = make(chan struct{})

	// Start event polling
	go a.pollEvents(ctx)

	log.Info().Msg("Pixie event listener started")
	return nil
}

// StopEventListener stops the event listener
func (a *PixieAgent) StopEventListener() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.listening {
		return nil
	}

	close(a.shutdownChan)
	a.listening = false
	log.Info().Msg("Pixie event listener stopped")
	return nil
}

// EventChannel returns the channel for receiving security events
func (a *PixieAgent) EventChannel() <-chan ebpf.SecurityEvent {
	return a.eventChan
}

// IsListening returns whether the event listener is active
func (a *PixieAgent) IsListening() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.listening
}

// LoadConfig loads the Pixie configuration
func (a *PixieAgent) LoadConfig() error {
	return nil
}

// UpdateConfig updates the Pixie configuration
func (a *PixieAgent) UpdateConfig(config ebpf.AgentConfig) error {
	return nil
}

// GetConfigPath returns the configuration file path
func (a *PixieAgent) GetConfigPath() string {
	return a.configPath
}

// GetRules returns the list of PxL script files
func (a *PixieAgent) GetRules() ([]ebpf.RuleFile, error) {
	files, err := a.listScriptFiles()
	if err != nil {
		return nil, err
	}

	rules := make([]ebpf.RuleFile, 0, len(files))
	for _, filename := range files {
		content, err := a.readScriptFile(filename)
		if err != nil {
			log.Warn().Err(err).Msgf("Error reading script file: %s", filename)
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

// UpdateRules updates the PxL script files
func (a *PixieAgent) UpdateRules(rules []ebpf.RuleFile) error {
	existingFiles, err := a.listScriptFiles()
	if err != nil {
		log.Warn().Err(err).Msg("Error listing existing script files")
	}

	newFilesMap := make(map[string]bool)

	for _, rule := range rules {
		if rule.Content == "" {
			continue
		}

		cleanContent := strings.TrimSpace(rule.Content)
		decodedContent, err := base64.StdEncoding.DecodeString(cleanContent)
		if err != nil {
			log.Error().Err(err).Msgf("Error decoding script file: %s", rule.Filename)
			continue
		}

		md5sum := md5.Sum(decodedContent)
		if fmt.Sprintf("%x", md5sum) != rule.MD5Sum {
			log.Error().Msgf("MD5 mismatch for script file: %s", rule.Filename)
			continue
		}

		if err := a.writeScriptFile(rule.Filename, string(decodedContent)); err != nil {
			log.Error().Err(err).Msgf("Error writing script file: %s", rule.Filename)
			continue
		}

		newFilesMap[rule.Filename] = true
	}

	// Delete stale files
	for _, existingFile := range existingFiles {
		if !newFilesMap[existingFile] {
			log.Info().Msgf("Deleting stale script file: %s", existingFile)
			if err := a.deleteScriptFile(existingFile); err != nil {
				log.Warn().Err(err).Msgf("Error deleting script file: %s", existingFile)
			}
		}
	}

	return nil
}

// GetRulesDir returns the scripts directory path
func (a *PixieAgent) GetRulesDir() string {
	return a.scriptsDir
}

// ServiceName returns the systemd service name
func (a *PixieAgent) ServiceName() string {
	return a.serviceName
}

// GetServiceStatus returns the current service status
func (a *PixieAgent) GetServiceStatus() (ebpf.ServiceStatus, error) {
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
func (a *PixieAgent) StartService() error {
	returnCode := systemd.StartService(a.serviceName)
	if returnCode != 0 {
		return fmt.Errorf("failed to start service, return code: %d", returnCode)
	}
	return nil
}

// StopService stops the systemd service
func (a *PixieAgent) StopService() error {
	returnCode := systemd.StopService(a.serviceName)
	if returnCode != 0 {
		return fmt.Errorf("failed to stop service, return code: %d", returnCode)
	}
	return nil
}

// RestartService restarts the systemd service
func (a *PixieAgent) RestartService() error {
	returnCode := systemd.RestartService(a.serviceName)
	if returnCode != 0 {
		return fmt.Errorf("failed to restart service, return code: %d", returnCode)
	}
	return nil
}

// GetServiceLogs returns recent service logs
func (a *PixieAgent) GetServiceLogs(lines int) (string, error) {
	return systemd.GetServiceLogs(a.serviceName, lines)
}

// IsInstalled returns whether Pixie is installed
func (a *PixieAgent) IsInstalled() bool {
	return a.binaryPath != ""
}

// GetBinaryPath returns the path to the Pixie binary
func (a *PixieAgent) GetBinaryPath() string {
	return a.binaryPath
}

// pollEvents polls Pixie's streaming API for events
func (a *PixieAgent) pollEvents(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.shutdownChan:
			return
		case <-ticker.C:
			a.fetchAndProcessEvents(ctx)
		}
	}
}

func (a *PixieAgent) fetchAndProcessEvents(ctx context.Context) {
	// Try to connect to Pixie's streaming endpoint
	req, err := http.NewRequestWithContext(ctx, "GET", a.apiEndpoint+"/api/v1/stream", nil)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to create request for Pixie API")
		return
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to connect to Pixie API")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Debug().Msgf("Pixie API returned status: %d", resp.StatusCode)
		return
	}

	// Read line-delimited JSON events
	reader := bufio.NewReader(resp.Body)
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.shutdownChan:
			return
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return
			}
			log.Debug().Err(err).Msg("Error reading from Pixie stream")
			return
		}

		var event PixieEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			log.Debug().Err(err).Msg("Failed to parse Pixie event")
			continue
		}

		secEvent := a.convertToSecurityEvent(event)
		if secEvent.UUID != "" {
			select {
			case a.eventChan <- secEvent:
				log.Debug().Msgf("Received Pixie event: %s", secEvent.Rule)
			default:
				log.Warn().Msg("Event channel full, dropping event")
			}
		}
	}
}

// convertToSecurityEvent converts a Pixie event to unified SecurityEvent
func (a *PixieAgent) convertToSecurityEvent(event PixieEvent) ebpf.SecurityEvent {
	secEvent := ebpf.SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: ebpf.AgentTypePixie,
		Timestamp: time.Now(),
		RawFields: event.Data,
	}

	if event.Time != "" {
		if t, err := time.Parse(time.RFC3339Nano, event.Time); err == nil {
			secEvent.Timestamp = t
		}
	}

	// Determine event type from table name
	switch event.Table {
	case "http_events", "http_request_trace":
		secEvent.Rule = "HTTP Request"
		secEvent.Source = "http"
		secEvent.Priority = ebpf.PriorityInformational
		a.fillHTTPEventInfo(&secEvent, event)

	case "conn_stats", "network_conn":
		secEvent.Rule = "Network Connection"
		secEvent.Source = "network"
		secEvent.Priority = ebpf.PriorityInformational
		a.fillConnEventInfo(&secEvent, event)

	case "process_stats":
		secEvent.Rule = "Process Activity"
		secEvent.Source = "process"
		secEvent.Priority = ebpf.PriorityDebug
		a.fillProcessEventInfo(&secEvent, event)

	default:
		secEvent.Rule = event.Table
		secEvent.Source = "pixie"
		secEvent.Priority = ebpf.PriorityInformational
	}

	return secEvent
}

func (a *PixieAgent) fillHTTPEventInfo(event *ebpf.SecurityEvent, pixieEvent PixieEvent) {
	if pixieEvent.Data == nil {
		return
	}

	if method, ok := pixieEvent.Data["req_method"].(string); ok {
		if path, ok := pixieEvent.Data["req_path"].(string); ok {
			event.Output = fmt.Sprintf("HTTP %s %s", method, path)
		}
	}

	if remoteAddr, ok := pixieEvent.Data["remote_addr"].(string); ok {
		event.Network.DstIP = remoteAddr
	}
	if remotePort, ok := pixieEvent.Data["remote_port"].(float64); ok {
		event.Network.DstPort = int(remotePort)
	}
	if status, ok := pixieEvent.Data["resp_status"].(float64); ok {
		if status >= 400 {
			event.Priority = ebpf.PriorityWarning
		}
		if status >= 500 {
			event.Priority = ebpf.PriorityError
		}
	}
	if pod, ok := pixieEvent.Data["pod"].(string); ok {
		event.K8s.Pod = pod
	}
	if ns, ok := pixieEvent.Data["namespace"].(string); ok {
		event.K8s.Namespace = ns
	}
}

func (a *PixieAgent) fillConnEventInfo(event *ebpf.SecurityEvent, pixieEvent PixieEvent) {
	if pixieEvent.Data == nil {
		return
	}

	event.Network.Protocol = "tcp"
	if protocol, ok := pixieEvent.Data["protocol"].(string); ok {
		event.Network.Protocol = protocol
	}

	if localAddr, ok := pixieEvent.Data["local_addr"].(string); ok {
		event.Network.SrcIP = localAddr
	}
	if localPort, ok := pixieEvent.Data["local_port"].(float64); ok {
		event.Network.SrcPort = int(localPort)
	}
	if remoteAddr, ok := pixieEvent.Data["remote_addr"].(string); ok {
		event.Network.DstIP = remoteAddr
	}
	if remotePort, ok := pixieEvent.Data["remote_port"].(float64); ok {
		event.Network.DstPort = int(remotePort)
	}
	if bytesSent, ok := pixieEvent.Data["bytes_sent"].(float64); ok {
		event.Network.BytesSent = int64(bytesSent)
	}
	if bytesRecv, ok := pixieEvent.Data["bytes_recv"].(float64); ok {
		event.Network.BytesReceived = int64(bytesRecv)
	}

	event.Output = fmt.Sprintf("Connection: %s:%d -> %s:%d",
		event.Network.SrcIP, event.Network.SrcPort,
		event.Network.DstIP, event.Network.DstPort)

	if pod, ok := pixieEvent.Data["pod"].(string); ok {
		event.K8s.Pod = pod
	}
	if ns, ok := pixieEvent.Data["namespace"].(string); ok {
		event.K8s.Namespace = ns
	}
}

func (a *PixieAgent) fillProcessEventInfo(event *ebpf.SecurityEvent, pixieEvent PixieEvent) {
	if pixieEvent.Data == nil {
		return
	}

	if pid, ok := pixieEvent.Data["pid"].(float64); ok {
		event.Process.PID = int(pid)
	}
	if cmdline, ok := pixieEvent.Data["cmdline"].(string); ok {
		event.Process.Cmdline = cmdline
		event.Output = fmt.Sprintf("Process: %s", cmdline)
	}
	if binary, ok := pixieEvent.Data["binary"].(string); ok {
		event.Process.ExePath = binary
	}
	if pod, ok := pixieEvent.Data["pod"].(string); ok {
		event.K8s.Pod = pod
	}
	if container, ok := pixieEvent.Data["container"].(string); ok {
		event.Container.Name = container
	}
	if ns, ok := pixieEvent.Data["namespace"].(string); ok {
		event.K8s.Namespace = ns
	}
}

func (a *PixieAgent) ensureScriptsDir() error {
	if _, err := os.Stat(a.scriptsDir); os.IsNotExist(err) {
		return os.MkdirAll(a.scriptsDir, 0755)
	}
	return nil
}

func (a *PixieAgent) listScriptFiles() ([]string, error) {
	if err := a.ensureScriptsDir(); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(a.scriptsDir)
	if err != nil {
		return nil, err
	}

	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".pxl") {
			files = append(files, entry.Name())
		}
	}
	return files, nil
}

func (a *PixieAgent) readScriptFile(filename string) (string, error) {
	content, err := os.ReadFile(filepath.Join(a.scriptsDir, filename))
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func (a *PixieAgent) writeScriptFile(filename string, content string) error {
	if err := a.ensureScriptsDir(); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(a.scriptsDir, filename), []byte(content), 0644)
}

func (a *PixieAgent) deleteScriptFile(filename string) error {
	return os.Remove(filepath.Join(a.scriptsDir, filename))
}

// init registers the Pixie agent with the factory
func init() {
	ebpf.Register(ebpf.AgentTypePixie, func() (ebpf.EBPFAgent, error) {
		return NewPixieAgent()
	})
}

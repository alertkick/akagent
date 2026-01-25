package tetragon

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
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

var log = logger.Sublogger("tetragon-agent")

const (
	defaultGRPCSocket       = "/var/run/tetragon/tetragon.sock"
	defaultConfigPath       = "/etc/tetragon/tetragon.yaml"
	defaultRulesDir         = "/etc/tetragon/tetragon.tp.d/"
	defaultServiceName      = "tetragon.service"
	eventChannelBufferSize  = 1000
)

// TetragonAgent implements the EBPFAgent interface for Tetragon
type TetragonAgent struct {
	mu           sync.RWMutex
	eventChan    chan ebpf.SecurityEvent
	running      bool
	listening    bool
	grpcSocket   string
	configPath   string
	rulesDir     string
	serviceName  string
	binaryPath   string
	shutdownChan chan struct{}
	conn         net.Conn
}

// TetragonEvent represents an incoming Tetragon event
type TetragonEvent struct {
	ProcessExec    *ProcessExec    `json:"process_exec,omitempty"`
	ProcessExit    *ProcessExit    `json:"process_exit,omitempty"`
	ProcessKprobe  *ProcessKprobe  `json:"process_kprobe,omitempty"`
	ProcessTracepoint *ProcessTracepoint `json:"process_tracepoint,omitempty"`
	Time           string          `json:"time,omitempty"`
	NodeName       string          `json:"node_name,omitempty"`
}

// ProcessExec represents a process execution event
type ProcessExec struct {
	Process Process `json:"process"`
	Parent  Process `json:"parent,omitempty"`
}

// ProcessExit represents a process exit event
type ProcessExit struct {
	Process Process `json:"process"`
	Parent  Process `json:"parent,omitempty"`
	Signal  string  `json:"signal,omitempty"`
	Status  int     `json:"status,omitempty"`
}

// ProcessKprobe represents a kprobe event
type ProcessKprobe struct {
	Process      Process            `json:"process"`
	Parent       Process            `json:"parent,omitempty"`
	FunctionName string             `json:"function_name,omitempty"`
	Args         []KprobeArg        `json:"args,omitempty"`
	Return       *KprobeArg         `json:"return,omitempty"`
	Action       string             `json:"action,omitempty"`
	PolicyName   string             `json:"policy_name,omitempty"`
}

// ProcessTracepoint represents a tracepoint event
type ProcessTracepoint struct {
	Process    Process     `json:"process"`
	Parent     Process     `json:"parent,omitempty"`
	Subsys     string      `json:"subsys,omitempty"`
	Event      string      `json:"event,omitempty"`
	Args       []KprobeArg `json:"args,omitempty"`
	PolicyName string      `json:"policy_name,omitempty"`
}

// Process represents process information in Tetragon events
type Process struct {
	ExecID       string    `json:"exec_id,omitempty"`
	PID          int       `json:"pid,omitempty"`
	UID          int       `json:"uid,omitempty"`
	Cwd          string    `json:"cwd,omitempty"`
	Binary       string    `json:"binary,omitempty"`
	Arguments    string    `json:"arguments,omitempty"`
	Flags        string    `json:"flags,omitempty"`
	StartTime    time.Time `json:"start_time,omitempty"`
	AUID         int       `json:"auid,omitempty"`
	Pod          *Pod      `json:"pod,omitempty"`
	Docker       string    `json:"docker,omitempty"`
	ParentExecID string    `json:"parent_exec_id,omitempty"`
	RefCnt       int       `json:"refcnt,omitempty"`
	Cap          *Cap      `json:"cap,omitempty"`
	NS           *NS       `json:"ns,omitempty"`
	TID          int       `json:"tid,omitempty"`
}

// Pod represents Kubernetes pod information
type Pod struct {
	Namespace string            `json:"namespace,omitempty"`
	Name      string            `json:"name,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	Container *Container        `json:"container,omitempty"`
}

// Container represents container information
type Container struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Image      *Image `json:"image,omitempty"`
	StartTime  time.Time `json:"start_time,omitempty"`
	PID        int    `json:"pid,omitempty"`
}

// Image represents container image information
type Image struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// Cap represents capabilities
type Cap struct {
	Permitted   string `json:"permitted,omitempty"`
	Effective   string `json:"effective,omitempty"`
	Inheritable string `json:"inheritable,omitempty"`
}

// NS represents namespaces
type NS struct {
	Level int    `json:"level,omitempty"`
	Inum  uint32 `json:"inum,omitempty"`
}

// KprobeArg represents a kprobe argument
type KprobeArg struct {
	StringArg    string `json:"string_arg,omitempty"`
	IntArg       int64  `json:"int_arg,omitempty"`
	SizeArg      uint64 `json:"size_arg,omitempty"`
	BytesArg     string `json:"bytes_arg,omitempty"`
	SockArg      *Sock  `json:"sock_arg,omitempty"`
	SkbArg       *Skb   `json:"skb_arg,omitempty"`
	FileArg      *File  `json:"file_arg,omitempty"`
	TruncatedBytesArg *TruncatedBytes `json:"truncated_bytes_arg,omitempty"`
}

// Sock represents socket information
type Sock struct {
	Family   string `json:"family,omitempty"`
	Type     string `json:"type,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	SAddr    string `json:"saddr,omitempty"`
	DAddr    string `json:"daddr,omitempty"`
	Sport    uint32 `json:"sport,omitempty"`
	Dport    uint32 `json:"dport,omitempty"`
}

// Skb represents socket buffer information
type Skb struct {
	Hash        uint32 `json:"hash,omitempty"`
	Len         uint32 `json:"len,omitempty"`
	Priority    uint32 `json:"priority,omitempty"`
	Mark        uint32 `json:"mark,omitempty"`
	Saddr       string `json:"saddr,omitempty"`
	Daddr       string `json:"daddr,omitempty"`
	Sport       uint32 `json:"sport,omitempty"`
	Dport       uint32 `json:"dport,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	SecPathLen  uint32 `json:"sec_path_len,omitempty"`
	SecPathOlen uint32 `json:"sec_path_olen,omitempty"`
}

// File represents file information
type File struct {
	Mount string `json:"mount,omitempty"`
	Path  string `json:"path,omitempty"`
	Flags string `json:"flags,omitempty"`
}

// TruncatedBytes represents truncated byte data
type TruncatedBytes struct {
	BytesArg string `json:"bytes_arg,omitempty"`
	OrigSize uint64 `json:"orig_size,omitempty"`
}

// NewTetragonAgent creates a new Tetragon agent instance
func NewTetragonAgent() (*TetragonAgent, error) {
	detection := ebpf.DetectAgent(ebpf.AgentTypeTetragon)

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

	agent := &TetragonAgent{
		eventChan:    make(chan ebpf.SecurityEvent, eventChannelBufferSize),
		grpcSocket:   defaultGRPCSocket,
		configPath:   configPath,
		rulesDir:     rulesDir,
		serviceName:  serviceName,
		binaryPath:   detection.BinaryPath,
		shutdownChan: make(chan struct{}),
	}

	return agent, nil
}

// Type returns the agent type
func (a *TetragonAgent) Type() ebpf.AgentType {
	return ebpf.AgentTypeTetragon
}

// Name returns the human-readable name
func (a *TetragonAgent) Name() string {
	return "Tetragon"
}

// Version returns the installed version
func (a *TetragonAgent) Version() (string, error) {
	if !a.IsInstalled() {
		return "", fmt.Errorf("tetragon is not installed")
	}

	detection := ebpf.DetectAgent(ebpf.AgentTypeTetragon)
	if detection.Version != "" {
		return detection.Version, nil
	}
	return "unknown", nil
}

// Start starts the Tetragon agent
func (a *TetragonAgent) Start(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.running {
		return nil
	}

	a.running = true
	log.Info().Msg("Tetragon agent started")
	return nil
}

// Stop stops the Tetragon agent
func (a *TetragonAgent) Stop(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.running {
		return nil
	}

	a.running = false
	log.Info().Msg("Tetragon agent stopped")
	return nil
}

// IsRunning returns whether the agent is running
func (a *TetragonAgent) IsRunning() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.running
}

// StartEventListener starts listening for Tetragon events via Unix socket
func (a *TetragonAgent) StartEventListener(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.listening {
		return nil
	}

	// Ensure rules directory exists
	if err := a.ensureRulesDir(); err != nil {
		log.Warn().Err(err).Msg("Failed to ensure rules directory exists")
	}

	// Connect to Tetragon socket
	conn, err := net.Dial("unix", a.grpcSocket)
	if err != nil {
		// Socket may not exist if Tetragon isn't running with event export
		log.Warn().Err(err).Msg("Failed to connect to Tetragon socket - events will not be received")
		// Don't fail - the agent can still manage service/rules
	} else {
		a.conn = conn
	}

	a.listening = true
	a.shutdownChan = make(chan struct{})

	if a.conn != nil {
		go a.readEvents(ctx)
	}

	log.Info().Msg("Tetragon event listener started")
	return nil
}

// StopEventListener stops the event listener
func (a *TetragonAgent) StopEventListener() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.listening {
		return nil
	}

	close(a.shutdownChan)

	if a.conn != nil {
		a.conn.Close()
		a.conn = nil
	}

	a.listening = false
	log.Info().Msg("Tetragon event listener stopped")
	return nil
}

// EventChannel returns the channel for receiving security events
func (a *TetragonAgent) EventChannel() <-chan ebpf.SecurityEvent {
	return a.eventChan
}

// IsListening returns whether the event listener is active
func (a *TetragonAgent) IsListening() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.listening
}

// LoadConfig loads the Tetragon configuration
func (a *TetragonAgent) LoadConfig() error {
	return nil
}

// UpdateConfig updates the Tetragon configuration
func (a *TetragonAgent) UpdateConfig(config ebpf.AgentConfig) error {
	return nil
}

// GetConfigPath returns the configuration file path
func (a *TetragonAgent) GetConfigPath() string {
	return a.configPath
}

// GetRules returns the list of tracing policy files
func (a *TetragonAgent) GetRules() ([]ebpf.RuleFile, error) {
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

// UpdateRules updates the tracing policy files
func (a *TetragonAgent) UpdateRules(rules []ebpf.RuleFile) error {
	existingFiles, err := a.listRulesFiles()
	if err != nil {
		log.Warn().Err(err).Msg("Error listing existing rules files")
	}

	newFilesMap := make(map[string]bool)

	for _, rule := range rules {
		if rule.Content == "" {
			continue
		}

		cleanContent := strings.TrimSpace(rule.Content)
		decodedContent, err := base64.StdEncoding.DecodeString(cleanContent)
		if err != nil {
			log.Error().Err(err).Msgf("Error decoding rule file: %s", rule.Filename)
			continue
		}

		md5sum := md5.Sum(decodedContent)
		if fmt.Sprintf("%x", md5sum) != rule.MD5Sum {
			log.Error().Msgf("MD5 mismatch for rule file: %s", rule.Filename)
			continue
		}

		if err := a.writeRuleFile(rule.Filename, string(decodedContent)); err != nil {
			log.Error().Err(err).Msgf("Error writing rule file: %s", rule.Filename)
			continue
		}

		newFilesMap[rule.Filename] = true
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
	log.Info().Msg("Rules updated, restarting Tetragon service")
	return a.RestartService()
}

// GetRulesDir returns the rules directory path
func (a *TetragonAgent) GetRulesDir() string {
	return a.rulesDir
}

// ServiceName returns the systemd service name
func (a *TetragonAgent) ServiceName() string {
	return a.serviceName
}

// GetServiceStatus returns the current service status
func (a *TetragonAgent) GetServiceStatus() (ebpf.ServiceStatus, error) {
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
func (a *TetragonAgent) StartService() error {
	returnCode := systemd.StartService(a.serviceName)
	if returnCode != 0 {
		return fmt.Errorf("failed to start service, return code: %d", returnCode)
	}
	return nil
}

// StopService stops the systemd service
func (a *TetragonAgent) StopService() error {
	returnCode := systemd.StopService(a.serviceName)
	if returnCode != 0 {
		return fmt.Errorf("failed to stop service, return code: %d", returnCode)
	}
	return nil
}

// RestartService restarts the systemd service
func (a *TetragonAgent) RestartService() error {
	returnCode := systemd.RestartService(a.serviceName)
	if returnCode != 0 {
		return fmt.Errorf("failed to restart service, return code: %d", returnCode)
	}
	return nil
}

// GetServiceLogs returns recent service logs
func (a *TetragonAgent) GetServiceLogs(lines int) (string, error) {
	return systemd.GetServiceLogs(a.serviceName, lines)
}

// IsInstalled returns whether Tetragon is installed
func (a *TetragonAgent) IsInstalled() bool {
	return a.binaryPath != ""
}

// GetBinaryPath returns the path to the Tetragon binary
func (a *TetragonAgent) GetBinaryPath() string {
	return a.binaryPath
}

// readEvents reads events from the Tetragon socket
func (a *TetragonAgent) readEvents(ctx context.Context) {
	reader := bufio.NewReader(a.conn)

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.shutdownChan:
			return
		default:
			// Set read deadline to allow periodic shutdown checks
			a.conn.SetReadDeadline(time.Now().Add(1 * time.Second))

			line, err := reader.ReadString('\n')
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // Timeout is expected, continue
				}
				if err == io.EOF {
					log.Info().Msg("Tetragon socket closed")
					return
				}
				log.Warn().Err(err).Msg("Error reading from Tetragon socket")
				continue
			}

			var event TetragonEvent
			if err := json.Unmarshal([]byte(line), &event); err != nil {
				log.Debug().Err(err).Msg("Failed to parse Tetragon event")
				continue
			}

			secEvent := a.convertToSecurityEvent(event)
			if secEvent.UUID != "" {
				select {
				case a.eventChan <- secEvent:
					log.Debug().Msgf("Received Tetragon event: %s", secEvent.Rule)
				default:
					log.Warn().Msg("Event channel full, dropping event")
				}
			}
		}
	}
}

// convertToSecurityEvent converts a Tetragon event to unified SecurityEvent
func (a *TetragonAgent) convertToSecurityEvent(event TetragonEvent) ebpf.SecurityEvent {
	secEvent := ebpf.SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: ebpf.AgentTypeTetragon,
		Hostname:  event.NodeName,
	}

	if event.Time != "" {
		if t, err := time.Parse(time.RFC3339Nano, event.Time); err == nil {
			secEvent.Timestamp = t
		} else {
			secEvent.Timestamp = time.Now()
		}
	} else {
		secEvent.Timestamp = time.Now()
	}

	// Process execution events
	if event.ProcessExec != nil {
		secEvent.Rule = "Process Execution"
		secEvent.Source = "exec"
		secEvent.Priority = ebpf.PriorityInformational
		secEvent.Output = fmt.Sprintf("Process executed: %s %s", event.ProcessExec.Process.Binary, event.ProcessExec.Process.Arguments)
		a.fillProcessInfo(&secEvent, event.ProcessExec.Process)
		if event.ProcessExec.Parent.Binary != "" {
			secEvent.Process.ParentName = event.ProcessExec.Parent.Binary
		}
	}

	// Process exit events
	if event.ProcessExit != nil {
		secEvent.Rule = "Process Exit"
		secEvent.Source = "exit"
		secEvent.Priority = ebpf.PriorityDebug
		secEvent.Output = fmt.Sprintf("Process exited: %s (status: %d)", event.ProcessExit.Process.Binary, event.ProcessExit.Status)
		a.fillProcessInfo(&secEvent, event.ProcessExit.Process)
	}

	// Kprobe events
	if event.ProcessKprobe != nil {
		secEvent.Rule = event.ProcessKprobe.PolicyName
		if secEvent.Rule == "" {
			secEvent.Rule = event.ProcessKprobe.FunctionName
		}
		secEvent.Source = "kprobe"
		secEvent.Priority = a.mapActionToPriority(event.ProcessKprobe.Action)
		secEvent.Output = fmt.Sprintf("Kprobe triggered: %s by %s", event.ProcessKprobe.FunctionName, event.ProcessKprobe.Process.Binary)
		a.fillProcessInfo(&secEvent, event.ProcessKprobe.Process)
		a.fillKprobeArgs(&secEvent, event.ProcessKprobe.Args)
	}

	// Tracepoint events
	if event.ProcessTracepoint != nil {
		secEvent.Rule = event.ProcessTracepoint.PolicyName
		if secEvent.Rule == "" {
			secEvent.Rule = fmt.Sprintf("%s:%s", event.ProcessTracepoint.Subsys, event.ProcessTracepoint.Event)
		}
		secEvent.Source = "tracepoint"
		secEvent.Priority = ebpf.PriorityNotice
		secEvent.Output = fmt.Sprintf("Tracepoint: %s:%s by %s", event.ProcessTracepoint.Subsys, event.ProcessTracepoint.Event, event.ProcessTracepoint.Process.Binary)
		a.fillProcessInfo(&secEvent, event.ProcessTracepoint.Process)
	}

	return secEvent
}

func (a *TetragonAgent) fillProcessInfo(event *ebpf.SecurityEvent, proc Process) {
	event.Process.PID = proc.PID
	event.Process.UID = proc.UID
	event.Process.ExePath = proc.Binary
	event.Process.Cmdline = proc.Arguments
	event.Process.Cwd = proc.Cwd
	event.Process.LoginUID = proc.AUID

	if proc.Pod != nil {
		event.K8s.Namespace = proc.Pod.Namespace
		event.K8s.Pod = proc.Pod.Name
		event.K8s.Labels = proc.Pod.Labels

		if proc.Pod.Container != nil {
			event.Container.ID = proc.Pod.Container.ID
			event.Container.Name = proc.Pod.Container.Name
			if proc.Pod.Container.Image != nil {
				event.Container.Image = proc.Pod.Container.Image.Name
			}
		}
	}

	if proc.Docker != "" {
		event.Container.ID = proc.Docker
	}
}

func (a *TetragonAgent) fillKprobeArgs(event *ebpf.SecurityEvent, args []KprobeArg) {
	for _, arg := range args {
		if arg.FileArg != nil {
			event.File.Path = arg.FileArg.Path
		}
		if arg.SockArg != nil {
			event.Network.Protocol = arg.SockArg.Protocol
			event.Network.SrcIP = arg.SockArg.SAddr
			event.Network.SrcPort = int(arg.SockArg.Sport)
			event.Network.DstIP = arg.SockArg.DAddr
			event.Network.DstPort = int(arg.SockArg.Dport)
		}
		if arg.SkbArg != nil {
			event.Network.Protocol = arg.SkbArg.Protocol
			event.Network.SrcIP = arg.SkbArg.Saddr
			event.Network.SrcPort = int(arg.SkbArg.Sport)
			event.Network.DstIP = arg.SkbArg.Daddr
			event.Network.DstPort = int(arg.SkbArg.Dport)
		}
	}
}

func (a *TetragonAgent) mapActionToPriority(action string) ebpf.PriorityLevel {
	switch strings.ToLower(action) {
	case "sigkill", "override":
		return ebpf.PriorityCritical
	case "signal":
		return ebpf.PriorityWarning
	case "geturl", "dnsLookup":
		return ebpf.PriorityNotice
	default:
		return ebpf.PriorityInformational
	}
}

func (a *TetragonAgent) ensureRulesDir() error {
	if _, err := os.Stat(a.rulesDir); os.IsNotExist(err) {
		return os.MkdirAll(a.rulesDir, 0755)
	}
	return nil
}

func (a *TetragonAgent) listRulesFiles() ([]string, error) {
	if err := a.ensureRulesDir(); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(a.rulesDir)
	if err != nil {
		return nil, err
	}

	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && (strings.HasSuffix(entry.Name(), ".yaml") || strings.HasSuffix(entry.Name(), ".yml")) {
			files = append(files, entry.Name())
		}
	}
	return files, nil
}

func (a *TetragonAgent) readRuleFile(filename string) (string, error) {
	content, err := os.ReadFile(filepath.Join(a.rulesDir, filename))
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func (a *TetragonAgent) writeRuleFile(filename string, content string) error {
	if err := a.ensureRulesDir(); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(a.rulesDir, filename), []byte(content), 0644)
}

func (a *TetragonAgent) deleteRuleFile(filename string) error {
	return os.Remove(filepath.Join(a.rulesDir, filename))
}

// init registers the Tetragon agent with the factory
func init() {
	ebpf.Register(ebpf.AgentTypeTetragon, func() (ebpf.EBPFAgent, error) {
		return NewTetragonAgent()
	})
}

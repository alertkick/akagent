package auth

import (
	"apagent/checks"
	"apagent/ebpf"
	"apagent/internal/api"
	"apagent/logger"
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	log = logger.Sublogger("host.monitor_auth")
)

func init() {
	checks.Add("host.monitor_auth", func() api.Check {
		return &AuthCheck{
			UUID:      "host.monitor_auth",
			Name:      "host.monitor_auth",
			Label:     "host.monitor_auth",
			CheckType: "host.monitor_auth",
			interval:  30, // Check every 30 seconds
		}
	})
	checks.AddConfig("host.monitor_auth")
}

// AuthEvent represents a detected authentication event
type AuthEvent struct {
	Timestamp   time.Time         `json:"timestamp"`
	EventType   string            `json:"event_type"`
	Priority    string            `json:"priority"`
	Service     string            `json:"service"`
	Username    string            `json:"username,omitempty"`
	SourceIP    string            `json:"source_ip,omitempty"`
	SourcePort  string            `json:"source_port,omitempty"`
	Description string            `json:"description"`
	RawLine     string            `json:"raw_line,omitempty"`
	RawFields   map[string]string `json:"raw_fields,omitempty"`
}

// AuthCheck monitors authentication logs for failures
type AuthCheck struct {
	UUID        string
	Name        string
	Label       string
	CheckType   string
	resultsChan chan api.CheckMetricParams
	// goroutine management
	lock        sync.Mutex
	debug       bool
	interval    int
	lastOffset  int64
	logFile     string
	eventQueue  chan ebpf.SecurityEvent
}

// Compiled regex patterns for auth log parsing
var (
	// SSH authentication failures
	sshdFailedPasswordRe = regexp.MustCompile(`sshd\[\d+\]: Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)`)
	sshdInvalidUserRe    = regexp.MustCompile(`sshd\[\d+\]: Invalid user (\S+) from (\S+) port (\d+)`)
	sshdAuthFailureRe    = regexp.MustCompile(`sshd\[\d+\]: pam_unix\(sshd:auth\): authentication failure.*user=(\S+)`)
	sshdDisconnectRe     = regexp.MustCompile(`sshd\[\d+\]: Disconnecting authenticating user (\S+) (\S+) port (\d+)`)
	sshdMaxRetriesRe     = regexp.MustCompile(`sshd\[\d+\]: error: maximum authentication attempts exceeded for (?:invalid user )?(\S+) from (\S+) port (\d+)`)

	// Sudo failures
	sudoAuthFailureRe = regexp.MustCompile(`sudo:\s+(\S+)\s+: authentication failure.*TTY=(\S+)`)
	sudoIncorrectRe   = regexp.MustCompile(`sudo:\s+pam_unix\(sudo:auth\): authentication failure.*user=(\S+)`)
	sudo3FailuresRe   = regexp.MustCompile(`sudo:\s+(\S+)\s+: 3 incorrect password attempts`)

	// PAM failures (generic)
	pamAuthFailureRe = regexp.MustCompile(`pam_unix\(([^)]+)\): authentication failure.*user=(\S+)`)

	// su failures
	suAuthFailureRe = regexp.MustCompile(`su\[\d+\]: pam_unix\(su[^)]*\): authentication failure.*user=(\S+)`)
	suFailedRe      = regexp.MustCompile(`su\[\d+\]: FAILED SU.*from (\S+) to (\S+)`)

	// Timestamp parsing - syslog format: "Jan 26 14:30:45"
	syslogTimestampRe = regexp.MustCompile(`^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})`)
)

func (c *AuthCheck) Init(resultsQueue chan api.CheckMetricParams, agentCheck api.AgentCheck) error {
	c.resultsChan = resultsQueue
	c.Label = agentCheck.Label
	if agentCheck.Period != 0 {
		c.interval = agentCheck.Period
	}
	c.logFile = c.detectAuthLogPath()
	c.eventQueue = make(chan ebpf.SecurityEvent, 100)
	return nil
}

func (c *AuthCheck) Start(stopCtx context.Context, debug bool) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	log.Debug().Msgf("auth.Start - %s monitor started with %d seconds interval, log file: %s", c.Name, c.interval, c.logFile)

	// Initialize offset to end of file to only process new entries
	if err := c.initializeOffset(); err != nil {
		log.Warn().Err(err).Msg("auth.Start - failed to initialize offset, will start from beginning")
	}

	ticker := time.NewTicker(time.Duration(c.interval) * time.Second)
	defer ticker.Stop()

	for {
		if err := c.RunAndSend(); err != nil {
			log.Info().Msgf("auth.Start - can not collect and send metrics: %s\n", err.Error())
		}
		select {
		case <-stopCtx.Done():
			log.Info().Msgf("auth.Start - %s monitor stopped", c.Name)
			return nil
		case <-ticker.C:
			continue
		}
	}
}

func (c *AuthCheck) Stop() error {
	return nil
}

func (c *AuthCheck) RunAndSend() error {
	log.Debug().Msg("auth.RunAndSend - checking for new auth events")

	events, err := c.parseNewLogEntries()
	if err != nil {
		log.Err(err).Msg("auth.RunAndSend - error parsing log entries")
		return err
	}

	// Process each detected event
	for _, event := range events {
		c.sendSecurityEvent(event)
	}

	// Send summary metrics
	c.sendAuthMetrics(len(events))

	return nil
}

// detectAuthLogPath determines the auth log path based on the OS
func (c *AuthCheck) detectAuthLogPath() string {
	// Debian/Ubuntu
	if _, err := os.Stat("/var/log/auth.log"); err == nil {
		return "/var/log/auth.log"
	}
	// RHEL/CentOS/Fedora
	if _, err := os.Stat("/var/log/secure"); err == nil {
		return "/var/log/secure"
	}
	// Fallback to auth.log
	return "/var/log/auth.log"
}

// initializeOffset sets the offset to the end of the file
func (c *AuthCheck) initializeOffset() error {
	info, err := os.Stat(c.logFile)
	if err != nil {
		return err
	}
	c.lastOffset = info.Size()
	return nil
}

// parseNewLogEntries reads new entries from the auth log since last check
func (c *AuthCheck) parseNewLogEntries() ([]AuthEvent, error) {
	file, err := os.Open(c.logFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open auth log: %w", err)
	}
	defer file.Close()

	// Check if file was rotated (current size smaller than last offset)
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat auth log: %w", err)
	}
	if info.Size() < c.lastOffset {
		// Log rotated, start from beginning
		log.Info().Msg("auth.parseNewLogEntries - log file rotated, starting from beginning")
		c.lastOffset = 0
	}

	// Seek to last position
	_, err = file.Seek(c.lastOffset, io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("failed to seek in auth log: %w", err)
	}

	var events []AuthEvent
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if event := c.parseLine(line); event != nil {
			events = append(events, *event)
		}
	}

	// Update offset
	newOffset, _ := file.Seek(0, io.SeekCurrent)
	c.lastOffset = newOffset

	if len(events) > 0 {
		log.Info().Msgf("auth.parseNewLogEntries - found %d auth events", len(events))
	}

	return events, scanner.Err()
}

// parseLine parses a single log line and returns an AuthEvent if it matches
func (c *AuthCheck) parseLine(line string) *AuthEvent {
	// Skip empty lines
	if strings.TrimSpace(line) == "" {
		return nil
	}

	// Extract timestamp
	timestamp := c.parseTimestamp(line)

	// Try each pattern
	if event := c.matchSSHDFailedPassword(line, timestamp); event != nil {
		return event
	}
	if event := c.matchSSHDInvalidUser(line, timestamp); event != nil {
		return event
	}
	if event := c.matchSSHDMaxRetries(line, timestamp); event != nil {
		return event
	}
	if event := c.matchSudoFailure(line, timestamp); event != nil {
		return event
	}
	if event := c.matchSuFailure(line, timestamp); event != nil {
		return event
	}
	if event := c.matchPAMFailure(line, timestamp); event != nil {
		return event
	}

	return nil
}

func (c *AuthCheck) parseTimestamp(line string) time.Time {
	match := syslogTimestampRe.FindStringSubmatch(line)
	if len(match) > 1 {
		// Parse syslog timestamp (assumes current year)
		timestampStr := match[1]
		currentYear := time.Now().Year()
		t, err := time.Parse("2006 Jan 2 15:04:05", fmt.Sprintf("%d %s", currentYear, timestampStr))
		if err == nil {
			return t
		}
	}
	return time.Now()
}

func (c *AuthCheck) matchSSHDFailedPassword(line string, timestamp time.Time) *AuthEvent {
	match := sshdFailedPasswordRe.FindStringSubmatch(line)
	if len(match) > 3 {
		return &AuthEvent{
			Timestamp:   timestamp,
			EventType:   "auth_failure_ssh",
			Priority:    "Warning",
			Service:     "sshd",
			Username:    match[1],
			SourceIP:    match[2],
			SourcePort:  match[3],
			Description: fmt.Sprintf("Failed SSH login attempt for user '%s' from %s:%s", match[1], match[2], match[3]),
			RawLine:     line,
			RawFields: map[string]string{
				"username":    match[1],
				"source_ip":   match[2],
				"source_port": match[3],
				"service":     "sshd",
			},
		}
	}
	return nil
}

func (c *AuthCheck) matchSSHDInvalidUser(line string, timestamp time.Time) *AuthEvent {
	match := sshdInvalidUserRe.FindStringSubmatch(line)
	if len(match) > 3 {
		return &AuthEvent{
			Timestamp:   timestamp,
			EventType:   "auth_failure_ssh_invalid_user",
			Priority:    "Warning",
			Service:     "sshd",
			Username:    match[1],
			SourceIP:    match[2],
			SourcePort:  match[3],
			Description: fmt.Sprintf("SSH login attempt with invalid user '%s' from %s:%s", match[1], match[2], match[3]),
			RawLine:     line,
			RawFields: map[string]string{
				"username":    match[1],
				"source_ip":   match[2],
				"source_port": match[3],
				"service":     "sshd",
			},
		}
	}
	return nil
}

func (c *AuthCheck) matchSSHDMaxRetries(line string, timestamp time.Time) *AuthEvent {
	match := sshdMaxRetriesRe.FindStringSubmatch(line)
	if len(match) > 3 {
		return &AuthEvent{
			Timestamp:   timestamp,
			EventType:   "auth_failure_ssh_max_retries",
			Priority:    "High",
			Service:     "sshd",
			Username:    match[1],
			SourceIP:    match[2],
			SourcePort:  match[3],
			Description: fmt.Sprintf("Maximum SSH authentication attempts exceeded for user '%s' from %s:%s", match[1], match[2], match[3]),
			RawLine:     line,
			RawFields: map[string]string{
				"username":    match[1],
				"source_ip":   match[2],
				"source_port": match[3],
				"service":     "sshd",
			},
		}
	}
	return nil
}

func (c *AuthCheck) matchSudoFailure(line string, timestamp time.Time) *AuthEvent {
	// Check for 3 incorrect password attempts first (higher priority)
	match := sudo3FailuresRe.FindStringSubmatch(line)
	if len(match) > 1 {
		return &AuthEvent{
			Timestamp:   timestamp,
			EventType:   "auth_failure_sudo_repeated",
			Priority:    "High",
			Service:     "sudo",
			Username:    match[1],
			Description: fmt.Sprintf("3 incorrect sudo password attempts by user '%s'", match[1]),
			RawLine:     line,
			RawFields: map[string]string{
				"username": match[1],
				"service":  "sudo",
			},
		}
	}

	// Check for regular sudo auth failure
	match = sudoAuthFailureRe.FindStringSubmatch(line)
	if len(match) > 2 {
		return &AuthEvent{
			Timestamp:   timestamp,
			EventType:   "auth_failure_sudo",
			Priority:    "Warning",
			Service:     "sudo",
			Username:    match[1],
			Description: fmt.Sprintf("Sudo authentication failure for user '%s' on TTY %s", match[1], match[2]),
			RawLine:     line,
			RawFields: map[string]string{
				"username": match[1],
				"tty":      match[2],
				"service":  "sudo",
			},
		}
	}

	// PAM sudo failure
	match = sudoIncorrectRe.FindStringSubmatch(line)
	if len(match) > 1 {
		return &AuthEvent{
			Timestamp:   timestamp,
			EventType:   "auth_failure_sudo",
			Priority:    "Warning",
			Service:     "sudo",
			Username:    match[1],
			Description: fmt.Sprintf("Sudo PAM authentication failure for user '%s'", match[1]),
			RawLine:     line,
			RawFields: map[string]string{
				"username": match[1],
				"service":  "sudo",
			},
		}
	}

	return nil
}

func (c *AuthCheck) matchSuFailure(line string, timestamp time.Time) *AuthEvent {
	match := suFailedRe.FindStringSubmatch(line)
	if len(match) > 2 {
		return &AuthEvent{
			Timestamp:   timestamp,
			EventType:   "auth_failure_su",
			Priority:    "Warning",
			Service:     "su",
			Username:    match[2], // Target user
			Description: fmt.Sprintf("Failed su attempt from '%s' to '%s'", match[1], match[2]),
			RawLine:     line,
			RawFields: map[string]string{
				"from_user": match[1],
				"to_user":   match[2],
				"service":   "su",
			},
		}
	}

	match = suAuthFailureRe.FindStringSubmatch(line)
	if len(match) > 1 {
		return &AuthEvent{
			Timestamp:   timestamp,
			EventType:   "auth_failure_su",
			Priority:    "Warning",
			Service:     "su",
			Username:    match[1],
			Description: fmt.Sprintf("Su PAM authentication failure for user '%s'", match[1]),
			RawLine:     line,
			RawFields: map[string]string{
				"username": match[1],
				"service":  "su",
			},
		}
	}

	return nil
}

func (c *AuthCheck) matchPAMFailure(line string, timestamp time.Time) *AuthEvent {
	match := pamAuthFailureRe.FindStringSubmatch(line)
	if len(match) > 2 {
		service := match[1]
		username := match[2]

		// Skip if already matched by more specific patterns
		if strings.Contains(service, "ssh") || strings.Contains(service, "sudo") || strings.Contains(service, "su") {
			return nil
		}

		return &AuthEvent{
			Timestamp:   timestamp,
			EventType:   "auth_failure_pam",
			Priority:    "Notice",
			Service:     service,
			Username:    username,
			Description: fmt.Sprintf("PAM authentication failure for user '%s' via %s", username, service),
			RawLine:     line,
			RawFields: map[string]string{
				"username": username,
				"service":  service,
			},
		}
	}
	return nil
}

// sendSecurityEvent sends an auth event as a security event
func (c *AuthCheck) sendSecurityEvent(event AuthEvent) {
	log.Debug().Msgf("auth.sendSecurityEvent - sending event: %s for user %s", event.EventType, event.Username)

	// Convert raw fields to map[string]interface{}
	rawFields := make(map[string]interface{})
	for k, v := range event.RawFields {
		rawFields[k] = v
	}

	// Create a unified security event
	secEvent := ebpf.SecurityEvent{
		UUID:      uuid.New().String(),
		AgentType: ebpf.AgentTypeNative,
		Timestamp: event.Timestamp,
		Priority:  mapPriority(event.Priority),
		Rule:      fmt.Sprintf("Authentication Failure: %s", event.Service),
		Source:    "auth_log",
		Category:  "authentication",
		Output:    event.Description,
		Message:   event.Description,
		Tags:      []string{"authentication", "security", event.Service},
		RawFields: rawFields,
	}

	// Send as check result
	metrics := make(map[string]api.Metric)
	metrics["event_type"] = api.Metric{Type: "event_type", Value: event.EventType, Unit: "string"}
	metrics["priority"] = api.Metric{Type: "priority", Value: event.Priority, Unit: "string"}
	metrics["service"] = api.Metric{Type: "service", Value: event.Service, Unit: "string"}
	if event.Username != "" {
		metrics["username"] = api.Metric{Type: "username", Value: event.Username, Unit: "string"}
	}
	if event.SourceIP != "" {
		metrics["source_ip"] = api.Metric{Type: "source_ip", Value: event.SourceIP, Unit: "string"}
	}
	if event.SourcePort != "" {
		metrics["source_port"] = api.Metric{Type: "source_port", Value: event.SourcePort, Unit: "string"}
	}
	metrics["description"] = api.Metric{Type: "description", Value: event.Description, Unit: "string"}

	// Serialize the security event for the params
	secEventJSON, _ := json.Marshal(secEvent)

	hostEventGroup := api.MetricGroup{
		Prefix:  "security_event",
		Metrics: metrics,
	}

	result := api.CheckMetricParams{
		Timestamp:      event.Timestamp.UnixNano() / int64(time.Millisecond),
		CheckID:        "host.auth_failure",
		CheckType:      "host.auth_failure",
		State:          event.EventType,
		Status:         event.Priority,
		MinCheckPeriod: int64(c.interval),
		MetricGroups: []api.MetricGroup{
			hostEventGroup,
		},
		InventoryData: secEventJSON,
	}

	log.Debug().Msgf("auth.sendSecurityEvent - submitting security event: %s", event.EventType)
	c.resultsChan <- result
}

// sendAuthMetrics sends summary metrics for auth monitoring
func (c *AuthCheck) sendAuthMetrics(eventCount int) {
	metrics := make(map[string]api.Metric)
	metrics["events_detected"] = api.Metric{Type: "events_detected", Value: strconv.Itoa(eventCount), Unit: "int"}
	metrics["log_file"] = api.Metric{Type: "log_file", Value: c.logFile, Unit: "string"}
	metrics["last_offset"] = api.Metric{Type: "last_offset", Value: strconv.FormatInt(c.lastOffset, 10), Unit: "int"}

	authMetricsGroup := api.MetricGroup{
		Prefix:  "auth_monitor",
		Metrics: metrics,
	}

	result := api.CheckMetricParams{
		Timestamp:      time.Now().UnixNano() / int64(time.Millisecond),
		CheckID:        "host.monitor_auth",
		CheckType:      "host.monitor_auth",
		State:          "ok",
		Status:         "ok",
		MinCheckPeriod: int64(c.interval),
		MetricGroups: []api.MetricGroup{
			authMetricsGroup,
		},
	}

	log.Debug().Msgf("auth.sendAuthMetrics - submitting: %s, events detected: %d", c.Label, eventCount)
	c.resultsChan <- result
}

// mapPriority maps string priority to ebpf.PriorityLevel
func mapPriority(priority string) ebpf.PriorityLevel {
	switch strings.ToLower(priority) {
	case "critical":
		return ebpf.PriorityCritical
	case "high", "error":
		return ebpf.PriorityError
	case "warning":
		return ebpf.PriorityWarning
	case "notice":
		return ebpf.PriorityNotice
	case "info", "informational":
		return ebpf.PriorityInformational
	default:
		return ebpf.PriorityNotice
	}
}

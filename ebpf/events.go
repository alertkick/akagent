package ebpf

import (
	"encoding/json"
	"strings"
	"time"
)

// PriorityLevel represents the severity level of a security event
type PriorityLevel int

const (
	PriorityDefault PriorityLevel = iota
	PriorityDebug
	PriorityInformational
	PriorityNotice
	PriorityWarning
	PriorityError
	PriorityCritical
	PriorityAlert
	PriorityEmergency
)

// String returns the string representation of the priority level
func (p PriorityLevel) String() string {
	switch p {
	case PriorityDebug:
		return "Debug"
	case PriorityInformational:
		return "Informational"
	case PriorityNotice:
		return "Notice"
	case PriorityWarning:
		return "Warning"
	case PriorityError:
		return "Error"
	case PriorityCritical:
		return "Critical"
	case PriorityAlert:
		return "Alert"
	case PriorityEmergency:
		return "Emergency"
	default:
		return ""
	}
}

// ParsePriority converts a string to a PriorityLevel
func ParsePriority(s string) PriorityLevel {
	switch strings.ToLower(s) {
	case "emergency":
		return PriorityEmergency
	case "alert":
		return PriorityAlert
	case "critical":
		return PriorityCritical
	case "error":
		return PriorityError
	case "warning":
		return PriorityWarning
	case "notice":
		return PriorityNotice
	case "informational", "info":
		return PriorityInformational
	case "debug":
		return PriorityDebug
	default:
		return PriorityDefault
	}
}

// UnmarshalJSON implements custom JSON unmarshaling for PriorityLevel
func (p *PriorityLevel) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*p = ParsePriority(s)
	return nil
}

// MarshalJSON implements custom JSON marshaling for PriorityLevel
func (p PriorityLevel) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

// ProcessInfo contains information about the process that triggered the event
type ProcessInfo struct {
	PID         int    `json:"pid,omitempty"`
	PPID        int    `json:"ppid,omitempty"`
	Name        string `json:"name,omitempty"`
	Cmdline     string `json:"cmdline,omitempty"`
	ExePath     string `json:"exe_path,omitempty"`
	UID         int    `json:"uid,omitempty"`
	Username    string `json:"username,omitempty"`
	LoginUID    int    `json:"login_uid,omitempty"`
	TTY         int    `json:"tty,omitempty"`
	ParentName  string `json:"parent_name,omitempty"`
	ParentExe       string `json:"parent_exe,omitempty"`
	GrandparentPID  int    `json:"grandparent_pid,omitempty"`
	GrandparentName string `json:"grandparent_name,omitempty"`
	Cwd             string `json:"cwd,omitempty"`
	Capabilities string `json:"capabilities,omitempty"`
}

// ContainerInfo contains information about the container context
type ContainerInfo struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Image      string `json:"image,omitempty"`
	ImageTag   string `json:"image_tag,omitempty"`
	Runtime    string `json:"runtime,omitempty"`
	Privileged bool   `json:"privileged,omitempty"`
}

// KubernetesInfo contains Kubernetes-specific context
type KubernetesInfo struct {
	Namespace  string            `json:"namespace,omitempty"`
	Pod        string            `json:"pod,omitempty"`
	PodUID     string            `json:"pod_uid,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Deployment string            `json:"deployment,omitempty"`
	Service    string            `json:"service,omitempty"`
}

// NetworkInfo contains network-related event information
type NetworkInfo struct {
	Protocol       string `json:"protocol,omitempty"`
	SrcIP          string `json:"src_ip,omitempty"`
	SrcPort        int    `json:"src_port,omitempty"`
	DstIP          string `json:"dst_ip,omitempty"`
	DstPort        int    `json:"dst_port,omitempty"`
	Direction      string `json:"direction,omitempty"` // inbound, outbound
	BytesSent      int64  `json:"bytes_sent,omitempty"`
	BytesReceived  int64  `json:"bytes_received,omitempty"`
	DNSQuery       string `json:"dns_query,omitempty"`
	DNSResponse    string `json:"dns_response,omitempty"`
}

// FileInfo contains file-related event information
type FileInfo struct {
	Path      string `json:"path,omitempty"`
	Name      string `json:"name,omitempty"`
	Operation string `json:"operation,omitempty"` // read, write, delete, create, chmod, etc.
	Inode     uint64 `json:"inode,omitempty"`
	Mode      string `json:"mode,omitempty"`
	UID       int    `json:"uid,omitempty"`
	GID       int    `json:"gid,omitempty"`
	Size      int64  `json:"size,omitempty"`
	Hash      string `json:"hash,omitempty"`
}

// SyscallInfo contains syscall-related event information
type SyscallInfo struct {
	Name       string   `json:"name,omitempty"`
	Number     int      `json:"number,omitempty"`
	Args       []string `json:"args,omitempty"`
	ReturnCode int      `json:"return_code,omitempty"`
}

// SecurityEvent represents a unified security event from any eBPF agent
type SecurityEvent struct {
	// Core identification
	UUID      string    `json:"uuid"`
	AgentType AgentType `json:"agent_type"`
	Timestamp time.Time `json:"timestamp"`

	// Event classification
	Priority PriorityLevel `json:"priority"`
	Rule     string        `json:"rule"`
	Source   string        `json:"source"` // syscall, k8s_audit, plugin, etc.
	Category string        `json:"category,omitempty"`

	// Human-readable output
	Output  string   `json:"output"`
	Message string   `json:"message,omitempty"`
	Tags    []string `json:"tags,omitempty"`

	// Context information
	Hostname  string `json:"hostname,omitempty"`
	Process   ProcessInfo    `json:"process,omitempty"`
	Container ContainerInfo  `json:"container,omitempty"`
	K8s       KubernetesInfo `json:"k8s,omitempty"`
	Network   NetworkInfo    `json:"network,omitempty"`
	File      FileInfo       `json:"file,omitempty"`
	Syscall   SyscallInfo    `json:"syscall,omitempty"`

	// Original data preserved for debugging
	RawFields map[string]interface{} `json:"raw_fields,omitempty"`

	// Deduplication fields (populated by agent when count > 1)
	AggregatedCount int        `json:"aggregated_count,omitempty"`
	FirstOccurrence *time.Time `json:"first_occurrence,omitempty"`
	LastOccurrence  *time.Time `json:"last_occurrence,omitempty"`

}

// String returns a JSON string representation of the event
func (e SecurityEvent) String() string {
	j, _ := json.Marshal(e)
	return string(j)
}

// Validate checks if the event has minimum required fields
func (e SecurityEvent) Validate() bool {
	if e.UUID == "" {
		return false
	}
	if e.AgentType == "" {
		return false
	}
	if e.Timestamp.IsZero() {
		return false
	}
	if e.Rule == "" && e.Output == "" {
		return false
	}
	return true
}

// IsHighPriority returns true if the event priority is Error or higher
func (e SecurityEvent) IsHighPriority() bool {
	return e.Priority >= PriorityError
}

// IsCritical returns true if the event priority is Critical or higher
func (e SecurityEvent) IsCritical() bool {
	return e.Priority >= PriorityCritical
}

// HasContainerContext returns true if the event has container information
func (e SecurityEvent) HasContainerContext() bool {
	return e.Container.ID != "" || e.Container.Name != ""
}

// HasK8sContext returns true if the event has Kubernetes information
func (e SecurityEvent) HasK8sContext() bool {
	return e.K8s.Namespace != "" || e.K8s.Pod != ""
}

// HasNetworkContext returns true if the event has network information
func (e SecurityEvent) HasNetworkContext() bool {
	return e.Network.SrcIP != "" || e.Network.DstIP != ""
}

// HasFileContext returns true if the event has file information
func (e SecurityEvent) HasFileContext() bool {
	return e.File.Path != "" || e.File.Name != ""
}

// DeduplicationKey returns a string key for grouping duplicate events.
// Events with the same rule and process name/parent pattern are considered duplicates.
func (e SecurityEvent) DeduplicationKey() string {
	return e.Rule + "|" + e.Process.Name + "|" + e.Process.ParentName
}

// EventBuffer provides a thread-safe buffer for events
type EventBuffer struct {
	events   []SecurityEvent
	maxSize  int
}

// NewEventBuffer creates a new event buffer with the specified max size
func NewEventBuffer(maxSize int) *EventBuffer {
	return &EventBuffer{
		events:  make([]SecurityEvent, 0, maxSize),
		maxSize: maxSize,
	}
}

// Add adds an event to the buffer, dropping oldest if at capacity
func (b *EventBuffer) Add(event SecurityEvent) {
	if len(b.events) >= b.maxSize {
		b.events = b.events[1:]
	}
	b.events = append(b.events, event)
}

// Drain returns all events and clears the buffer
func (b *EventBuffer) Drain() []SecurityEvent {
	events := b.events
	b.events = make([]SecurityEvent, 0, b.maxSize)
	return events
}

// Len returns the current number of events in the buffer
func (b *EventBuffer) Len() int {
	return len(b.events)
}

//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"akagent/ebpf/bpfgen"

	"github.com/rs/xid"
)

// parseExecveEvent converts a raw execve BPF event to a SecurityEvent
func (a *NativeEBPFAgent) parseExecveEvent(data []byte) (SecurityEvent, error) {
	var bpfEvent bpfgen.ExecveEvent

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.TimestampNs); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Pid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Ppid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Uid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Gid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Comm); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Filename); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read filename: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Args); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read args: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.ArgsCount); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read args_count: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.RetCode); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ret_code: %w", err)
	}

	comm := int8ArrayToString(bpfEvent.Comm[:])
	filename := int8ArrayToString(bpfEvent.Filename[:])
	args := int8ArrayToString(bpfEvent.Args[:])

	procInfo := ProcessInfo{
		PID:     int(bpfEvent.Pid),
		PPID:    int(bpfEvent.Ppid),
		Name:    comm,
		ExePath: filename,
		Cmdline: args,
		UID:     int(bpfEvent.Uid),
	}
	// Match the other parsers — fill parent_name/parent_exe/username/cwd
	// from /proc so downstream consumers (SSH login hydration, the endpoint
	// rule evaluator) don't have to re-walk the parent chain themselves.
	EnrichProcessInfo(&procInfo)

	event := SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  PriorityInformational,
		Rule:      "Process Execution",
		Source:    "syscall",
		Category:  "process",
		Output:    fmt.Sprintf("Process %s executed: %s %s", comm, filename, args),
		Tags:      []string{"process", "execve"},
		Process:   procInfo,
		RawFields: map[string]interface{}{
			"timestamp_ns": bpfEvent.TimestampNs,
			"gid":          bpfEvent.Gid,
			"args_count":   bpfEvent.ArgsCount,
			"ret_code":     bpfEvent.RetCode,
		},
	}

	return event, nil
}

// parseFileopsEvent converts a raw fileops BPF event to a SecurityEvent

// parseFileopsEvent converts a raw fileops BPF event to a SecurityEvent
func (a *NativeEBPFAgent) parseFileopsEvent(data []byte) (SecurityEvent, error) {
	var bpfEvent bpfgen.FileEvent

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.TimestampNs); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.EventType); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Pid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Ppid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Uid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Gid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Comm); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Filename); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read filename: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Filename2); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read filename2: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Flags); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read flags: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.RetCode); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ret_code: %w", err)
	}

	// Read extended fields (new_uid, new_gid) added for chown support
	var newUID, newGID uint32
	binary.Read(reader, binary.LittleEndian, &newUID)
	binary.Read(reader, binary.LittleEndian, &newGID)

	comm := int8ArrayToString(bpfEvent.Comm[:])
	filename := int8ArrayToString(bpfEvent.Filename[:])
	filename2 := int8ArrayToString(bpfEvent.Filename2[:])

	var rule, output string
	var tags []string
	priority := PriorityInformational

	switch bpfEvent.EventType {
	case EventTypeOpen:
		rule = "File Open"
		output = fmt.Sprintf("Process %s opened file: %s (flags=0x%x)", comm, filename, bpfEvent.Flags)
		tags = []string{"file", "open"}
	case EventTypeUnlink:
		rule = "File Delete"
		output = fmt.Sprintf("Process %s deleted file: %s", comm, filename)
		tags = []string{"file", "unlink", "delete"}
	case EventTypeRename:
		rule = "File Rename"
		output = fmt.Sprintf("Process %s renamed file: %s -> %s", comm, filename, filename2)
		tags = []string{"file", "rename"}
	case EventTypeChmod:
		rule = "File Permission Change"
		output = fmt.Sprintf("Process %s changed permissions: %s (mode=0o%o)", comm, filename, bpfEvent.Flags)
		tags = []string{"file", "chmod", "permission"}
	case EventTypeChown:
		rule = "File Ownership Change"
		output = fmt.Sprintf("Process %s changed ownership: %s (uid=%d, gid=%d)", comm, filename, newUID, newGID)
		tags = []string{"file", "chown", "ownership"}
		// Changing ownership to root is suspicious
		if newUID == 0 {
			priority = PriorityWarning
			tags = append(tags, "privilege_escalation")
		}
	case EventTypeMkdir:
		rule = "Directory Create"
		output = fmt.Sprintf("Process %s created directory: %s (mode=0o%o)", comm, filename, bpfEvent.Flags)
		tags = []string{"file", "mkdir", "directory"}
	case EventTypeRmdir:
		rule = "Directory Remove"
		output = fmt.Sprintf("Process %s removed directory: %s", comm, filename)
		tags = []string{"file", "rmdir", "directory", "delete"}
	case EventTypeLink:
		rule = "Hard Link Create"
		output = fmt.Sprintf("Process %s created hard link: %s -> %s", comm, filename2, filename)
		tags = []string{"file", "link", "hardlink"}
		priority = PriorityNotice
	case EventTypeSymlink:
		rule = "Symbolic Link Create"
		output = fmt.Sprintf("Process %s created symlink: %s -> %s", comm, filename, filename2)
		tags = []string{"file", "symlink"}
	case EventTypeSetxattr:
		rule = "Extended Attribute Set"
		output = fmt.Sprintf("Process %s set xattr on %s: %s", comm, filename, filename2)
		tags = []string{"file", "xattr", "setxattr"}
		// Security-relevant xattr namespaces
		if isSecurityXattr(filename2) {
			priority = PriorityWarning
			tags = append(tags, "security_label")
		}
	case EventTypeRemovexattr:
		rule = "Extended Attribute Remove"
		output = fmt.Sprintf("Process %s removed xattr from %s: %s", comm, filename, filename2)
		tags = []string{"file", "xattr", "removexattr"}
		if isSecurityXattr(filename2) {
			priority = PriorityWarning
			tags = append(tags, "security_label")
		}
	case EventTypeUtimes:
		rule = "Timestamp Modification"
		output = fmt.Sprintf("Process %s modified timestamps: %s", comm, filename)
		tags = []string{"file", "utimes", "timestamp", "anti_forensics"}
		priority = PriorityNotice
	default:
		rule = "File Operation"
		output = fmt.Sprintf("Process %s performed file operation on: %s", comm, filename)
		tags = []string{"file"}
	}

	event := SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  priority,
		Rule:      rule,
		Source:    "syscall",
		Category:  "file",
		Output:    output,
		Tags:      tags,
		Process: ProcessInfo{
			PID:  int(bpfEvent.Pid),
			PPID: int(bpfEvent.Ppid),
			Name: comm,
			UID:  int(bpfEvent.Uid),
		},
		File: FileInfo{
			Path:      filename,
			Operation: fileOpsEventTypeName(bpfEvent.EventType),
		},
		RawFields: map[string]interface{}{
			"timestamp_ns": bpfEvent.TimestampNs,
			"event_type":   bpfEvent.EventType,
			"filename":     filename,
			"filename2":    filename2,
			"flags":        bpfEvent.Flags,
			"gid":          bpfEvent.Gid,
			"ret_code":     bpfEvent.RetCode,
			"new_uid":      newUID,
			"new_gid":      newGID,
		},
	}

	return event, nil
}

// isSecurityXattr returns true if the xattr name is in a security-relevant namespace

// isSecurityXattr returns true if the xattr name is in a security-relevant namespace
func isSecurityXattr(name string) bool {
	return len(name) > 0 && (strings.HasPrefix(name, "security.") ||
		strings.HasPrefix(name, "system.posix_acl") ||
		strings.HasPrefix(name, "trusted."))
}

// fileOpsEventTypeName returns a human-readable name for a file event type

// fileOpsEventTypeName returns a human-readable name for a file event type
func fileOpsEventTypeName(eventType uint32) string {
	switch eventType {
	case EventTypeOpen:
		return "open"
	case EventTypeUnlink:
		return "unlink"
	case EventTypeRename:
		return "rename"
	case EventTypeChmod:
		return "chmod"
	case EventTypeChown:
		return "chown"
	case EventTypeMkdir:
		return "mkdir"
	case EventTypeRmdir:
		return "rmdir"
	case EventTypeLink:
		return "link"
	case EventTypeSymlink:
		return "symlink"
	case EventTypeSetxattr:
		return "setxattr"
	case EventTypeRemovexattr:
		return "removexattr"
	case EventTypeUtimes:
		return "utimes"
	default:
		return "unknown"
	}
}

// parseNetworkEvent converts a raw network BPF event to a SecurityEvent

// parseNetworkEvent converts a raw network BPF event to a SecurityEvent
func (a *NativeEBPFAgent) parseNetworkEvent(data []byte) (SecurityEvent, error) {
	var bpfEvent bpfgen.NetworkEvent

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.TimestampNs); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.EventType); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Pid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Ppid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Uid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Gid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Comm); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Family); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read family: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Sport); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read sport: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Dport); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read dport: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Protocol); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read protocol: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Saddr); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read saddr: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Daddr); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read daddr: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.RetCode); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ret_code: %w", err)
	}

	comm := int8ArrayToString(bpfEvent.Comm[:])

	// Convert address bytes to IP string
	var daddr string
	if bpfEvent.Family == 2 { // AF_INET
		daddr = net.IP(bpfEvent.Daddr[:4]).String()
	} else if bpfEvent.Family == 10 { // AF_INET6
		daddr = net.IP(bpfEvent.Daddr[:]).String()
	}

	var rule, output string
	var tags []string

	switch bpfEvent.EventType {
	case EventTypeConnect:
		rule = "Network Connect"
		output = fmt.Sprintf("Process %s connecting to %s:%d", comm, daddr, bpfEvent.Dport)
		tags = []string{"network", "connect"}
	case EventTypeAccept:
		rule = "Network Accept"
		output = fmt.Sprintf("Process %s accepting connection", comm)
		tags = []string{"network", "accept"}
	case EventTypeBind:
		rule = "Network Bind"
		if daddr != "" {
			output = fmt.Sprintf("Process %s (pid %d) binding to %s:%d", comm, bpfEvent.Pid, daddr, bpfEvent.Dport)
		} else {
			output = fmt.Sprintf("Process %s (pid %d) binding to port %d", comm, bpfEvent.Pid, bpfEvent.Dport)
		}
		tags = []string{"network", "bind"}
	case EventTypeSocket:
		rule = "Socket Create"
		output = fmt.Sprintf("Process %s created socket (family=%d, protocol=%d)", comm, bpfEvent.Family, bpfEvent.Protocol)
		tags = []string{"network", "socket"}
	default:
		rule = "Network Operation"
		output = fmt.Sprintf("Process %s performed network operation", comm)
		tags = []string{"network"}
	}

	event := SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  PriorityInformational,
		Rule:      rule,
		Source:    "syscall",
		Category:  "network",
		Output:    output,
		Tags:      tags,
		Process: ProcessInfo{
			PID:  int(bpfEvent.Pid),
			PPID: int(bpfEvent.Ppid),
			Name: comm,
			UID:  int(bpfEvent.Uid),
		},
		RawFields: map[string]interface{}{
			"timestamp_ns": bpfEvent.TimestampNs,
			"event_type":   bpfEvent.EventType,
			"family":       bpfEvent.Family,
			"sport":        bpfEvent.Sport,
			"dport":        bpfEvent.Dport,
			"protocol":     bpfEvent.Protocol,
			"daddr":        daddr,
			"gid":          bpfEvent.Gid,
			"ret_code":     bpfEvent.RetCode,
		},
	}

	return event, nil
}

// parseProcessEvent converts a raw process BPF event to a SecurityEvent

// parseProcessEvent converts a raw process BPF event to a SecurityEvent
func (a *NativeEBPFAgent) parseProcessEvent(data []byte) (SecurityEvent, error) {
	var bpfEvent bpfgen.ProcessEvent

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.TimestampNs); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.EventType); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Pid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Ppid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Uid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Gid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Comm); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.TargetPid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read target_pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Sig); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read sig: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.PtraceRequest); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ptrace_request: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.CloneFlags); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read clone_flags: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.RetCode); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ret_code: %w", err)
	}

	comm := int8ArrayToString(bpfEvent.Comm[:])

	// Build process info and enrich with /proc context
	procInfo := ProcessInfo{
		PID:  int(bpfEvent.Pid),
		PPID: int(bpfEvent.Ppid),
		Name: comm,
		UID:  int(bpfEvent.Uid),
	}
	EnrichProcessInfo(&procInfo)

	var rule, output string
	var tags []string
	priority := PriorityInformational

	// Get process context for detailed output
	procContext := GetProcessContext(&procInfo)

	switch bpfEvent.EventType {
	case EventTypeClone:
		rule = "Process Clone"
		tags = []string{"process", "clone"}
		// Detect namespace-creating clones (container breakout / escape vector)
		nsFlags := bpfEvent.CloneFlags & 0x7E020080 // All CLONE_NEW* flags
		if nsFlags != 0 {
			nsFlagStr := cloneNsFlagsString(bpfEvent.CloneFlags)
			rule = "Namespace Clone"
			output = fmt.Sprintf("Process cloned with namespace flags: %s (flags=0x%x). Context: %s", nsFlagStr, bpfEvent.CloneFlags, procContext)
			tags = append(tags, "namespace", "container_security")
			priority = PriorityNotice
		} else {
			output = fmt.Sprintf("Process cloned (flags=0x%x). Context: %s", bpfEvent.CloneFlags, procContext)
		}
	case EventTypeKill:
		rule = "Process Signal"
		output = fmt.Sprintf("Process sent signal %d to PID %d. Context: %s", bpfEvent.Sig, bpfEvent.TargetPid, procContext)
		tags = []string{"process", "kill", "signal"}
		if bpfEvent.Sig == 9 { // SIGKILL
			priority = PriorityWarning
		}
	case EventTypeTgkill:
		rule = "Process Signal"
		output = fmt.Sprintf("Process sent signal %d to thread group %d via tgkill. Context: %s", bpfEvent.Sig, bpfEvent.TargetPid, procContext)
		tags = []string{"process", "tgkill", "signal"}
		if bpfEvent.Sig == 9 { // SIGKILL
			priority = PriorityWarning
		}
	case EventTypeTkill:
		rule = "Process Signal"
		output = fmt.Sprintf("Process sent signal %d to thread %d via tkill. Context: %s", bpfEvent.Sig, bpfEvent.TargetPid, procContext)
		tags = []string{"process", "tkill", "signal"}
		if bpfEvent.Sig == 9 { // SIGKILL
			priority = PriorityWarning
		}
	case EventTypePtrace:
		rule = "Process Ptrace"
		output = fmt.Sprintf("Process used ptrace (request=%d) on PID %d. Context: %s", bpfEvent.PtraceRequest, bpfEvent.TargetPid, procContext)
		tags = []string{"process", "ptrace", "debug"}
		priority = PriorityWarning // Ptrace is often suspicious
	default:
		rule = "Process Operation"
		output = fmt.Sprintf("Process performed operation. Context: %s", procContext)
		tags = []string{"process"}
	}

	event := SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  priority,
		Rule:      rule,
		Source:    "syscall",
		Category:  "process",
		Output:    output,
		Tags:      tags,
		Process:   procInfo,
		RawFields: map[string]interface{}{
			"timestamp_ns":   bpfEvent.TimestampNs,
			"event_type":     bpfEvent.EventType,
			"target_pid":     bpfEvent.TargetPid,
			"sig":            bpfEvent.Sig,
			"ptrace_request": bpfEvent.PtraceRequest,
			"clone_flags":    bpfEvent.CloneFlags,
			"gid":            bpfEvent.Gid,
			"ret_code":       bpfEvent.RetCode,
		},
	}

	return event, nil
}

// int8ArrayToString converts an int8 array to a string, stopping at the first null byte

// int8ArrayToString converts an int8 array to a string, stopping at the first null byte
func int8ArrayToString(arr []int8) string {
	buf := make([]byte, 0, len(arr))
	for _, c := range arr {
		if c == 0 {
			break
		}
		buf = append(buf, byte(c))
	}
	return string(buf)
}

// nullTerminatedString converts a byte slice to a string, stopping at the first null byte

// nullTerminatedString converts a byte slice to a string, stopping at the first null byte
func nullTerminatedString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// readPrivilegeEvents reads events from the privilege ring buffer

// parsePrivilegeEvent converts a raw privilege BPF event to a SecurityEvent
func (a *NativeEBPFAgent) parsePrivilegeEvent(data []byte) (SecurityEvent, error) {
	var bpfEvent bpfgen.PrivilegeEvent

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.TimestampNs); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.EventType); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Pid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Ppid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Uid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Gid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Comm); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.NewUid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read new_uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.NewGid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read new_gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.NewEuid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read new_euid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.NewEgid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read new_egid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.RetCode); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ret_code: %w", err)
	}

	comm := int8ArrayToString(bpfEvent.Comm[:])

	// Build process info and enrich with /proc context
	procInfo := ProcessInfo{
		PID:  int(bpfEvent.Pid),
		PPID: int(bpfEvent.Ppid),
		Name: comm,
		UID:  int(bpfEvent.Uid),
	}
	EnrichProcessInfo(&procInfo)

	// Filter out container runtimes - they legitimately setuid/setgid to root
	// This must happen before priority assignment since high priority bypasses alert rules
	processNameLower := strings.ToLower(procInfo.Name)
	containerRuntimes := []string{"runc", "containerd", "dockerd", "docker-proxy", "crio", "podman", "buildah", "crun"}
	for _, runtime := range containerRuntimes {
		if strings.HasPrefix(processNameLower, runtime) {
			return SecurityEvent{}, fmt.Errorf("filtered: container runtime %s", runtime)
		}
	}

	var rule, output string
	var tags []string
	priority := PriorityWarning // Privilege changes are high priority

	// Get process context for detailed output
	procContext := GetProcessContext(&procInfo)

	switch bpfEvent.EventType {
	case EventTypeSetuid:
		rule = "Privilege Escalation: setuid"
		output = fmt.Sprintf("Process called setuid to UID %d. Context: %s", bpfEvent.NewUid, procContext)
		tags = []string{"privilege", "setuid"}
	case EventTypeSetgid:
		rule = "Privilege Escalation: setgid"
		output = fmt.Sprintf("Process called setgid to GID %d. Context: %s", bpfEvent.NewGid, procContext)
		tags = []string{"privilege", "setgid"}
	case EventTypeSetreuid:
		rule = "Privilege Escalation: setreuid"
		output = fmt.Sprintf("Process called setreuid (ruid=%d, euid=%d). Context: %s", bpfEvent.NewUid, bpfEvent.NewEuid, procContext)
		tags = []string{"privilege", "setreuid"}
	case EventTypeSetregid:
		rule = "Privilege Escalation: setregid"
		output = fmt.Sprintf("Process called setregid (rgid=%d, egid=%d). Context: %s", bpfEvent.NewGid, bpfEvent.NewEgid, procContext)
		tags = []string{"privilege", "setregid"}
	default:
		rule = "Privilege Change"
		output = fmt.Sprintf("Process performed privilege change. Context: %s", procContext)
		tags = []string{"privilege"}
	}

	// Escalation to root is critical
	if bpfEvent.NewUid == 0 || bpfEvent.NewEuid == 0 {
		priority = PriorityCritical
		output += " [ESCALATION TO ROOT]"
	}

	event := SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  priority,
		Rule:      rule,
		Source:    "syscall",
		Category:  "privilege",
		Output:    output,
		Tags:      tags,
		Process:   procInfo,
		RawFields: map[string]interface{}{
			"timestamp_ns": bpfEvent.TimestampNs,
			"event_type":   bpfEvent.EventType,
			"new_uid":      bpfEvent.NewUid,
			"new_gid":      bpfEvent.NewGid,
			"new_euid":     bpfEvent.NewEuid,
			"new_egid":     bpfEvent.NewEgid,
			"gid":          bpfEvent.Gid,
			"ret_code":     bpfEvent.RetCode,
		},
	}

	return event, nil
}

// parseMountEvent converts a raw mount BPF event to a SecurityEvent

// parseMountEvent converts a raw mount BPF event to a SecurityEvent
func (a *NativeEBPFAgent) parseMountEvent(data []byte) (SecurityEvent, error) {
	var bpfEvent bpfgen.MountEvent

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.TimestampNs); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.EventType); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Pid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Ppid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Uid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Gid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Comm); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Source); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read source: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Target); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read target: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Fstype); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read fstype: %w", err)
	}
	// Skip padding
	var padding [4]byte
	binary.Read(reader, binary.LittleEndian, &padding)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Flags); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read flags: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.RetCode); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ret_code: %w", err)
	}

	comm := int8ArrayToString(bpfEvent.Comm[:])
	source := int8ArrayToString(bpfEvent.Source[:])
	target := int8ArrayToString(bpfEvent.Target[:])
	fstype := int8ArrayToString(bpfEvent.Fstype[:])

	// Filter out routine mount operations that aren't security-relevant
	// These are normal system operations that create noise without actionable value
	processNameLower := strings.ToLower(comm)

	// Filter /proc/self mounts - these are process namespace/fd operations (systemd service isolation, etc.)
	if strings.HasPrefix(target, "/proc/self/") {
		return SecurityEvent{}, fmt.Errorf("filtered: process namespace mount operation")
	}

	// Filter systemd mount operations
	if processNameLower == "systemd" || strings.HasPrefix(processNameLower, "systemd-") {
		// Filter systemd credential directory operations (service credential management)
		if strings.HasPrefix(target, "/run/credentials/") {
			return SecurityEvent{}, fmt.Errorf("filtered: systemd credential mount operation")
		}
		// Filter systemd internal mount operations
		if strings.HasPrefix(target, "/run/systemd/") {
			return SecurityEvent{}, fmt.Errorf("filtered: systemd internal mount operation")
		}
	}

	// Filter container runtime and sandbox mount operations (these are extremely noisy)
	containerAndSandboxTools := []string{
		// Container runtimes
		"runc", "containerd", "dockerd", "crio", "podman", "buildah", "crun",
		// Sandbox tools (Flatpak, Snap, etc.)
		"bwrap", "bubblewrap", "flatpak", "snap", "firejail",
	}
	for _, tool := range containerAndSandboxTools {
		if strings.HasPrefix(processNameLower, tool) {
			return SecurityEvent{}, fmt.Errorf("filtered: container/sandbox mount operation")
		}
	}

	// Filter sandbox-related mount paths (oldroot/newroot are sandbox setup)
	if strings.HasPrefix(target, "/newroot/") || strings.HasPrefix(target, "/oldroot/") {
		return SecurityEvent{}, fmt.Errorf("filtered: sandbox mount operation")
	}

	// Build process info and enrich with /proc context
	procInfo := ProcessInfo{
		PID:  int(bpfEvent.Pid),
		PPID: int(bpfEvent.Ppid),
		Name: comm,
		UID:  int(bpfEvent.Uid),
	}
	EnrichProcessInfo(&procInfo)

	var rule, output string
	var tags []string
	priority := PriorityWarning // Mount operations are security-sensitive

	// Get process context for detailed output
	procContext := GetProcessContext(&procInfo)

	switch bpfEvent.EventType {
	case EventTypeMount:
		rule = "Filesystem Mount"
		output = fmt.Sprintf("Process mounted %s on %s (type=%s, flags=0x%x). Context: %s", source, target, fstype, bpfEvent.Flags, procContext)
		tags = []string{"mount", "filesystem"}
	case EventTypeUmount:
		rule = "Filesystem Unmount"
		output = fmt.Sprintf("Process unmounted %s. Context: %s", target, procContext)
		tags = []string{"umount", "filesystem"}
	default:
		rule = "Filesystem Operation"
		output = fmt.Sprintf("Process performed filesystem operation. Context: %s", procContext)
		tags = []string{"filesystem"}
	}

	event := SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  priority,
		Rule:      rule,
		Source:    "syscall",
		Category:  "filesystem",
		Output:    output,
		Tags:      tags,
		Process:   procInfo,
		RawFields: map[string]interface{}{
			"timestamp_ns": bpfEvent.TimestampNs,
			"event_type":   bpfEvent.EventType,
			"source":       source,
			"target":       target,
			"fstype":       fstype,
			"flags":        bpfEvent.Flags,
			"gid":          bpfEvent.Gid,
			"ret_code":     bpfEvent.RetCode,
		},
	}

	return event, nil
}

// parseModuleEvent converts a raw module BPF event to a SecurityEvent

// parseModuleEvent converts a raw module BPF event to a SecurityEvent
func (a *NativeEBPFAgent) parseModuleEvent(data []byte) (SecurityEvent, error) {
	var bpfEvent bpfgen.ModuleEvent

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.TimestampNs); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.EventType); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Pid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Ppid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Uid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Gid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Comm); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.ModuleName); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read module_name: %w", err)
	}
	// Skip padding
	var padding [4]byte
	binary.Read(reader, binary.LittleEndian, &padding)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.ModuleSize); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read module_size: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Flags); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read flags: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.RetCode); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ret_code: %w", err)
	}

	comm := int8ArrayToString(bpfEvent.Comm[:])
	moduleName := int8ArrayToString(bpfEvent.ModuleName[:])

	// Build process info and enrich with /proc context
	procInfo := ProcessInfo{
		PID:  int(bpfEvent.Pid),
		PPID: int(bpfEvent.Ppid),
		Name: comm,
		UID:  int(bpfEvent.Uid),
	}
	EnrichProcessInfo(&procInfo)

	var rule, output string
	var tags []string
	priority := PriorityCritical // Kernel module operations are critical

	// Get process context for detailed output
	procContext := GetProcessContext(&procInfo)

	switch bpfEvent.EventType {
	case EventTypeInitModule:
		rule = "Kernel Module Load"
		output = fmt.Sprintf("Process loaded kernel module (size=%d bytes). Context: %s", bpfEvent.ModuleSize, procContext)
		tags = []string{"module", "kernel", "init_module"}
	case EventTypeFinitModule:
		rule = "Kernel Module Load (from file)"
		output = fmt.Sprintf("Process loaded kernel module from file. Context: %s", procContext)
		tags = []string{"module", "kernel", "finit_module"}
	case EventTypeDeleteModule:
		rule = "Kernel Module Unload"
		output = fmt.Sprintf("Process unloaded kernel module: %s. Context: %s", moduleName, procContext)
		tags = []string{"module", "kernel", "delete_module"}
	default:
		rule = "Kernel Module Operation"
		output = fmt.Sprintf("Process performed kernel module operation. Context: %s", procContext)
		tags = []string{"module", "kernel"}
	}

	event := SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  priority,
		Rule:      rule,
		Source:    "syscall",
		Category:  "kernel",
		Output:    output,
		Tags:      tags,
		Process:   procInfo,
		RawFields: map[string]interface{}{
			"timestamp_ns": bpfEvent.TimestampNs,
			"event_type":   bpfEvent.EventType,
			"module_name":  moduleName,
			"module_size":  bpfEvent.ModuleSize,
			"flags":        bpfEvent.Flags,
			"gid":          bpfEvent.Gid,
			"ret_code":     bpfEvent.RetCode,
		},
	}

	return event, nil
}

// protFlagsString converts a PROT_* bitmask to a human-readable string (e.g., "RWX")

// protFlagsString converts a PROT_* bitmask to a human-readable string (e.g., "RWX")
func protFlagsString(prot uint32) string {
	var s string
	if prot&0x1 != 0 {
		s += "R"
	}
	if prot&0x2 != 0 {
		s += "W"
	}
	if prot&0x4 != 0 {
		s += "X"
	}
	if s == "" {
		s = "NONE"
	}
	return s
}

// mmapFlagsString converts MAP_* flags to a human-readable string

// mmapFlagsString converts MAP_* flags to a human-readable string
func mmapFlagsString(flags uint32) string {
	var parts []string
	if flags&0x01 != 0 {
		parts = append(parts, "MAP_SHARED")
	}
	if flags&0x02 != 0 {
		parts = append(parts, "MAP_PRIVATE")
	}
	if flags&0x10 != 0 {
		parts = append(parts, "MAP_FIXED")
	}
	if flags&0x20 != 0 {
		parts = append(parts, "MAP_ANONYMOUS")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("0x%x", flags)
	}
	return strings.Join(parts, "|")
}

// isJITProcess returns true if the process name matches a known JIT compiler/runtime
// These legitimately use W+X memory and should not trigger code injection alerts

// isJITProcess returns true if the process name matches a known JIT compiler/runtime
// These legitimately use W+X memory and should not trigger code injection alerts
func isJITProcess(name string) bool {
	processNameLower := strings.ToLower(name)
	jitProcesses := []string{
		// Browsers
		"chrome", "chromium", "firefox", "msedge", "brave", "opera", "vivaldi",
		// JavaScript runtimes
		"node", "nodejs", "deno", "bun",
		// JVMs
		"java", "javac",
		// Other runtimes
		"python", "python3", "ruby", "php", "dotnet", "mono",
		// Desktop with JS engines
		"gnome-shell", "plasmashell", "kwin",
		// Electron apps
		"electron", "code", "slack", "discord", "teams", "spotify",
	}
	for _, jit := range jitProcesses {
		if strings.HasPrefix(processNameLower, jit) {
			return true
		}
	}
	return false
}

// parseMemoryEvent converts a raw memory BPF event to a SecurityEvent
// Handles both mprotect (EVENT_TYPE_MPROTECT=50) and mmap (EVENT_TYPE_MMAP=51)

// parseMemoryEvent converts a raw memory BPF event to a SecurityEvent
// Handles both mprotect (EVENT_TYPE_MPROTECT=50) and mmap (EVENT_TYPE_MMAP=51)
func (a *NativeEBPFAgent) parseMemoryEvent(data []byte) (SecurityEvent, error) {
	var bpfEvent bpfgen.MemoryEvent

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.TimestampNs); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.EventType); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Pid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Ppid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Uid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Gid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Comm); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	// Skip padding (comm[16] at offset 28 needs 4 bytes padding to align addr to 8-byte boundary)
	var padding [4]byte
	binary.Read(reader, binary.LittleEndian, &padding)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Addr); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read addr: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Len); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read len: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Prot); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read prot: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.RetCode); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ret_code: %w", err)
	}
	// Read mmap-specific fields (flags and fd) — zero for mprotect events
	var mmapFlags uint32
	var mmapFd int32
	binary.Read(reader, binary.LittleEndian, &mmapFlags)
	binary.Read(reader, binary.LittleEndian, &mmapFd)

	comm := int8ArrayToString(bpfEvent.Comm[:])

	// Build process info and enrich with /proc context
	procInfo := ProcessInfo{
		PID:  int(bpfEvent.Pid),
		PPID: int(bpfEvent.Ppid),
		Name: comm,
		UID:  int(bpfEvent.Uid),
	}
	EnrichProcessInfo(&procInfo)

	protStr := protFlagsString(bpfEvent.Prot)
	isWX := bpfEvent.Prot&0x2 != 0 && bpfEvent.Prot&0x4 != 0

	// Filter out JIT processes for W+X events — they legitimately use W+X memory
	// This must happen before priority assignment since high priority bypasses alert rules
	if isWX && isJITProcess(procInfo.Name) {
		return SecurityEvent{}, fmt.Errorf("filtered: JIT process %s", procInfo.Name)
	}

	procContext := GetProcessContext(&procInfo)

	var rule, output string
	var tags []string
	var priority PriorityLevel
	rawFields := map[string]interface{}{
		"timestamp_ns": bpfEvent.TimestampNs,
		"event_type":   bpfEvent.EventType,
		"addr":         bpfEvent.Addr,
		"len":          bpfEvent.Len,
		"prot":         bpfEvent.Prot,
		"prot_str":     protStr,
		"gid":          bpfEvent.Gid,
		"ret_code":     bpfEvent.RetCode,
	}

	switch bpfEvent.EventType {
	case EventTypeMmap:
		isAnon := mmapFlags&0x20 != 0
		isFixed := mmapFlags&0x10 != 0
		flagsStr := mmapFlagsString(mmapFlags)

		tags = []string{"memory", "mmap", "exec"}
		priority = PriorityInformational
		rawFields["flags"] = mmapFlags
		rawFields["flags_str"] = flagsStr
		rawFields["fd"] = mmapFd

		if isWX {
			if isAnon {
				// Anonymous RWX mapping — strongest indicator of shellcode injection
				// Normal programs never create anonymous RWX memory (JIT already filtered above)
				rule = "Anonymous RWX Memory Mapping"
				priority = PriorityCritical
				tags = append(tags, "code_injection", "rwx", "anonymous_exec")
				output = fmt.Sprintf("Process created anonymous RWX memory mapping at 0x%x (len=%d, flags=%s). Context: %s [CRITICAL - POTENTIAL SHELLCODE INJECTION]",
					bpfEvent.Addr, bpfEvent.Len, flagsStr, procContext)
			} else {
				// File-backed RWX mapping — suspicious but less so (could be JIT from shared lib)
				rule = "RWX Memory Mapping"
				priority = PriorityWarning
				tags = append(tags, "code_injection", "rwx")
				output = fmt.Sprintf("Process created RWX memory mapping at 0x%x (len=%d, flags=%s, fd=%d). Context: %s [W+X MAPPING]",
					bpfEvent.Addr, bpfEvent.Len, flagsStr, mmapFd, procContext)
			}
		} else if isAnon {
			// Anonymous executable mapping without write — could be JIT code staging
			rule = "Anonymous Executable Memory Mapping"
			priority = PriorityNotice
			tags = append(tags, "anonymous_exec")
			output = fmt.Sprintf("Process created anonymous executable mapping at 0x%x (len=%d, prot=%s, flags=%s). Context: %s",
				bpfEvent.Addr, bpfEvent.Len, protStr, flagsStr, procContext)
		} else if isFixed {
			// MAP_FIXED with PROT_EXEC — could be code replacement at a specific address
			rule = "Fixed Executable Memory Mapping"
			priority = PriorityNotice
			tags = append(tags, "fixed_exec")
			output = fmt.Sprintf("Process created fixed executable mapping at 0x%x (len=%d, prot=%s, flags=%s, fd=%d). Context: %s",
				bpfEvent.Addr, bpfEvent.Len, protStr, flagsStr, mmapFd, procContext)
		} else {
			// File-backed executable mapping (normal library load captured because PROT_EXEC)
			rule = "Executable Memory Mapping"
			output = fmt.Sprintf("Process created executable mapping at 0x%x (len=%d, prot=%s, flags=%s, fd=%d). Context: %s",
				bpfEvent.Addr, bpfEvent.Len, protStr, flagsStr, mmapFd, procContext)
		}

	default: // EventTypeMprotect
		rule = "Memory Protection Change"
		tags = []string{"memory", "mprotect"}
		priority = PriorityInformational
		output = fmt.Sprintf("Process set memory at 0x%x (len=%d) to %s. Context: %s",
			bpfEvent.Addr, bpfEvent.Len, protStr, procContext)

		if isWX {
			priority = PriorityWarning
			tags = append(tags, "exec", "code_injection", "wxe")
			output += " [W+X - POTENTIAL CODE INJECTION]"
		}
	}

	event := SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  priority,
		Rule:      rule,
		Source:    "syscall",
		Category:  "memory",
		Output:    output,
		Tags:      tags,
		Process:   procInfo,
		RawFields: rawFields,
	}

	return event, nil
}

// readDnsEvents reads events from the DNS ring buffer

// parseDnsEvent converts a raw DNS BPF event to a SecurityEvent
func (a *NativeEBPFAgent) parseDnsEvent(data []byte) (SecurityEvent, error) {
	var bpfEvent bpfgen.DnsEvent

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.TimestampNs); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.EventType); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Pid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Ppid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Uid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Gid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Comm); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Id); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read id: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Qtype); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read qtype: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Qclass); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read qclass: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Family); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read family: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Dport); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read dport: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.NameLen); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read name_len: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Daddr); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read daddr: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Qname); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read qname: %w", err)
	}

	comm := int8ArrayToString(bpfEvent.Comm[:])
	qname := int8ArrayToString(bpfEvent.Qname[:])

	// Convert DNS server address to string
	var dnsServer string
	if bpfEvent.Family == 2 { // AF_INET
		dnsServer = net.IP(bpfEvent.Daddr[:4]).String()
	} else if bpfEvent.Family == 10 { // AF_INET6
		dnsServer = net.IP(bpfEvent.Daddr[:]).String()
	}

	// DNS query type name
	qtypeName := dnsQtypeName(bpfEvent.Qtype)

	rule := "DNS Query"
	output := fmt.Sprintf("Process %s queried DNS for %s (%s) via %s", comm, qname, qtypeName, dnsServer)
	tags := []string{"network", "dns", "dns_query"}

	event := SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  PriorityInformational,
		Rule:      rule,
		Source:    "syscall",
		Category:  "network",
		Output:    output,
		Tags:      tags,
		Process: ProcessInfo{
			PID:  int(bpfEvent.Pid),
			PPID: int(bpfEvent.Ppid),
			Name: comm,
			UID:  int(bpfEvent.Uid),
		},
		Network: NetworkInfo{
			Protocol: "udp",
			DstIP:    dnsServer,
			DstPort:  int(bpfEvent.Dport),
			DNSQuery: qname,
		},
		RawFields: map[string]interface{}{
			"timestamp_ns": bpfEvent.TimestampNs,
			"event_type":   bpfEvent.EventType,
			"dns_id":       bpfEvent.Id,
			"qtype":        bpfEvent.Qtype,
			"qtype_name":   qtypeName,
			"qclass":       bpfEvent.Qclass,
			"family":       bpfEvent.Family,
			"dport":        bpfEvent.Dport,
			"dns_server":   dnsServer,
			"qname":        qname,
			"name_len":     bpfEvent.NameLen,
			"gid":          bpfEvent.Gid,
		},
	}

	return event, nil
}

// dnsQtypeName returns the human-readable name for a DNS query type

// dnsQtypeName returns the human-readable name for a DNS query type
func dnsQtypeName(qtype uint16) string {
	switch qtype {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 255:
		return "ANY"
	default:
		return fmt.Sprintf("TYPE%d", qtype)
	}
}

// readImdsEvents reads events from the IMDS ring buffer

// parseImdsEvent converts a raw IMDS BPF event to a SecurityEvent
func (a *NativeEBPFAgent) parseImdsEvent(data []byte) (SecurityEvent, error) {
	var bpfEvent bpfgen.ImdsEvent

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.TimestampNs); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.EventType); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Pid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Ppid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Uid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Gid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Comm); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Family); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read family: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Dport); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read dport: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Daddr); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read daddr: %w", err)
	}

	comm := int8ArrayToString(bpfEvent.Comm[:])

	// IMDS address (always 169.254.169.254 for IPv4)
	daddr := net.IP(bpfEvent.Daddr[:4]).String()

	// Build process info and enrich with /proc context
	procInfo := ProcessInfo{
		PID:  int(bpfEvent.Pid),
		PPID: int(bpfEvent.Ppid),
		Name: comm,
		UID:  int(bpfEvent.Uid),
	}
	EnrichProcessInfo(&procInfo)
	procContext := GetProcessContext(&procInfo)

	rule := "Cloud IMDS Access"
	output := fmt.Sprintf("Process %s connected to cloud metadata service %s:%d. Context: %s",
		comm, daddr, bpfEvent.Dport, procContext)
	tags := []string{"network", "cloud", "imds", "credential_access"}
	priority := PriorityWarning // IMDS access is always suspicious

	event := SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  priority,
		Rule:      rule,
		Source:    "syscall",
		Category:  "network",
		Output:    output,
		Tags:      tags,
		Process:   procInfo,
		Network: NetworkInfo{
			Protocol: "tcp",
			DstIP:    daddr,
			DstPort:  int(bpfEvent.Dport),
		},
		RawFields: map[string]interface{}{
			"timestamp_ns": bpfEvent.TimestampNs,
			"event_type":   bpfEvent.EventType,
			"family":       bpfEvent.Family,
			"dport":        bpfEvent.Dport,
			"daddr":        daddr,
			"gid":          bpfEvent.Gid,
		},
	}

	return event, nil
}

// readBpfSyscallEvents reads events from the BPF syscall ring buffer

// parseBpfSyscallEvent converts a raw BPF syscall event to a SecurityEvent
func (a *NativeEBPFAgent) parseBpfSyscallEvent(data []byte) (SecurityEvent, error) {
	var bpfEvent bpfgen.BpfSyscallEvent

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.TimestampNs); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.EventType); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Pid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Ppid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Uid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Gid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Comm); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Cmd); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read cmd: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.ProgType); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read prog_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.InsnCnt); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read insn_cnt: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.AttachType); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read attach_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.ObjName); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read obj_name: %w", err)
	}

	comm := int8ArrayToString(bpfEvent.Comm[:])
	objName := int8ArrayToString(bpfEvent.ObjName[:])
	cmdName := bpfCmdName(bpfEvent.Cmd)

	// Build process info and enrich
	procInfo := ProcessInfo{
		PID:  int(bpfEvent.Pid),
		PPID: int(bpfEvent.Ppid),
		Name: comm,
		UID:  int(bpfEvent.Uid),
	}
	EnrichProcessInfo(&procInfo)
	procContext := GetProcessContext(&procInfo)

	// Determine priority based on command type
	priority := PriorityWarning
	rule := "BPF Syscall"
	tags := []string{"kernel", "bpf"}

	switch bpfEvent.Cmd {
	case 5: // BPF_PROG_LOAD
		priority = PriorityCritical
		rule = "BPF Program Load"
		tags = append(tags, "rootkit", "defense_evasion")
	case 0: // BPF_MAP_CREATE
		rule = "BPF Map Create"
	case 8: // BPF_PROG_ATTACH
		priority = PriorityCritical
		rule = "BPF Program Attach"
		tags = append(tags, "rootkit", "defense_evasion")
	case 6: // BPF_OBJ_PIN
		rule = "BPF Object Pin"
		tags = append(tags, "persistence")
	case 17: // BPF_RAW_TRACEPOINT_OPEN
		priority = PriorityCritical
		rule = "BPF Raw Tracepoint Open"
		tags = append(tags, "rootkit")
	case 28: // BPF_LINK_CREATE
		priority = PriorityCritical
		rule = "BPF Link Create"
		tags = append(tags, "rootkit")
	case 18: // BPF_BTF_LOAD
		rule = "BPF BTF Load"
	}

	// Build output message with context
	var output string
	switch bpfEvent.Cmd {
	case 5: // BPF_PROG_LOAD
		output = fmt.Sprintf("Process %s loaded BPF program %q (type=%s, insns=%d, attach=%s). Context: %s",
			comm, objName, bpfProgTypeName(bpfEvent.ProgType), bpfEvent.InsnCnt,
			bpfAttachTypeName(bpfEvent.AttachType), procContext)
	case 0: // BPF_MAP_CREATE
		output = fmt.Sprintf("Process %s created BPF map %q (type=%s). Context: %s",
			comm, objName, bpfMapTypeName(bpfEvent.ProgType), procContext)
	default:
		output = fmt.Sprintf("Process %s invoked bpf(%s). Context: %s",
			comm, cmdName, procContext)
	}

	event := SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  priority,
		Rule:      rule,
		Source:    "syscall",
		Category:  "kernel",
		Output:    output,
		Tags:      tags,
		Process:   procInfo,
		RawFields: map[string]interface{}{
			"timestamp_ns": bpfEvent.TimestampNs,
			"event_type":   bpfEvent.EventType,
			"bpf_cmd":      bpfEvent.Cmd,
			"bpf_cmd_name": cmdName,
			"prog_type":    bpfEvent.ProgType,
			"insn_cnt":     bpfEvent.InsnCnt,
			"attach_type":  bpfEvent.AttachType,
			"obj_name":     objName,
			"gid":          bpfEvent.Gid,
		},
	}

	return event, nil
}

// bpfCmdName returns a human-readable name for a BPF command

// bpfCmdName returns a human-readable name for a BPF command
func bpfCmdName(cmd uint32) string {
	switch cmd {
	case 0:
		return "BPF_MAP_CREATE"
	case 1:
		return "BPF_MAP_LOOKUP_ELEM"
	case 2:
		return "BPF_MAP_UPDATE_ELEM"
	case 3:
		return "BPF_MAP_DELETE_ELEM"
	case 4:
		return "BPF_MAP_GET_NEXT_KEY"
	case 5:
		return "BPF_PROG_LOAD"
	case 6:
		return "BPF_OBJ_PIN"
	case 7:
		return "BPF_OBJ_GET"
	case 8:
		return "BPF_PROG_ATTACH"
	case 9:
		return "BPF_PROG_DETACH"
	case 17:
		return "BPF_RAW_TRACEPOINT_OPEN"
	case 18:
		return "BPF_BTF_LOAD"
	case 28:
		return "BPF_LINK_CREATE"
	case 29:
		return "BPF_LINK_UPDATE"
	case 35:
		return "BPF_PROG_BIND_MAP"
	default:
		return fmt.Sprintf("BPF_CMD_%d", cmd)
	}
}

// bpfProgTypeName returns a human-readable name for a BPF program type

// bpfProgTypeName returns a human-readable name for a BPF program type
func bpfProgTypeName(pt uint32) string {
	switch pt {
	case 0:
		return "UNSPEC"
	case 1:
		return "SOCKET_FILTER"
	case 2:
		return "KPROBE"
	case 3:
		return "SCHED_CLS"
	case 4:
		return "SCHED_ACT"
	case 5:
		return "TRACEPOINT"
	case 6:
		return "XDP"
	case 7:
		return "PERF_EVENT"
	case 8:
		return "CGROUP_SKB"
	case 9:
		return "CGROUP_SOCK"
	case 10:
		return "LWT_IN"
	case 14:
		return "RAW_TRACEPOINT"
	case 22:
		return "LSM"
	case 26:
		return "TRACING"
	case 29:
		return "SYSCALL"
	default:
		return fmt.Sprintf("TYPE_%d", pt)
	}
}

// bpfMapTypeName returns a human-readable name for a BPF map type

// bpfMapTypeName returns a human-readable name for a BPF map type
func bpfMapTypeName(mt uint32) string {
	switch mt {
	case 0:
		return "UNSPEC"
	case 1:
		return "HASH"
	case 2:
		return "ARRAY"
	case 3:
		return "PROG_ARRAY"
	case 4:
		return "PERF_EVENT_ARRAY"
	case 5:
		return "PERCPU_HASH"
	case 6:
		return "PERCPU_ARRAY"
	case 9:
		return "LRU_HASH"
	case 10:
		return "LRU_PERCPU_HASH"
	case 12:
		return "HASH_OF_MAPS"
	case 13:
		return "ARRAY_OF_MAPS"
	case 27:
		return "RINGBUF"
	default:
		return fmt.Sprintf("MAP_TYPE_%d", mt)
	}
}

// bpfAttachTypeName returns a human-readable name for a BPF attach type

// bpfAttachTypeName returns a human-readable name for a BPF attach type
func bpfAttachTypeName(at uint32) string {
	switch at {
	case 0:
		return "NONE"
	case 1:
		return "CGROUP_INET_INGRESS"
	case 2:
		return "CGROUP_INET_EGRESS"
	case 5:
		return "CGROUP_SOCK_OPS"
	case 24:
		return "TRACE_RAW_TP"
	case 26:
		return "TRACE_FENTRY"
	case 27:
		return "TRACE_FEXIT"
	case 29:
		return "LSM_MAC"
	default:
		return fmt.Sprintf("ATTACH_%d", at)
	}
}

// readMemfdEvents reads events from the memfd/execveat ring buffer

// parseMemfdEvent converts a raw memfd/execveat BPF event to a SecurityEvent
func (a *NativeEBPFAgent) parseMemfdEvent(data []byte) (SecurityEvent, error) {
	var bpfEvent bpfgen.MemfdEvent

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.TimestampNs); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.EventType); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Pid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Ppid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Uid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Gid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Comm); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Name); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read name: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Flags); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read flags: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Fd); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read fd: %w", err)
	}

	comm := int8ArrayToString(bpfEvent.Comm[:])
	name := int8ArrayToString(bpfEvent.Name[:])

	// Build process info and enrich
	procInfo := ProcessInfo{
		PID:  int(bpfEvent.Pid),
		PPID: int(bpfEvent.Ppid),
		Name: comm,
		UID:  int(bpfEvent.Uid),
	}
	EnrichProcessInfo(&procInfo)
	procContext := GetProcessContext(&procInfo)

	var rule, output, category string
	var priority PriorityLevel
	var tags []string

	switch bpfEvent.EventType {
	case EventTypeMemfdCreate:
		rule = "Memfd Create"
		category = "process"
		tags = []string{"process", "fileless", "memfd"}
		flagStr := memfdFlagsString(bpfEvent.Flags)

		// MFD_ALLOW_SEALING is a strong indicator of fileless execution prep
		if bpfEvent.Flags&0x0002 != 0 { // MFD_ALLOW_SEALING
			priority = PriorityWarning
			tags = append(tags, "defense_evasion")
		} else {
			priority = PriorityNotice
		}

		if name == "" {
			name = "<anonymous>"
		}
		output = fmt.Sprintf("Process %s created memory-backed file %q (flags=%s). Context: %s",
			comm, name, flagStr, procContext)

	case EventTypeExecveat:
		rule = "Execveat"
		category = "process"
		tags = []string{"process", "execution"}

		isEmptyPath := bpfEvent.Flags&0x1000 != 0 // AT_EMPTY_PATH

		if isEmptyPath {
			// AT_EMPTY_PATH + fd = fileless execution (smoking gun)
			priority = PriorityCritical
			rule = "Fileless Execution (execveat AT_EMPTY_PATH)"
			tags = append(tags, "fileless", "defense_evasion", "execution")
			output = fmt.Sprintf("Process %s executed from fd=%d via execveat(AT_EMPTY_PATH) — fileless execution detected. Context: %s",
				comm, bpfEvent.Fd, procContext)
		} else {
			priority = PriorityNotice
			if name == "" {
				name = "<empty>"
			}
			output = fmt.Sprintf("Process %s called execveat(fd=%d, path=%q, flags=0x%x). Context: %s",
				comm, bpfEvent.Fd, name, bpfEvent.Flags, procContext)
		}

	default:
		return SecurityEvent{}, fmt.Errorf("unknown memfd event type: %d", bpfEvent.EventType)
	}

	event := SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  priority,
		Rule:      rule,
		Source:    "syscall",
		Category:  category,
		Output:    output,
		Tags:      tags,
		Process:   procInfo,
		RawFields: map[string]interface{}{
			"timestamp_ns": bpfEvent.TimestampNs,
			"event_type":   bpfEvent.EventType,
			"name":         name,
			"flags":        bpfEvent.Flags,
			"fd":           bpfEvent.Fd,
			"gid":          bpfEvent.Gid,
		},
	}

	return event, nil
}

// memfdFlagsString returns a human-readable string of memfd_create flags

// memfdFlagsString returns a human-readable string of memfd_create flags
func memfdFlagsString(flags uint32) string {
	if flags == 0 {
		return "0"
	}
	var parts []string
	if flags&0x0001 != 0 {
		parts = append(parts, "MFD_CLOEXEC")
	}
	if flags&0x0002 != 0 {
		parts = append(parts, "MFD_ALLOW_SEALING")
	}
	if flags&0x0004 != 0 {
		parts = append(parts, "MFD_HUGETLB")
	}
	if flags&0x0008 != 0 {
		parts = append(parts, "MFD_NOEXEC_SEAL")
	}
	if flags&0x0010 != 0 {
		parts = append(parts, "MFD_EXEC")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("0x%x", flags)
	}
	return strings.Join(parts, "|")
}

// readIouringEvents reads events from the io_uring ring buffer

// parseIouringEvent converts a raw io_uring BPF event to a SecurityEvent
func (a *NativeEBPFAgent) parseIouringEvent(data []byte) (SecurityEvent, error) {
	var bpfEvent bpfgen.IouringEvent

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.TimestampNs); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.EventType); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Pid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Ppid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Uid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Gid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Comm); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.SqEntries); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read sq_entries: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.SetupFlags); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read setup_flags: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Fd); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read fd: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.Opcode); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read opcode: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &bpfEvent.NrArgs); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read nr_args: %w", err)
	}

	comm := int8ArrayToString(bpfEvent.Comm[:])

	// Build process info and enrich
	procInfo := ProcessInfo{
		PID:  int(bpfEvent.Pid),
		PPID: int(bpfEvent.Ppid),
		Name: comm,
		UID:  int(bpfEvent.Uid),
	}
	EnrichProcessInfo(&procInfo)
	procContext := GetProcessContext(&procInfo)

	var rule, output string
	var priority PriorityLevel
	tags := []string{"kernel", "io_uring", "seccomp_bypass"}

	switch bpfEvent.EventType {
	case EventTypeIoUringSetup:
		rule = "io_uring Setup"
		flagStr := iouringSetupFlagsString(bpfEvent.SetupFlags)

		// SQPOLL mode is particularly suspicious - creates kernel polling thread
		if bpfEvent.SetupFlags&0x02 != 0 { // IORING_SETUP_SQPOLL
			priority = PriorityCritical
			tags = append(tags, "defense_evasion")
			output = fmt.Sprintf("Process %s created io_uring with SQPOLL (entries=%d, flags=%s) — kernel polling thread enables stealthy operations. Context: %s",
				comm, bpfEvent.SqEntries, flagStr, procContext)
		} else {
			priority = PriorityWarning
			output = fmt.Sprintf("Process %s created io_uring instance (entries=%d, flags=%s). Context: %s",
				comm, bpfEvent.SqEntries, flagStr, procContext)
		}

	case EventTypeIoUringRegister:
		rule = "io_uring Register"
		opName := iouringRegisterOpName(bpfEvent.Opcode)
		priority = PriorityNotice
		output = fmt.Sprintf("Process %s registered io_uring resource (fd=%d, op=%s, nr_args=%d). Context: %s",
			comm, bpfEvent.Fd, opName, bpfEvent.NrArgs, procContext)

	default:
		return SecurityEvent{}, fmt.Errorf("unknown io_uring event type: %d", bpfEvent.EventType)
	}

	event := SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  priority,
		Rule:      rule,
		Source:    "syscall",
		Category:  "kernel",
		Output:    output,
		Tags:      tags,
		Process:   procInfo,
		RawFields: map[string]interface{}{
			"timestamp_ns": bpfEvent.TimestampNs,
			"event_type":   bpfEvent.EventType,
			"sq_entries":   bpfEvent.SqEntries,
			"setup_flags":  bpfEvent.SetupFlags,
			"fd":           bpfEvent.Fd,
			"opcode":       bpfEvent.Opcode,
			"nr_args":      bpfEvent.NrArgs,
			"gid":          bpfEvent.Gid,
		},
	}

	return event, nil
}

// iouringSetupFlagsString returns a human-readable string of io_uring_setup flags

// iouringSetupFlagsString returns a human-readable string of io_uring_setup flags
func iouringSetupFlagsString(flags uint32) string {
	if flags == 0 {
		return "0"
	}
	var parts []string
	if flags&0x01 != 0 {
		parts = append(parts, "IOPOLL")
	}
	if flags&0x02 != 0 {
		parts = append(parts, "SQPOLL")
	}
	if flags&0x04 != 0 {
		parts = append(parts, "SQ_AFF")
	}
	if flags&0x08 != 0 {
		parts = append(parts, "CQSIZE")
	}
	if flags&0x10 != 0 {
		parts = append(parts, "CLAMP")
	}
	if flags&0x20 != 0 {
		parts = append(parts, "ATTACH_WQ")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("0x%x", flags)
	}
	return strings.Join(parts, "|")
}

// iouringRegisterOpName returns a human-readable name for an io_uring_register opcode

// iouringRegisterOpName returns a human-readable name for an io_uring_register opcode
func iouringRegisterOpName(op uint32) string {
	switch op {
	case 0:
		return "REGISTER_BUFFERS"
	case 1:
		return "UNREGISTER_BUFFERS"
	case 2:
		return "REGISTER_FILES"
	case 3:
		return "UNREGISTER_FILES"
	case 4:
		return "REGISTER_EVENTFD"
	case 5:
		return "UNREGISTER_EVENTFD"
	case 6:
		return "REGISTER_FILES_UPDATE"
	case 7:
		return "REGISTER_EVENTFD_ASYNC"
	case 8:
		return "REGISTER_PROBE"
	case 9:
		return "REGISTER_PERSONALITY"
	case 10:
		return "UNREGISTER_PERSONALITY"
	case 11:
		return "REGISTER_RESTRICTIONS"
	case 12:
		return "REGISTER_ENABLE_RINGS"
	case 15:
		return "REGISTER_IOWQ_AFF"
	case 16:
		return "UNREGISTER_IOWQ_AFF"
	case 17:
		return "REGISTER_IOWQ_MAX_WORKERS"
	case 22:
		return "REGISTER_PBUF_RING"
	case 23:
		return "UNREGISTER_PBUF_RING"
	default:
		return fmt.Sprintf("OP_%d", op)
	}
}

// ============================================================================
// Namespace event reader and parser
// ============================================================================

// CLONE_NEW* flag constants (must match linux/sched.h)
const (
	cloneNewNS     = 0x00020000
	cloneNewCgroup = 0x02000000
	cloneNewUTS    = 0x04000000
	cloneNewIPC    = 0x08000000
	cloneNewUser   = 0x10000000
	cloneNewPID    = 0x20000000
	cloneNewNet    = 0x40000000
	cloneNewTime   = 0x00000080
)

// cloneNsFlagsString converts CLONE_NEW* flags to a human-readable string

// cloneNsFlagsString converts CLONE_NEW* flags to a human-readable string
func cloneNsFlagsString(flags uint64) string {
	var parts []string
	if flags&cloneNewNS != 0 {
		parts = append(parts, "CLONE_NEWNS")
	}
	if flags&cloneNewCgroup != 0 {
		parts = append(parts, "CLONE_NEWCGROUP")
	}
	if flags&cloneNewUTS != 0 {
		parts = append(parts, "CLONE_NEWUTS")
	}
	if flags&cloneNewIPC != 0 {
		parts = append(parts, "CLONE_NEWIPC")
	}
	if flags&cloneNewUser != 0 {
		parts = append(parts, "CLONE_NEWUSER")
	}
	if flags&cloneNewPID != 0 {
		parts = append(parts, "CLONE_NEWPID")
	}
	if flags&cloneNewNet != 0 {
		parts = append(parts, "CLONE_NEWNET")
	}
	if flags&cloneNewTime != 0 {
		parts = append(parts, "CLONE_NEWTIME")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "|")
}

// nstypeString converts a namespace type constant to a human-readable string

// nstypeString converts a namespace type constant to a human-readable string
func nstypeString(nstype uint32) string {
	switch nstype {
	case 0:
		return "auto" // 0 means kernel auto-detects from fd
	default:
		// nstype uses the same CLONE_NEW* constants
		return cloneNsFlagsString(uint64(nstype))
	}
}

// readNamespaceEvents reads events from the namespace ring buffer

// parseNamespaceEvent converts a raw namespace BPF event to a SecurityEvent
func (a *NativeEBPFAgent) parseNamespaceEvent(data []byte) (SecurityEvent, error) {
	reader := bytes.NewReader(data)

	var timestampNs uint64
	var eventType, pid, ppid, uid, gid uint32
	var comm [16]int8
	var fd int32
	var nstype uint32
	var flags uint64
	var retCode int32

	if err := binary.Read(reader, binary.LittleEndian, &timestampNs); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &eventType); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &pid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &ppid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &uid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &gid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &comm); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &fd); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read fd: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &nstype); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read nstype: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &flags); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read flags: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &retCode); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ret_code: %w", err)
	}

	commStr := int8ArrayToString(comm[:])

	procInfo := ProcessInfo{
		PID:  int(pid),
		PPID: int(ppid),
		Name: commStr,
		UID:  int(uid),
	}
	EnrichProcessInfo(&procInfo)

	procContext := GetProcessContext(&procInfo)

	var rule, output string
	var tags []string
	priority := PriorityWarning // Namespace operations are always security-significant

	rawFields := map[string]interface{}{
		"timestamp_ns": timestampNs,
		"event_type":   eventType,
		"gid":          gid,
		"ret_code":     retCode,
	}

	switch eventType {
	case EventTypeSetns:
		nstypeStr := nstypeString(nstype)
		rule = "Namespace Switch"
		tags = []string{"namespace", "setns", "container_security"}
		output = fmt.Sprintf("Process switched namespace via setns(fd=%d, nstype=%s). Context: %s",
			fd, nstypeStr, procContext)
		rawFields["fd"] = fd
		rawFields["nstype"] = nstype
		rawFields["nstype_str"] = nstypeStr

		// setns to PID or mount namespace is a strong container escape indicator
		if nstype == 0 || nstype&(cloneNewPID|cloneNewNS) != 0 {
			priority = PriorityError
			tags = append(tags, "container_escape")
			output += " [POTENTIAL CONTAINER ESCAPE]"
		}

	case EventTypeUnshare:
		flagsStr := cloneNsFlagsString(flags)
		rule = "Namespace Unshare"
		tags = []string{"namespace", "unshare", "container_security"}
		output = fmt.Sprintf("Process created new namespace(s) via unshare(flags=%s). Context: %s",
			flagsStr, procContext)
		rawFields["flags"] = flags
		rawFields["flags_str"] = flagsStr

		// CLONE_NEWUSER allows privilege escalation in the new namespace
		if flags&cloneNewUser != 0 {
			priority = PriorityError
			tags = append(tags, "privilege_escalation")
			output += " [USER NAMESPACE - POTENTIAL PRIVILEGE ESCALATION]"
		}

	default:
		rule = "Namespace Operation"
		output = fmt.Sprintf("Unknown namespace operation. Context: %s", procContext)
		tags = []string{"namespace"}
	}

	event := SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  priority,
		Rule:      rule,
		Source:    "syscall",
		Category:  "namespace",
		Output:    output,
		Tags:      tags,
		Process:   procInfo,
		RawFields: rawFields,
	}

	return event, nil
}

// ============================================================================
// Capability event reader and parser
// ============================================================================

// Linux capability constants (from include/uapi/linux/capability.h)
const (
	capChown          = 0
	capDacOverride    = 1
	capDacReadSearch  = 2
	capFowner         = 3
	capFsetid         = 4
	capKill           = 5
	capSetgid         = 6
	capSetuid         = 7
	capSetpcap        = 8
	capNetBindService = 10
	capNetBroadcast   = 11
	capNetAdmin       = 12
	capNetRaw         = 13
	capSysModule      = 16
	capSysRawio       = 17
	capSysPtrace      = 19
	capSysAdmin       = 21
	capSysBoot        = 22
	capSysResource    = 24
	capSysTime        = 25
	capMknod          = 27
	capAuditControl   = 30
	capAuditWrite     = 29
	capSyslog         = 34
	capPerfmon        = 38
	capBpf            = 39
	capCheckpointRestore = 40
)

// dangerousCapabilities are capabilities that indicate significant security impact
var dangerousCapabilities = map[int]string{
	capSysAdmin:    "CAP_SYS_ADMIN",
	capNetAdmin:    "CAP_NET_ADMIN",
	capNetRaw:      "CAP_NET_RAW",
	capSysModule:   "CAP_SYS_MODULE",
	capSysPtrace:   "CAP_SYS_PTRACE",
	capSysRawio:    "CAP_SYS_RAWIO",
	capSysBoot:     "CAP_SYS_BOOT",
	capDacOverride: "CAP_DAC_OVERRIDE",
	capSetuid:      "CAP_SETUID",
	capSetgid:      "CAP_SETGID",
	capBpf:         "CAP_BPF",
	capPerfmon:     "CAP_PERFMON",
	capAuditControl: "CAP_AUDIT_CONTROL",
}

// capBitmaskToNames converts a capability bitmask to a list of capability names

// capBitmaskToNames converts a capability bitmask to a list of capability names
func capBitmaskToNames(caps uint64) []string {
	var names []string
	for bit := 0; bit < 64; bit++ {
		if caps&(1<<uint(bit)) != 0 {
			if name, ok := dangerousCapabilities[bit]; ok {
				names = append(names, name)
			}
		}
	}
	return names
}

// hasDangerousCaps returns true if the capability bitmask contains any dangerous capabilities

// hasDangerousCaps returns true if the capability bitmask contains any dangerous capabilities
func hasDangerousCaps(caps uint64) bool {
	for bit := range dangerousCapabilities {
		if caps&(1<<uint(bit)) != 0 {
			return true
		}
	}
	return false
}

// readCapsEvents reads events from the capability ring buffer

// parseCapsEvent converts a raw capability BPF event to a SecurityEvent
func (a *NativeEBPFAgent) parseCapsEvent(data []byte) (SecurityEvent, error) {
	reader := bytes.NewReader(data)

	var timestampNs uint64
	var eventType, pid, ppid, uid, gid uint32
	var comm [16]int8
	var targetPid, capVersion uint32
	var capEffective, capPermitted, capInheritable uint64
	var retCode int32

	if err := binary.Read(reader, binary.LittleEndian, &timestampNs); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &eventType); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &pid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &ppid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &uid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &gid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &comm); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &targetPid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read target_pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &capVersion); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read cap_version: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &capEffective); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read cap_effective: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &capPermitted); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read cap_permitted: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &capInheritable); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read cap_inheritable: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &retCode); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ret_code: %w", err)
	}

	commStr := int8ArrayToString(comm[:])

	procInfo := ProcessInfo{
		PID:  int(pid),
		PPID: int(ppid),
		Name: commStr,
		UID:  int(uid),
	}
	EnrichProcessInfo(&procInfo)

	procContext := GetProcessContext(&procInfo)

	// Identify which dangerous capabilities are being requested
	dangerousEffective := capBitmaskToNames(capEffective)
	dangerousPermitted := capBitmaskToNames(capPermitted)

	rule := "Capability Change"
	tags := []string{"capability", "capset", "privilege"}
	priority := PriorityNotice

	targetStr := "self"
	if targetPid != 0 {
		targetStr = fmt.Sprintf("PID %d", targetPid)
	}

	output := fmt.Sprintf("Process called capset(target=%s, effective=0x%x, permitted=0x%x, inheritable=0x%x). Context: %s",
		targetStr, capEffective, capPermitted, capInheritable, procContext)

	// Escalate priority based on dangerous capabilities
	if hasDangerousCaps(capEffective) {
		priority = PriorityWarning
		rule = "Dangerous Capability Change"
		tags = append(tags, "dangerous_caps")
		output += fmt.Sprintf(" [DANGEROUS CAPS: %s]", strings.Join(dangerousEffective, ", "))

		// CAP_SYS_ADMIN is the most dangerous — essentially root equivalent
		if capEffective&(1<<capSysAdmin) != 0 {
			priority = PriorityError
			tags = append(tags, "sys_admin")
		}
	}

	if hasDangerousCaps(capPermitted) && !hasDangerousCaps(capEffective) {
		// Permitted but not effective — process is staging for future escalation
		tags = append(tags, "staged_escalation")
		if len(dangerousPermitted) > 0 {
			output += fmt.Sprintf(" [STAGED: %s]", strings.Join(dangerousPermitted, ", "))
		}
	}

	event := SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  priority,
		Rule:      rule,
		Source:    "syscall",
		Category:  "capability",
		Output:    output,
		Tags:      tags,
		Process:   procInfo,
		RawFields: map[string]interface{}{
			"timestamp_ns":    timestampNs,
			"event_type":      eventType,
			"target_pid":      targetPid,
			"cap_version":     capVersion,
			"cap_effective":   capEffective,
			"cap_permitted":   capPermitted,
			"cap_inheritable": capInheritable,
			"gid":             gid,
			"ret_code":        retCode,
		},
	}

	return event, nil
}

// readDataexfilEvents reads events from the data exfiltration ring buffer

// parseDataexfilEvent converts a raw data exfiltration BPF event to a SecurityEvent
func (a *NativeEBPFAgent) parseDataexfilEvent(data []byte) (SecurityEvent, error) {
	reader := bytes.NewReader(data)

	var timestampNs uint64
	var eventType, pid, ppid, uid, gid uint32
	var comm [16]int8
	var fdIn, fdOut int32
	var dataLen uint64
	var flags uint32
	var retCode int32

	if err := binary.Read(reader, binary.LittleEndian, &timestampNs); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &eventType); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &pid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &ppid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &uid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &gid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &comm); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &fdIn); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read fd_in: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &fdOut); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read fd_out: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &dataLen); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read len: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &flags); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read flags: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &retCode); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ret_code: %w", err)
	}

	commStr := int8ArrayToString(comm[:])

	procInfo := ProcessInfo{
		PID:  int(pid),
		PPID: int(ppid),
		Name: commStr,
		UID:  int(uid),
	}
	EnrichProcessInfo(&procInfo)
	procContext := GetProcessContext(&procInfo)

	var rule, output string
	var priority PriorityLevel
	tags := []string{"file", "data_transfer"}

	syscallName := "unknown"
	switch eventType {
	case EventTypeSplice:
		syscallName = "splice"
	case EventTypeSendfile:
		syscallName = "sendfile"
	case EventTypeCopyFileRange:
		syscallName = "copy_file_range"
	case EventTypeTee:
		syscallName = "tee"
	default:
		return SecurityEvent{}, fmt.Errorf("unknown dataexfil event type: %d", eventType)
	}

	rule = "Data Transfer via " + strings.ToUpper(syscallName[:1]) + syscallName[1:]

	// Large transfers are higher priority
	if dataLen > 10*1024*1024 { // > 10MB
		priority = PriorityWarning
		tags = append(tags, "exfiltration")
		output = fmt.Sprintf("Process %s performed large data transfer via %s (fd_in=%d, fd_out=%d, len=%d bytes, flags=0x%x). Context: %s",
			commStr, syscallName, fdIn, fdOut, dataLen, flags, procContext)
	} else {
		priority = PriorityNotice
		output = fmt.Sprintf("Process %s called %s (fd_in=%d, fd_out=%d, len=%d bytes, flags=0x%x). Context: %s",
			commStr, syscallName, fdIn, fdOut, dataLen, flags, procContext)
	}

	event := SecurityEvent{
		UUID:      xid.New().String(),
		Timestamp: time.Now(),
		Rule:      rule,
		Priority:  priority,
		Source:    "syscall",
		Category:  "file",
		Output:    output,
		Tags:      tags,
		Process:   procInfo,
		RawFields: map[string]interface{}{
			"timestamp_ns": timestampNs,
			"event_type":   eventType,
			"syscall":      syscallName,
			"fd_in":        fdIn,
			"fd_out":       fdOut,
			"len":          dataLen,
			"flags":        flags,
			"gid":          gid,
			"ret_code":     retCode,
		},
	}

	return event, nil
}

// readDiropsEvents reads events from the directory operations ring buffer

// parseDiropsEvent converts a raw directory operations BPF event to a SecurityEvent
func (a *NativeEBPFAgent) parseDiropsEvent(data []byte) (SecurityEvent, error) {
	reader := bytes.NewReader(data)

	var timestampNs uint64
	var eventType, pid, ppid, uid, gid uint32
	var comm [16]int8
	var path [256]int8
	var path2 [256]int8
	var fd int32
	var retCode int32

	if err := binary.Read(reader, binary.LittleEndian, &timestampNs); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &eventType); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &pid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &ppid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &uid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &gid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &comm); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &path); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read path: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &path2); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read path2: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &fd); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read fd: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &retCode); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ret_code: %w", err)
	}

	commStr := int8ArrayToString(comm[:])
	pathStr := int8ArrayToString(path[:])
	path2Str := int8ArrayToString(path2[:])

	procInfo := ProcessInfo{
		PID:  int(pid),
		PPID: int(ppid),
		Name: commStr,
		UID:  int(uid),
	}
	EnrichProcessInfo(&procInfo)
	procContext := GetProcessContext(&procInfo)

	var rule, output string
	var priority PriorityLevel
	tags := []string{"filesystem", "directory"}

	switch eventType {
	case EventTypeChdir:
		rule = "Directory Change (chdir)"
		priority = PriorityNotice
		output = fmt.Sprintf("Process %s changed directory to %q. Context: %s", commStr, pathStr, procContext)

	case EventTypeFchdir:
		rule = "Directory Change (fchdir)"
		priority = PriorityNotice
		output = fmt.Sprintf("Process %s changed directory via fd=%d. Context: %s", commStr, fd, procContext)

	case EventTypeChroot:
		rule = "Filesystem Root Change (chroot)"
		priority = PriorityWarning
		tags = append(tags, "container_escape", "sandbox_evasion")
		output = fmt.Sprintf("Process %s called chroot(%q) — potential sandbox escape. Context: %s", commStr, pathStr, procContext)

	case EventTypePivotRoot:
		rule = "Filesystem Root Change (pivot_root)"
		priority = PriorityCritical
		tags = append(tags, "container_escape", "sandbox_evasion")
		output = fmt.Sprintf("Process %s called pivot_root(new=%q, old=%q) — potential container escape. Context: %s",
			commStr, pathStr, path2Str, procContext)

	default:
		return SecurityEvent{}, fmt.Errorf("unknown dirops event type: %d", eventType)
	}

	event := SecurityEvent{
		UUID:      xid.New().String(),
		Timestamp: time.Now(),
		Rule:      rule,
		Priority:  priority,
		Source:    "syscall",
		Category:  "filesystem",
		Output:    output,
		Tags:      tags,
		Process:   procInfo,
		RawFields: map[string]interface{}{
			"timestamp_ns": timestampNs,
			"event_type":   eventType,
			"path":         pathStr,
			"path2":        path2Str,
			"fd":           fd,
			"gid":          gid,
			"ret_code":     retCode,
		},
	}

	return event, nil
}

// readVfshooksEvents reads events from the VFS hooks kprobe ring buffer

// parseVfshooksEvent converts a raw VFS kprobe event to a SecurityEvent
func (a *NativeEBPFAgent) parseVfshooksEvent(data []byte) (SecurityEvent, error) {
	reader := bytes.NewReader(data)

	var timestampNs uint64
	var eventType, pid, ppid, uid, gid uint32
	var comm [16]int8
	var path [256]int8
	var path2 [256]int8
	var iMode, iUid uint32
	var iIno uint64
	var retCode int32

	if err := binary.Read(reader, binary.LittleEndian, &timestampNs); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &eventType); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &pid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &ppid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &uid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &gid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &comm); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &path); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read path: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &path2); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read path2: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &iMode); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read i_mode: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &iUid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read i_uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &iIno); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read i_ino: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &retCode); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ret_code: %w", err)
	}

	commStr := int8ArrayToString(comm[:])
	pathStr := int8ArrayToString(path[:])
	path2Str := int8ArrayToString(path2[:])

	procInfo := ProcessInfo{
		PID:  int(pid),
		PPID: int(ppid),
		Name: commStr,
		UID:  int(uid),
	}
	EnrichProcessInfo(&procInfo)
	procContext := GetProcessContext(&procInfo)

	var rule, output string
	var priority PriorityLevel
	tags := []string{"file", "vfs", "kprobe"}

	switch eventType {
	case EventTypeVfsOpen:
		rule = "VFS File Open"
		priority = PriorityNotice
		output = fmt.Sprintf("Process %s opened %q (inode=%d, mode=0%o). Context: %s",
			commStr, pathStr, iIno, iMode, procContext)

	case EventTypeVfsUnlink:
		rule = "VFS File Delete"
		priority = PriorityNotice
		output = fmt.Sprintf("Process %s deleted %q (inode=%d, owner_uid=%d). Context: %s",
			commStr, pathStr, iIno, iUid, procContext)

	case EventTypeVfsRename:
		rule = "VFS File Rename"
		priority = PriorityNotice
		output = fmt.Sprintf("Process %s renamed %q -> %q (inode=%d). Context: %s",
			commStr, pathStr, path2Str, iIno, procContext)

	case EventTypeInodeSetattr:
		rule = "VFS Attribute Change"
		priority = PriorityNotice
		output = fmt.Sprintf("Process %s changed attributes on %q (inode=%d, mode=0%o). Context: %s",
			commStr, pathStr, iIno, iMode, procContext)

	default:
		return SecurityEvent{}, fmt.Errorf("unknown VFS event type: %d", eventType)
	}

	event := SecurityEvent{
		UUID:      xid.New().String(),
		Timestamp: time.Now(),
		Rule:      rule,
		Priority:  priority,
		Source:    "kprobe",
		Category:  "file",
		Output:    output,
		Tags:      tags,
		Process:   procInfo,
		RawFields: map[string]interface{}{
			"timestamp_ns": timestampNs,
			"event_type":   eventType,
			"path":         pathStr,
			"path2":        path2Str,
			"i_mode":       iMode,
			"i_uid":        iUid,
			"i_ino":        iIno,
			"gid":          gid,
			"ret_code":     retCode,
		},
	}

	return event, nil
}

// readCredhooksEvents reads events from the credential hooks kprobe ring buffer

// parseCredhooksEvent converts a raw credential kprobe event to a SecurityEvent
func (a *NativeEBPFAgent) parseCredhooksEvent(data []byte) (SecurityEvent, error) {
	reader := bytes.NewReader(data)

	var timestampNs uint64
	var eventType, pid, ppid, uid, gid uint32
	var comm [16]int8
	var newUid, newEuid, newGid, newEgid uint32
	var exitCode, retCode int32

	if err := binary.Read(reader, binary.LittleEndian, &timestampNs); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &eventType); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &pid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &ppid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &uid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &gid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &comm); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &newUid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read new_uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &newEuid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read new_euid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &newGid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read new_gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &newEgid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read new_egid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &exitCode); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read exit_code: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &retCode); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ret_code: %w", err)
	}

	commStr := int8ArrayToString(comm[:])

	procInfo := ProcessInfo{
		PID:  int(pid),
		PPID: int(ppid),
		Name: commStr,
		UID:  int(uid),
	}
	EnrichProcessInfo(&procInfo)
	procContext := GetProcessContext(&procInfo)

	var rule, output string
	var priority PriorityLevel
	var tags []string

	switch eventType {
	case EventTypeCommitCreds:
		tags = []string{"privilege", "credential", "kprobe"}

		// Privilege escalation: non-root becoming root
		if uid != 0 && (newEuid == 0 || newUid == 0) {
			rule = "Credential Change — Privilege Escalation"
			priority = PriorityWarning
			output = fmt.Sprintf("Process %s escalated privileges (uid=%d->%d, euid=%d->%d, gid=%d->%d). Context: %s",
				commStr, uid, newUid, uid, newEuid, gid, newGid, procContext)
		} else {
			rule = "Credential Change"
			priority = PriorityNotice
			output = fmt.Sprintf("Process %s changed credentials (uid=%d->%d, euid->%d, gid=%d->%d). Context: %s",
				commStr, uid, newUid, newEuid, gid, newGid, procContext)
		}

	case EventTypeProcessExit:
		tags = []string{"process", "lifecycle", "kprobe"}
		// Exit code format: bits 0-7 = signal, bits 8-15 = exit status
		sig := exitCode & 0x7f
		status := (exitCode >> 8) & 0xff

		if sig > 0 {
			rule = "Process Exit — Signal"
			if sig == 9 || sig == 11 || sig == 6 { // SIGKILL, SIGSEGV, SIGABRT
				priority = PriorityWarning
				tags = append(tags, "crash")
			} else {
				priority = PriorityNotice
			}
			output = fmt.Sprintf("Process %s (pid=%d) killed by signal %d. Context: %s",
				commStr, pid, sig, procContext)
		} else {
			rule = "Process Exit"
			priority = PriorityNotice
			output = fmt.Sprintf("Process %s (pid=%d) exited with status %d. Context: %s",
				commStr, pid, status, procContext)
		}

	default:
		return SecurityEvent{}, fmt.Errorf("unknown credential event type: %d", eventType)
	}

	event := SecurityEvent{
		UUID:      xid.New().String(),
		Timestamp: time.Now(),
		Rule:      rule,
		Priority:  priority,
		Source:    "kprobe",
		Category:  tags[0],
		Output:    output,
		Tags:      tags,
		Process:   procInfo,
		RawFields: map[string]interface{}{
			"timestamp_ns": timestampNs,
			"event_type":   eventType,
			"new_uid":      newUid,
			"new_euid":     newEuid,
			"new_gid":      newGid,
			"new_egid":     newEgid,
			"exit_code":    exitCode,
			"gid":          gid,
			"ret_code":     retCode,
		},
	}

	return event, nil
}

// readIoctlEvents reads events from the ioctl ring buffer

// parseIoctlEvent converts raw ioctl event bytes to a SecurityEvent
func (a *NativeEBPFAgent) parseIoctlEvent(data []byte) (SecurityEvent, error) {
	if len(data) < 48 {
		return SecurityEvent{}, fmt.Errorf("ioctl event too short: %d bytes", len(data))
	}

	reader := bytes.NewReader(data)
	var timestampNs uint64
	var eventType uint32
	var pid, ppid, uid, gid uint32
	var comm [16]int8
	var fd int32
	var cmd uint32
	var arg uint64
	var retCode int32

	if err := binary.Read(reader, binary.LittleEndian, &timestampNs); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &eventType); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read event_type: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &pid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read pid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &ppid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ppid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &uid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read uid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &gid); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read gid: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &comm); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read comm: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &fd); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read fd: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &cmd); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read cmd: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &arg); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read arg: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &retCode); err != nil {
		return SecurityEvent{}, fmt.Errorf("failed to read ret_code: %w", err)
	}

	commStr := int8ArrayToString(comm[:])

	// Map ioctl command to human-readable name
	var cmdName string
	priority := PriorityWarning
	tags := []string{"ioctl"}

	switch cmd {
	case 0x5412: // TIOCSTI
		cmdName = "TIOCSTI (terminal injection)"
		priority = PriorityCritical
		tags = append(tags, "terminal_injection", "tiocsti")
	case 0x5414: // TIOCSWINSZ
		cmdName = "TIOCSWINSZ (window size change)"
		tags = append(tags, "terminal")
	case 0x541C: // TIOCLINUX
		cmdName = "TIOCLINUX"
		priority = PriorityCritical
		tags = append(tags, "terminal_escape")
	case 0x4B32: // KDSETLED
		cmdName = "KDSETLED"
		tags = append(tags, "keyboard")
	case 0x4C00: // LOOP_SET_FD
		cmdName = "LOOP_SET_FD (loop device setup)"
		tags = append(tags, "loop_device")
	case 0x4C01: // LOOP_CLR_FD
		cmdName = "LOOP_CLR_FD (loop device teardown)"
		tags = append(tags, "loop_device")
	case 0x4C04: // LOOP_SET_STATUS64
		cmdName = "LOOP_SET_STATUS64"
		tags = append(tags, "loop_device")
	default:
		cmdName = fmt.Sprintf("0x%x", cmd)
	}

	output := fmt.Sprintf("Process %s (pid=%d) issued ioctl %s on fd=%d (arg=0x%x)",
		commStr, pid, cmdName, fd, arg)

	procInfo := ProcessInfo{
		PID:  int(pid),
		PPID: int(ppid),
		Name: commStr,
		UID:  int(uid),
	}
	EnrichProcessInfo(&procInfo)
	procContext := GetProcessContext(&procInfo)

	if procContext != "" {
		output = output + ". Context: " + procContext
	}

	event := SecurityEvent{
		UUID:      xid.New().String(),
		AgentType: AgentTypeNative,
		Timestamp: time.Now(),
		Priority:  priority,
		Rule:      "Security-Relevant Ioctl",
		Source:    "syscall",
		Category:  "ioctl",
		Output:    output,
		Tags:      tags,
		Process:   procInfo,
		RawFields: map[string]interface{}{
			"timestamp_ns": timestampNs,
			"fd":           fd,
			"cmd":          cmd,
			"cmd_name":     cmdName,
			"arg":          arg,
			"ret_code":     retCode,
		},
	}

	return event, nil
}


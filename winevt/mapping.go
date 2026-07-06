// Package winevt turns Windows Event Log records into akagent security
// events. The subscription/reader layer is Windows-only (winevt_windows.go);
// this file is the pure-Go mapping from a parsed event record to an
// ebpf.SecurityEvent, so it builds and unit-tests on any platform.
package winevt

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"akagent/ebpf"

	"github.com/rs/xid"
)

// Record is a parsed Windows event, produced by the platform reader from
// rendered event XML. Fields carry the values we care about across the
// event IDs we map; unused fields stay empty.
type Record struct {
	Channel   string    // "Security", "System", "Application", ...
	Provider  string    // publisher name, e.g. "Microsoft-Windows-Security-Auditing"
	EventID   int       // e.g. 4624
	Level     int       // Windows level (1=critical .. 4=info); 0 if absent
	Timestamp time.Time // event time (system-provided)
	Computer  string

	// EventData name→value pairs, lowercased keys. Populated from the
	// <EventData> section of the rendered event.
	Data map[string]string
}

// get returns the trimmed EventData value for a key (case-insensitive), or "".
func (r *Record) get(key string) string {
	if r.Data == nil {
		return ""
	}
	return strings.TrimSpace(r.Data[strings.ToLower(key)])
}

// MapEvent converts a Windows event record into a SecurityEvent. It returns
// (event, true) for events we care about, and (_, false) for everything
// else so the reader can skip them cheaply. The mapping mirrors the Linux
// engine's category/rule/priority conventions so the backend rules and UI
// treat Windows events uniformly.
func MapEvent(r *Record) (ebpf.SecurityEvent, bool) {
	base := func(rule, category string, prio ebpf.PriorityLevel) ebpf.SecurityEvent {
		return ebpf.SecurityEvent{
			UUID:      xid.New().String(),
			AgentType: ebpf.AgentTypeNative,
			Timestamp: eventTime(r),
			Priority:  prio,
			Rule:      rule,
			Source:    "winevt",
			Category:  category,
			Hostname:  r.Computer,
			RawFields: map[string]interface{}{
				"event_id":       r.EventID,
				"event_channel":  r.Channel,
				"event_provider": r.Provider,
			},
		}
	}

	switch r.EventID {
	// ---- Logons (Security channel) ----
	case 4624: // successful logon
		return mapLogonSuccess(r, base)
	case 4625: // failed logon
		return mapLogonFailure(r, base)
	case 4740: // account locked out
		ev := base("Account Lockout", "auth", ebpf.PriorityWarning)
		user := r.get("TargetUserName")
		ev.Process = ebpf.ProcessInfo{Username: user}
		ev.Output = fmt.Sprintf("Account %q locked out (source %s)", user, r.get("SubjectUserName"))
		ev.RawFields["target_user"] = user
		return ev, true
	case 4672: // special privileges assigned to new logon
		ev := base("Privileged Logon", "privilege", ebpf.PriorityNotice)
		user := r.get("SubjectUserName")
		ev.Process = ebpf.ProcessInfo{Username: user}
		ev.Output = fmt.Sprintf("Privileged logon for %q", user)
		ev.RawFields["user"] = user
		return ev, true

	// ---- Account/group management (Security channel) ----
	case 4720: // user account created
		return mapAccountChange(r, base, "User Account Created", ebpf.PriorityWarning)
	case 4722: // user account enabled
		return mapAccountChange(r, base, "User Account Enabled", ebpf.PriorityNotice)
	case 4726: // user account deleted
		return mapAccountChange(r, base, "User Account Deleted", ebpf.PriorityWarning)
	case 4728, 4732, 4756: // member added to a (global/local/universal) security group
		ev := base("Security Group Member Added", "privilege", ebpf.PriorityWarning)
		member := r.get("MemberName")
		group := r.get("TargetUserName")
		ev.Process = ebpf.ProcessInfo{Username: r.get("SubjectUserName")}
		ev.Output = fmt.Sprintf("%s added to group %q", member, group)
		ev.RawFields["member"] = member
		ev.RawFields["group"] = group
		return ev, true

	// ---- Persistence (Security + System channels) ----
	case 4697: // service installed (Security)
		ev := base("Service Installed", "persistence", ebpf.PriorityWarning)
		name := r.get("ServiceName")
		ev.Process = ebpf.ProcessInfo{Name: name, Cmdline: r.get("ServiceFileName"), Username: r.get("SubjectUserName")}
		ev.Output = fmt.Sprintf("Service %q installed: %s", name, r.get("ServiceFileName"))
		ev.RawFields["service_name"] = name
		ev.RawFields["service_file"] = r.get("ServiceFileName")
		return ev, true
	case 7045: // service installed (System, Service Control Manager)
		ev := base("Service Installed", "persistence", ebpf.PriorityWarning)
		name := r.get("ServiceName")
		ev.Process = ebpf.ProcessInfo{Name: name, Cmdline: r.get("ImagePath")}
		ev.Output = fmt.Sprintf("Service %q installed: %s", name, r.get("ImagePath"))
		ev.RawFields["service_name"] = name
		ev.RawFields["service_file"] = r.get("ImagePath")
		ev.RawFields["start_type"] = r.get("StartType")
		return ev, true
	case 4698: // scheduled task created
		ev := base("Scheduled Task Created", "persistence", ebpf.PriorityWarning)
		task := r.get("TaskName")
		ev.Process = ebpf.ProcessInfo{Name: task, Username: r.get("SubjectUserName")}
		ev.Output = fmt.Sprintf("Scheduled task %q created", task)
		ev.RawFields["task_name"] = task
		return ev, true

	// ---- Process creation (Security channel; requires audit policy) ----
	case 4688:
		return mapProcessCreation(r, base)

	// ---- Defense evasion (Security channel) ----
	case 1102: // audit log cleared
		ev := base("Audit Log Cleared", "defense_evasion", ebpf.PriorityError)
		user := r.get("SubjectUserName")
		ev.Process = ebpf.ProcessInfo{Username: user}
		ev.Output = fmt.Sprintf("Security audit log cleared by %q", user)
		ev.RawFields["user"] = user
		return ev, true

	// ---- Package installs (Application channel, MsiInstaller) ----
	case 11707: // install success
		return mapMsi(r, base, "package_installed", "Software Installed")
	case 11724: // uninstall success
		return mapMsi(r, base, "package_removed", "Software Removed")

	// ---- Defender detections (Defender/Operational channel) ----
	case 1116: // malware detected
		ev := base("Defender Malware Detected", "malware", ebpf.PriorityCritical)
		threat := r.get("Threat Name")
		if threat == "" {
			threat = r.get("ThreatName")
		}
		ev.Output = fmt.Sprintf("Microsoft Defender detected %q", threat)
		ev.RawFields["threat"] = threat
		return ev, true
	case 1117: // action taken on malware
		ev := base("Defender Action Taken", "malware", ebpf.PriorityWarning)
		threat := r.get("Threat Name")
		if threat == "" {
			threat = r.get("ThreatName")
		}
		ev.Output = fmt.Sprintf("Microsoft Defender acted on %q", threat)
		ev.RawFields["threat"] = threat
		return ev, true
	}

	return ebpf.SecurityEvent{}, false
}

func mapLogonSuccess(r *Record, base func(string, string, ebpf.PriorityLevel) ebpf.SecurityEvent) (ebpf.SecurityEvent, bool) {
	logonType := r.get("LogonType")
	user := r.get("TargetUserName")

	// Skip machine accounts and the well-known service/system logons — they
	// are constant background noise on servers.
	if isMachineOrServiceAccount(user) {
		return ebpf.SecurityEvent{}, false
	}

	// Interactive (2), RemoteInteractive/RDP (10), and unlock (7) are the
	// interesting human logons. RDP is the SSH-login analogue and is routed
	// into the session pipeline (see mapRDPSession).
	if logonType == "10" {
		return mapRDPSession(r, base, user)
	}

	ev := base("Windows Logon", "auth", ebpf.PriorityNotice)
	ev.Process = ebpf.ProcessInfo{Username: user}
	ev.Network = ebpf.NetworkInfo{SrcIP: r.get("IpAddress")}
	ev.Output = fmt.Sprintf("Logon (type %s) for %q from %s", logonType, user, r.get("IpAddress"))
	ev.RawFields["logon_type"] = logonType
	ev.RawFields["user"] = user
	ev.RawFields["source_ip"] = r.get("IpAddress")
	return ev, true
}

// mapRDPSession renders an RDP logon as an SSH-session-shaped event so the
// existing ac-012 inbound-login session UI binds without endpoint changes.
// The RawFields deliberately reuse the ssh_* keys the session tracker sets.
func mapRDPSession(r *Record, base func(string, string, ebpf.PriorityLevel) ebpf.SecurityEvent, user string) (ebpf.SecurityEvent, bool) {
	srcIP := r.get("IpAddress")
	logonID := r.get("TargetLogonId")
	sessionID := "rdpsess-" + strings.TrimPrefix(logonID, "0x")

	ev := base(ebpf.RuleSSHInboundLogin, "ssh_session", ebpf.PriorityError)
	ev.UUID = sessionID // stable across re-emit so the API upserts the session
	ev.Source = "session"
	ev.Tags = []string{"ssh_session", "rdp"}
	ev.Process = ebpf.ProcessInfo{Username: user}
	ev.Network = ebpf.NetworkInfo{SrcIP: srcIP}
	ev.Output = fmt.Sprintf("RDP login for %q from %s", user, srcIP)
	ev.Message = ev.Output
	loginTime := eventTime(r).UTC().Format(time.RFC3339)
	ev.RawFields["event_kind"] = "ssh_session"
	ev.RawFields["ssh_login"] = true
	ev.RawFields["ssh_session_id"] = sessionID
	ev.RawFields["status"] = "open"
	ev.RawFields["login_time"] = loginTime
	ev.RawFields["last_activity"] = loginTime
	ev.RawFields["ssh_source_ip"] = srcIP
	ev.RawFields["ssh_username"] = user
	ev.RawFields["session_type"] = "rdp"
	ev.RawFields["logon_id"] = logonID
	return ev, true
}

func mapLogonFailure(r *Record, base func(string, string, ebpf.PriorityLevel) ebpf.SecurityEvent) (ebpf.SecurityEvent, bool) {
	user := r.get("TargetUserName")
	if isMachineOrServiceAccount(user) {
		return ebpf.SecurityEvent{}, false
	}
	ev := base("Windows Logon Failure", "auth", ebpf.PriorityWarning)
	ev.Process = ebpf.ProcessInfo{Username: user}
	ev.Network = ebpf.NetworkInfo{SrcIP: r.get("IpAddress")}
	ev.Output = fmt.Sprintf("Failed logon for %q from %s (status %s)", user, r.get("IpAddress"), r.get("Status"))
	ev.RawFields["user"] = user
	ev.RawFields["source_ip"] = r.get("IpAddress")
	ev.RawFields["logon_type"] = r.get("LogonType")
	ev.RawFields["failure_status"] = r.get("Status")
	return ev, true
}

func mapAccountChange(r *Record, base func(string, string, ebpf.PriorityLevel) ebpf.SecurityEvent, rule string, prio ebpf.PriorityLevel) (ebpf.SecurityEvent, bool) {
	ev := base(rule, "privilege", prio)
	target := r.get("TargetUserName")
	actor := r.get("SubjectUserName")
	ev.Process = ebpf.ProcessInfo{Username: actor}
	ev.Output = fmt.Sprintf("%s: target=%q by=%q", rule, target, actor)
	ev.RawFields["target_user"] = target
	ev.RawFields["actor"] = actor
	return ev, true
}

func mapProcessCreation(r *Record, base func(string, string, ebpf.PriorityLevel) ebpf.SecurityEvent) (ebpf.SecurityEvent, bool) {
	image := r.get("NewProcessName")
	if image == "" {
		return ebpf.SecurityEvent{}, false
	}
	pid := parseHexInt(r.get("NewProcessId"))
	ppid := parseHexInt(r.get("ProcessId"))

	ev := base("Process Execution", "process", ebpf.PriorityInformational)
	ev.Process = ebpf.ProcessInfo{
		PID:        pid,
		PPID:       ppid,
		Name:       baseName(image),
		ExePath:    image,
		Cmdline:    r.get("CommandLine"),
		Username:   r.get("SubjectUserName"),
		ParentExe:  r.get("ParentProcessName"),
		ParentName: baseName(r.get("ParentProcessName")),
	}
	ev.Output = fmt.Sprintf("Process %s started (pid %d)", image, pid)
	ev.RawFields["image"] = image
	ev.RawFields["command_line"] = r.get("CommandLine")
	return ev, true
}

func mapMsi(r *Record, base func(string, string, ebpf.PriorityLevel) ebpf.SecurityEvent, kind, rule string) (ebpf.SecurityEvent, bool) {
	// MsiInstaller 11707/11724 put "Product: <name> -- ..." in a param.
	product := r.get("param1")
	name := extractMsiProduct(product)
	ev := base(rule, "software", ebpf.PriorityNotice)
	ev.Process = ebpf.ProcessInfo{Name: name}
	ev.Output = fmt.Sprintf("%s: %s", rule, name)
	ev.RawFields["event_kind"] = kind
	ev.RawFields["product"] = name
	return ev, true
}

// isMachineOrServiceAccount reports whether a logon username is a computer
// account (ends with "$") or a well-known local service principal.
func isMachineOrServiceAccount(user string) bool {
	if user == "" || user == "-" {
		return true
	}
	if strings.HasSuffix(user, "$") {
		return true
	}
	switch strings.ToUpper(user) {
	case "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "DWM-1", "DWM-2", "UMFD-0", "UMFD-1":
		return true
	}
	return false
}

func eventTime(r *Record) time.Time {
	if r.Timestamp.IsZero() {
		return time.Now()
	}
	return r.Timestamp
}

// parseHexInt parses a Windows hex process id like "0x1a4"; also accepts
// plain decimal. Returns 0 on failure.
func parseHexInt(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		if v, err := strconv.ParseInt(s[2:], 16, 64); err == nil {
			return int(v)
		}
		return 0
	}
	if v, err := strconv.Atoi(s); err == nil {
		return v
	}
	return 0
}

func baseName(path string) string {
	if path == "" {
		return ""
	}
	path = strings.ReplaceAll(path, "/", `\`)
	if i := strings.LastIndex(path, `\`); i >= 0 {
		return path[i+1:]
	}
	return path
}

// extractMsiProduct pulls the product name out of an MsiInstaller message
// param, which looks like "Product: Foo -- Installation completed ...".
func extractMsiProduct(param string) string {
	param = strings.TrimSpace(param)
	param = strings.TrimPrefix(param, "Product: ")
	if i := strings.Index(param, " -- "); i >= 0 {
		return strings.TrimSpace(param[:i])
	}
	return param
}

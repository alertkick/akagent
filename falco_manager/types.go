package falco_manager

import (
	"encoding/json"
	"time"
)

// FalcoRule represents the structure of a Falco rule
type FalcoRule struct {
	Rule       string              `yaml:"rule"`
	Desc       string              `yaml:"desc"`
	Condition  string              `yaml:"condition"`
	Output     string              `yaml:"output"`
	Priority   string              `yaml:"priority"`
	Tags       []string            `yaml:"tags"`
	Source     string              `yaml:"source"`
	Exceptions []map[string]string `yaml:"exceptions,omitempty"`
}

// Sample Falco Event Payload
// {
// 	"hostname":"ssidhut",
// 	"output":"18:22:11.409805555: Warning Log files were tampered (file=/var/log/gpu-manager-switch.log evt_type=openat user=root user_uid=0 user_loginuid=1000 process=gpu-manager proc_exepath=/usr/bin/gpu-manager parent=prime-switch command=gpu-manager --log /var/log/gpu-manager-switch.log terminal=0 container_id=host container_name=host)",
// 	"priority":"Warning",
// 	"rule":"Clear Log Activities",
// 	"source":"syscall",
// 	"tags":["NIST_800-53_AU-10","T1070","container","filesystem","host","maturity_stable","mitre_defense_evasion"],
// 	"time":"2024-09-26T17:22:11.409805555Z",
// 	"output_fields": {"container.id":"host","container.name":"host","evt.time":1727371331409805555,"evt.type":"openat","fd.name":"/var/log/gpu-manager-switch.log","proc.cmdline":"gpu-manager --log /var/log/gpu-manager-switch.log","proc.exepath":"/usr/bin/gpu-manager","proc.name":"gpu-manager","proc.pname":"prime-switch","proc.tty":0,"user.loginuid":1000,"user.name":"root","user.uid":0}}

// FalcoPayload is a struct to map falco event json
type FalcoEventPayload struct {
	UUID          string                 `json:"uuid,omitempty"`
	Output        string                 `json:"output,omitempty"`
	Priority      PriorityType           `json:"priority,omitempty"`
	Rule          string                 `json:"rule,omitempty"`
	Time          time.Time              `json:"time,omitempty"`
	OutputFields  map[string]interface{} `json:"output_fields,omitempty"`
	Source        string                 `json:"source,omitempty"`
	Tags          []string               `json:"tags,omitempty"`
	Hostname      string                 `json:"hostname,omitempty"`
	ContainerID   string                 `json:"container.id,omitempty"`
	ContainerName string                 `json:"container.name,omitempty"`
	EvtTime       int64                  `json:"evt.time,omitempty"`
	EvtType       string                 `json:"evt.type,omitempty"`
	FdName        string                 `json:"fd.name,omitempty"`
	ProcCmdline   string                 `json:"proc.cmdline,omitempty"`
	ProcExepath   string                 `json:"proc.exepath,omitempty"`
	ProcName      string                 `json:"proc.name,omitempty"`
	ProcPname     string                 `json:"proc.pname,omitempty"`
	ProcTty       int                    `json:"proc.tty,omitempty"`
	UserLoginuid  int                    `json:"user.loginuid,omitempty"`
	UserName      string                 `json:"user.name,omitempty"`
	UserUid       int                    `json:"user.uid,omitempty"`
}

func (f FalcoEventPayload) String() string {
	j, _ := json.Marshal(f)
	return string(j)
}

func (f FalcoEventPayload) Check() bool {
	if f.Priority.String() == "" {
		return false
	}
	if f.Rule == "" {
		return false
	}
	if f.Time.IsZero() {
		return false
	}
	if len(f.OutputFields) == 0 {
		return false
	}
	return true
}

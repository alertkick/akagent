//go:build linux

package all

import (
	_ "apagent/checks/auth"
	_ "apagent/checks/cpu"
	_ "apagent/checks/disk_usage"
	_ "apagent/checks/dns"
	_ "apagent/checks/docker"
	_ "apagent/checks/http"
	_ "apagent/checks/load_avg"
	_ "apagent/checks/memory"
	_ "apagent/checks/packages"
	_ "apagent/checks/ports"
	_ "apagent/checks/process"
	_ "apagent/checks/services"
	_ "apagent/checks/ssh"
)

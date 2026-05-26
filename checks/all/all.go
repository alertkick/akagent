//go:build linux

package all

import (
	_ "akagent/checks/cpu"
	_ "akagent/checks/disk_usage"
	_ "akagent/checks/dns"
	_ "akagent/checks/docker"
	_ "akagent/checks/http"
	_ "akagent/checks/load_avg"
	_ "akagent/checks/memory"
	_ "akagent/checks/packages"
	_ "akagent/checks/ports"
	_ "akagent/checks/process"
	_ "akagent/checks/services"
	_ "akagent/checks/ssh"
)

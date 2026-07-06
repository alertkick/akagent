//go:build !windows

package main

func defaultConfigDir() string {
	return "/etc/alertkick-agent"
}

func defaultConfigFile() string {
	return "/etc/alertkick-agent/alertkick-agent.conf"
}

func defaultLogFile() string {
	return "/var/log/alertkick-agent/apagent.log"
}

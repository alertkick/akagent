//go:build windows

package main

import (
	"os"
	"path/filepath"
)

// programDataDir is the agent's writable state root on Windows. Config and
// logs live under %ProgramData%\AlertKick (the binary itself is installed
// under %ProgramFiles%\AlertKick by the install script). The install script
// restricts the directory ACL to SYSTEM + Administrators because the config
// file contains the agent token.
func programDataDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "AlertKick")
}

func defaultConfigDir() string {
	return programDataDir()
}

func defaultConfigFile() string {
	return filepath.Join(programDataDir(), "alertkick-agent.conf")
}

func defaultLogFile() string {
	return filepath.Join(programDataDir(), "logs", "alertkick-agent.log")
}

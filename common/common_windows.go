//go:build windows

package common

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// Uname returns the hostname and OS version. The second value is reported
// to the endpoint as the "kernel version"; on Windows that is the NT
// version triple, e.g. "10.0.20348" (Server 2022).
func Uname() (string, string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", "", err
	}
	major, minor, build := windows.RtlGetNtVersionNumbers()
	return hostname, fmt.Sprintf("%d.%d.%d", major, minor, build), nil
}

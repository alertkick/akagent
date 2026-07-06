//go:build !linux && !windows

package common

import "os"

func Uname() (string, string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", "", err
	}
	return hostname, "0.0", nil
}

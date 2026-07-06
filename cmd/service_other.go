//go:build !windows

package main

func runningAsWindowsService() bool {
	return false
}

func runWindowsService() error {
	return nil
}

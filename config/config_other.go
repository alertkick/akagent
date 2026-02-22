//go:build !linux

package config

import "github.com/rs/zerolog"

func watchConfigReloadSignal(configfile string, log zerolog.Logger) {
	// SIGUSR2-based config reload is not supported on non-Linux platforms
}

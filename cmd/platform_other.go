//go:build !linux

package main

import "github.com/rs/zerolog"

func validateKernel(log zerolog.Logger, kv string) {
	// No kernel version validation on non-Linux platforms
	log.Info().Msg("Running on non-Linux platform, skipping kernel version check")
}

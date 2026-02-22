//go:build linux

package config

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"
)

func watchConfigReloadSignal(configfile string, log zerolog.Logger) {
	s := make(chan os.Signal, 1)
	signal.Notify(s, syscall.SIGUSR2)
	go func() {
		for {
			<-s
			loadConfig(false, configfile, log)
		}
	}()
}

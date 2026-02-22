//go:build linux

package main

import (
	"apagent/common"

	"github.com/rs/zerolog"
	"golang.org/x/mod/semver"
)

const minSupportedKernelVersion = "4.16"

func validateKernel(log zerolog.Logger, kv string) {
	ver := common.KernelMajorMinor(kv)
	if ver == "" {
		log.Panic().Msgf("invalid kernel version: %v", kv)
	}
	if semver.Compare("v"+ver, "v"+minSupportedKernelVersion) == -1 {
		log.Panic().Msgf("the minimum Linux kernel version required is %s or later", minSupportedKernelVersion)
	}
}

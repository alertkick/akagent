package common

import (
	"regexp"
	"strings"
)

var (
	kernelVersionRe = regexp.MustCompile(`^(\d+\.\d+)`)
)

func KernelMajorMinor(version string) string {
	return kernelVersionRe.FindString(version)
}

func IsNotExist(err error) bool {
	return strings.Contains(err.Error(), "no such file or directory") || strings.Contains(err.Error(), "no such process")
}

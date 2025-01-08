package common

import (
	"bytes"
	"os"
	"regexp"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
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

func Uname() (string, string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	f, err := os.Open("/proc/1/ns/uts")
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	self, err := os.Open("/proc/self/ns/uts")
	if err != nil {
		return "", "", err
	}
	defer self.Close()

	defer func() {
		unix.Setns(int(self.Fd()), unix.CLONE_NEWUTS)
	}()

	err = unix.Setns(int(f.Fd()), unix.CLONE_NEWUTS)
	if err != nil {
		return "", "", err
	}
	var utsname unix.Utsname
	if err := unix.Uname(&utsname); err != nil {
		return "", "", err
	}
	hostname := string(bytes.Split(utsname.Nodename[:], []byte{0})[0])
	kernelVersion := string(bytes.Split(utsname.Release[:], []byte{0})[0])
	return hostname, kernelVersion, nil
}

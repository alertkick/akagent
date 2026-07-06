//go:build !linux && !windows

package checks

// Stubs for platforms with no system-info collectors (keeps base.go's
// CollectSystemData compiling on darwin etc.).

func GetSystemListeningPorts() ([]SystemPortInfo, error) {
	return nil, nil
}

func GetSystemServices() ([]SystemServiceInfo, error) {
	return nil, nil
}

func GetInstalledPackages() ([]PackageInfo, error) {
	return nil, nil
}

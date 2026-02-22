//go:build linux

package ebpf

import (
	"fmt"
	"os"
	"path/filepath"

	ciliumebpf "github.com/cilium/ebpf"
)

const (
	// BPFPinBasePath is the base path for pinning AlertPriority BPF objects
	BPFPinBasePath = "/sys/fs/bpf/alertpriority"

	// Subdirectories for organizing pinned objects
	BPFPinProgsPath = BPFPinBasePath + "/progs"
	BPFPinMapsPath  = BPFPinBasePath + "/maps"
	BPFPinLinksPath = BPFPinBasePath + "/links"
)

// BPFPinManager handles pinning and unpinning of BPF programs and maps
type BPFPinManager struct {
	basePath  string
	progsPath string
	mapsPath  string
	linksPath string
}

// NewBPFPinManager creates a new BPF pin manager
func NewBPFPinManager() *BPFPinManager {
	return &BPFPinManager{
		basePath:  BPFPinBasePath,
		progsPath: BPFPinProgsPath,
		mapsPath:  BPFPinMapsPath,
		linksPath: BPFPinLinksPath,
	}
}

// EnsurePinDirectories creates the BPF pin directory structure if it doesn't exist
func (m *BPFPinManager) EnsurePinDirectories() error {
	// Check if BPF filesystem is mounted
	if _, err := os.Stat("/sys/fs/bpf"); os.IsNotExist(err) {
		return fmt.Errorf("BPF filesystem not mounted at /sys/fs/bpf")
	}

	// Create directory structure
	dirs := []string{m.basePath, m.progsPath, m.mapsPath, m.linksPath}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create BPF pin directory %s: %w", dir, err)
		}
	}

	nativeLog.Debug().Str("path", m.basePath).Msg("BPF pin directories ready")
	return nil
}

// CleanupExistingPins removes all existing pinned objects from previous runs
// This ensures a clean slate when starting the agent
func (m *BPFPinManager) CleanupExistingPins() error {
	// Check if base path exists
	if _, err := os.Stat(m.basePath); os.IsNotExist(err) {
		// Nothing to clean up
		return nil
	}

	nativeLog.Info().Str("path", m.basePath).Msg("Cleaning up existing BPF pinned objects")

	// Remove all pinned objects by removing the entire directory tree
	// This is safe because we own this directory
	if err := os.RemoveAll(m.basePath); err != nil {
		return fmt.Errorf("failed to cleanup BPF pin directory: %w", err)
	}

	nativeLog.Debug().Msg("BPF pin cleanup complete")
	return nil
}

// PinProgram pins a BPF program to the filesystem
func (m *BPFPinManager) PinProgram(prog *ciliumebpf.Program, name string) error {
	if prog == nil {
		return nil
	}

	pinPath := filepath.Join(m.progsPath, name)
	if err := prog.Pin(pinPath); err != nil {
		return fmt.Errorf("failed to pin program %s: %w", name, err)
	}

	nativeLog.Debug().Str("program", name).Str("path", pinPath).Msg("Pinned BPF program")
	return nil
}

// PinMap pins a BPF map to the filesystem
func (m *BPFPinManager) PinMap(m2 *ciliumebpf.Map, name string) error {
	if m2 == nil {
		return nil
	}

	pinPath := filepath.Join(m.mapsPath, name)
	if err := m2.Pin(pinPath); err != nil {
		return fmt.Errorf("failed to pin map %s: %w", name, err)
	}

	nativeLog.Debug().Str("map", name).Str("path", pinPath).Msg("Pinned BPF map")
	return nil
}

// UnpinProgram unpins a BPF program from the filesystem
func (m *BPFPinManager) UnpinProgram(name string) error {
	pinPath := filepath.Join(m.progsPath, name)
	if err := os.Remove(pinPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to unpin program %s: %w", name, err)
	}
	return nil
}

// UnpinMap unpins a BPF map from the filesystem
func (m *BPFPinManager) UnpinMap(name string) error {
	pinPath := filepath.Join(m.mapsPath, name)
	if err := os.Remove(pinPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to unpin map %s: %w", name, err)
	}
	return nil
}

// UnpinAll removes all pinned objects (full cleanup)
func (m *BPFPinManager) UnpinAll() error {
	return m.CleanupExistingPins()
}

// GetPinPath returns the full pin path for a given object type and name
func (m *BPFPinManager) GetPinPath(objType, name string) string {
	switch objType {
	case "prog":
		return filepath.Join(m.progsPath, name)
	case "map":
		return filepath.Join(m.mapsPath, name)
	case "link":
		return filepath.Join(m.linksPath, name)
	default:
		return filepath.Join(m.basePath, name)
	}
}

// IsPinned checks if an object is already pinned at the given path
func (m *BPFPinManager) IsPinned(objType, name string) bool {
	pinPath := m.GetPinPath(objType, name)
	_, err := os.Stat(pinPath)
	return err == nil
}

// ListPinnedPrograms returns a list of pinned program names
func (m *BPFPinManager) ListPinnedPrograms() ([]string, error) {
	return m.listPinnedObjects(m.progsPath)
}

// ListPinnedMaps returns a list of pinned map names
func (m *BPFPinManager) ListPinnedMaps() ([]string, error) {
	return m.listPinnedObjects(m.mapsPath)
}

func (m *BPFPinManager) listPinnedObjects(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var names []string
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	return names, nil
}

// GetCollectionOptions returns ciliumebpf.CollectionOptions configured for pinning
func (m *BPFPinManager) GetCollectionOptions() *ciliumebpf.CollectionOptions {
	return &ciliumebpf.CollectionOptions{
		Maps: ciliumebpf.MapOptions{
			PinPath: m.mapsPath,
		},
		Programs: ciliumebpf.ProgramOptions{
			// Programs are pinned individually after loading
		},
	}
}

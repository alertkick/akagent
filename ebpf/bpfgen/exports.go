// Package bpfgen provides exported wrappers for the generated BPF types.
// The generated types are unexported (lowercase) by bpf2go, so we provide
// exported aliases for use by other packages.
package bpfgen

import "github.com/cilium/ebpf"

// --- Execve types ---

// ExecveEvent is the event structure sent from the BPF program
type ExecveEvent = execveExecveEvent

// ExecveObjects contains the loaded BPF objects (maps and programs)
type ExecveObjects = execveObjects

// ExecveMaps contains the BPF maps
type ExecveMaps = execveMaps

// ExecvePrograms contains the BPF programs
type ExecvePrograms = execvePrograms

// LoadExecveObjects loads the BPF objects into the kernel
func LoadExecveObjects(obj *ExecveObjects, opts *ebpf.CollectionOptions) error {
	return loadExecveObjects(obj, opts)
}

// --- File operations types ---

// FileEvent is the event structure for file operations
type FileEvent = fileopsFileEvent

// FileopsObjects contains the loaded BPF objects for file operations
type FileopsObjects = fileopsObjects

// FileopsMaps contains the BPF maps for file operations
type FileopsMaps = fileopsMaps

// FileopsPrograms contains the BPF programs for file operations
type FileopsPrograms = fileopsPrograms

// LoadFileopsObjects loads the file operations BPF objects into the kernel
func LoadFileopsObjects(obj *FileopsObjects, opts *ebpf.CollectionOptions) error {
	return loadFileopsObjects(obj, opts)
}

// --- Network types ---

// NetworkEvent is the event structure for network operations
type NetworkEvent = networkNetworkEvent

// NetworkObjects contains the loaded BPF objects for network operations
type NetworkObjects = networkObjects

// NetworkMaps contains the BPF maps for network operations
type NetworkMaps = networkMaps

// NetworkPrograms contains the BPF programs for network operations
type NetworkPrograms = networkPrograms

// LoadNetworkObjects loads the network BPF objects into the kernel
func LoadNetworkObjects(obj *NetworkObjects, opts *ebpf.CollectionOptions) error {
	return loadNetworkObjects(obj, opts)
}

// --- Process types ---

// ProcessEvent is the event structure for process operations
type ProcessEvent = processProcessEvent

// ProcessObjects contains the loaded BPF objects for process operations
type ProcessObjects = processObjects

// ProcessMaps contains the BPF maps for process operations
type ProcessMaps = processMaps

// ProcessPrograms contains the BPF programs for process operations
type ProcessPrograms = processPrograms

// LoadProcessObjects loads the process BPF objects into the kernel
func LoadProcessObjects(obj *ProcessObjects, opts *ebpf.CollectionOptions) error {
	return loadProcessObjects(obj, opts)
}

// --- Privilege types (SOX/PCI compliance) ---

// PrivilegeEvent is the event structure for privilege escalation operations
type PrivilegeEvent = privilegePrivilegeEvent

// PrivilegeObjects contains the loaded BPF objects for privilege operations
type PrivilegeObjects = privilegeObjects

// PrivilegeMaps contains the BPF maps for privilege operations
type PrivilegeMaps = privilegeMaps

// PrivilegePrograms contains the BPF programs for privilege operations
type PrivilegePrograms = privilegePrograms

// LoadPrivilegeObjects loads the privilege BPF objects into the kernel
func LoadPrivilegeObjects(obj *PrivilegeObjects, opts *ebpf.CollectionOptions) error {
	return loadPrivilegeObjects(obj, opts)
}

// --- Mount types (SOX/PCI compliance) ---

// MountEvent is the event structure for mount operations
type MountEvent = mountMountEvent

// MountObjects contains the loaded BPF objects for mount operations
type MountObjects = mountObjects

// MountMaps contains the BPF maps for mount operations
type MountMaps = mountMaps

// MountPrograms contains the BPF programs for mount operations
type MountPrograms = mountPrograms

// LoadMountObjects loads the mount BPF objects into the kernel
func LoadMountObjects(obj *MountObjects, opts *ebpf.CollectionOptions) error {
	return loadMountObjects(obj, opts)
}

// --- Module types (SOX/PCI compliance) ---

// ModuleEvent is the event structure for kernel module operations
type ModuleEvent = moduleModuleEvent

// ModuleObjects contains the loaded BPF objects for module operations
type ModuleObjects = moduleObjects

// ModuleMaps contains the BPF maps for module operations
type ModuleMaps = moduleMaps

// ModulePrograms contains the BPF programs for module operations
type ModulePrograms = modulePrograms

// LoadModuleObjects loads the module BPF objects into the kernel
func LoadModuleObjects(obj *ModuleObjects, opts *ebpf.CollectionOptions) error {
	return loadModuleObjects(obj, opts)
}

// --- Memory types (code injection detection) ---

// MemoryEvent is the event structure for memory protection changes
type MemoryEvent = memoryMemoryEvent

// MemoryObjects contains the loaded BPF objects for memory operations
type MemoryObjects = memoryObjects

// MemoryMaps contains the BPF maps for memory operations
type MemoryMaps = memoryMaps

// MemoryPrograms contains the BPF programs for memory operations
type MemoryPrograms = memoryPrograms

// LoadMemoryObjects loads the memory BPF objects into the kernel
func LoadMemoryObjects(obj *MemoryObjects, opts *ebpf.CollectionOptions) error {
	return loadMemoryObjects(obj, opts)
}

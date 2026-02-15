package bpfgen

// Type aliases for event structs.
// bpf2go generates types with the prefix prepended to the Go-ified C type name
// (e.g., ExecveExecveEvent from prefix "Execve" + C type "execve_event").
// The rest of the codebase references these shorter names.

type ExecveEvent = ExecveExecveEvent
type FileEvent = FileopsFileEvent
type NetworkEvent = NetworkNetworkEvent
type ProcessEvent = ProcessProcessEvent
type PrivilegeEvent = PrivilegePrivilegeEvent
type MountEvent = MountMountEvent
type ModuleEvent = ModuleModuleEvent
type MemoryEvent = MemoryMemoryEvent
type DnsEvent = DnsDnsEvent
type ImdsEvent = ImdsImdsEvent
type BpfSyscallEvent = BpfsyscallBpfSyscallEvent
type MemfdEvent = MemfdMemfdEvent
type IouringEvent = IouringIouringEvent

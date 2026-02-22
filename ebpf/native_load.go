//go:build linux

package ebpf

import (
	"fmt"

	"apagent/ebpf/bpfgen"
	"apagent/logger"
)

// loadAllPrograms loads all BPF program objects
func (a *NativeEBPFAgent) loadAllPrograms() error {
	var err error
	perf := a.outputMode == OutputModePerf

	// Load process cache first (optional - enriches events with process lineage)
	// Must be loaded before other programs so the kernel map is populated
	// before security events start flowing.
	a.processCacheObjs = &bpfgen.ProcesscacheObjects{}
	if err = bpfgen.LoadProcesscacheObjects(a.processCacheObjs, nil); err != nil {
		nativeLog.Warn().Err(err).Msg("Failed to load process cache BPF, events will have basic context only")
		a.processCacheObjs = nil
	} else {
		nativeLog.Info().Msg("Process cache BPF loaded successfully")
		a.processCache = NewProcessCache(a.processCacheObjs.ProcessCache, 32768)
	}

	// Load execve program
	if perf {
		a.perfExecveObjs = &bpfgen.PerfexecveObjects{}
		if err = bpfgen.LoadPerfexecveObjects(a.perfExecveObjs, nil); err != nil {
			return fmt.Errorf("failed to load execve BPF objects: %w", err)
		}
	} else {
		a.execveObjs = &bpfgen.ExecveObjects{}
		if err = bpfgen.LoadExecveObjects(a.execveObjs, nil); err != nil {
			return fmt.Errorf("failed to load execve BPF objects: %w", err)
		}
	}
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Loaded execve BPF program")
	}

	// Load fileops program
	if perf {
		a.perfFileopsObjs = &bpfgen.PerffileopsObjects{}
		if err = bpfgen.LoadPerffileopsObjects(a.perfFileopsObjs, nil); err != nil {
			return fmt.Errorf("failed to load fileops BPF objects: %w", err)
		}
	} else {
		a.fileopsObjs = &bpfgen.FileopsObjects{}
		if err = bpfgen.LoadFileopsObjects(a.fileopsObjs, nil); err != nil {
			return fmt.Errorf("failed to load fileops BPF objects: %w", err)
		}
	}
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Loaded fileops BPF program")
	}

	// Load network program
	if perf {
		a.perfNetworkObjs = &bpfgen.PerfnetworkObjects{}
		if err = bpfgen.LoadPerfnetworkObjects(a.perfNetworkObjs, nil); err != nil {
			return fmt.Errorf("failed to load network BPF objects: %w", err)
		}
	} else {
		a.networkObjs = &bpfgen.NetworkObjects{}
		if err = bpfgen.LoadNetworkObjects(a.networkObjs, nil); err != nil {
			return fmt.Errorf("failed to load network BPF objects: %w", err)
		}
	}
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Loaded network BPF program")
	}

	// Load process program
	if perf {
		a.perfProcessObjs = &bpfgen.PerfprocessObjects{}
		if err = bpfgen.LoadPerfprocessObjects(a.perfProcessObjs, nil); err != nil {
			return fmt.Errorf("failed to load process BPF objects: %w", err)
		}
	} else {
		a.processObjs = &bpfgen.ProcessObjects{}
		if err = bpfgen.LoadProcessObjects(a.processObjs, nil); err != nil {
			return fmt.Errorf("failed to load process BPF objects: %w", err)
		}
	}
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Loaded process BPF program")
	}

	// Load compliance programs (SOX/PCI)
	if perf {
		a.perfPrivilegeObjs = &bpfgen.PerfprivilegeObjects{}
		if err = bpfgen.LoadPerfprivilegeObjects(a.perfPrivilegeObjs, nil); err != nil {
			return fmt.Errorf("failed to load privilege BPF objects: %w", err)
		}
	} else {
		a.privilegeObjs = &bpfgen.PrivilegeObjects{}
		if err = bpfgen.LoadPrivilegeObjects(a.privilegeObjs, nil); err != nil {
			return fmt.Errorf("failed to load privilege BPF objects: %w", err)
		}
	}
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Loaded privilege BPF program")
	}

	if perf {
		a.perfMountObjs = &bpfgen.PerfmountObjects{}
		if err = bpfgen.LoadPerfmountObjects(a.perfMountObjs, nil); err != nil {
			return fmt.Errorf("failed to load mount BPF objects: %w", err)
		}
	} else {
		a.mountObjs = &bpfgen.MountObjects{}
		if err = bpfgen.LoadMountObjects(a.mountObjs, nil); err != nil {
			return fmt.Errorf("failed to load mount BPF objects: %w", err)
		}
	}
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Loaded mount BPF program")
	}

	if perf {
		a.perfModuleObjs = &bpfgen.PerfmoduleObjects{}
		if err = bpfgen.LoadPerfmoduleObjects(a.perfModuleObjs, nil); err != nil {
			return fmt.Errorf("failed to load module BPF objects: %w", err)
		}
	} else {
		a.moduleObjs = &bpfgen.ModuleObjects{}
		if err = bpfgen.LoadModuleObjects(a.moduleObjs, nil); err != nil {
			return fmt.Errorf("failed to load module BPF objects: %w", err)
		}
	}
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Loaded module BPF program")
	}

	if perf {
		a.perfMemoryObjs = &bpfgen.PerfmemoryObjects{}
		if err = bpfgen.LoadPerfmemoryObjects(a.perfMemoryObjs, nil); err != nil {
			return fmt.Errorf("failed to load memory BPF objects: %w", err)
		}
	} else {
		a.memoryObjs = &bpfgen.MemoryObjects{}
		if err = bpfgen.LoadMemoryObjects(a.memoryObjs, nil); err != nil {
			return fmt.Errorf("failed to load memory BPF objects: %w", err)
		}
	}
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Loaded memory BPF program")
	}

	// Load DNS program
	if perf {
		a.perfDnsObjs = &bpfgen.PerfdnsObjects{}
		if err = bpfgen.LoadPerfdnsObjects(a.perfDnsObjs, nil); err != nil {
			return fmt.Errorf("failed to load DNS BPF objects: %w", err)
		}
	} else {
		a.dnsObjs = &bpfgen.DnsObjects{}
		if err = bpfgen.LoadDnsObjects(a.dnsObjs, nil); err != nil {
			return fmt.Errorf("failed to load DNS BPF objects: %w", err)
		}
	}
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Loaded DNS BPF program")
	}

	// Load IMDS program
	if perf {
		a.perfImdsObjs = &bpfgen.PerfimdsObjects{}
		if err = bpfgen.LoadPerfimdsObjects(a.perfImdsObjs, nil); err != nil {
			return fmt.Errorf("failed to load IMDS BPF objects: %w", err)
		}
	} else {
		a.imdsObjs = &bpfgen.ImdsObjects{}
		if err = bpfgen.LoadImdsObjects(a.imdsObjs, nil); err != nil {
			return fmt.Errorf("failed to load IMDS BPF objects: %w", err)
		}
	}
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Loaded IMDS BPF program")
	}

	// Load BPF syscall monitoring program
	if perf {
		a.perfBpfsyscallObjs = &bpfgen.PerfbpfsyscallObjects{}
		if err = bpfgen.LoadPerfbpfsyscallObjects(a.perfBpfsyscallObjs, nil); err != nil {
			return fmt.Errorf("failed to load BPF syscall BPF objects: %w", err)
		}
	} else {
		a.bpfsyscallObjs = &bpfgen.BpfsyscallObjects{}
		if err = bpfgen.LoadBpfsyscallObjects(a.bpfsyscallObjs, nil); err != nil {
			return fmt.Errorf("failed to load BPF syscall BPF objects: %w", err)
		}
	}
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Loaded BPF syscall monitoring program")
	}

	// Load memfd/execveat fileless execution monitoring program
	if perf {
		a.perfMemfdObjs = &bpfgen.PerfmemfdObjects{}
		if err = bpfgen.LoadPerfmemfdObjects(a.perfMemfdObjs, nil); err != nil {
			return fmt.Errorf("failed to load memfd BPF objects: %w", err)
		}
	} else {
		a.memfdObjs = &bpfgen.MemfdObjects{}
		if err = bpfgen.LoadMemfdObjects(a.memfdObjs, nil); err != nil {
			return fmt.Errorf("failed to load memfd BPF objects: %w", err)
		}
	}
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Loaded memfd/execveat BPF program")
	}

	// Load io_uring monitoring program
	if perf {
		a.perfIouringObjs = &bpfgen.PerfiouringObjects{}
		if err = bpfgen.LoadPerfiouringObjects(a.perfIouringObjs, nil); err != nil {
			return fmt.Errorf("failed to load io_uring BPF objects: %w", err)
		}
	} else {
		a.iouringObjs = &bpfgen.IouringObjects{}
		if err = bpfgen.LoadIouringObjects(a.iouringObjs, nil); err != nil {
			return fmt.Errorf("failed to load io_uring BPF objects: %w", err)
		}
	}
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Loaded io_uring BPF program")
	}

	// Load namespace monitoring program
	if perf {
		a.perfNamespaceObjs = &bpfgen.PerfnamespaceObjects{}
		if err = bpfgen.LoadPerfnamespaceObjects(a.perfNamespaceObjs, nil); err != nil {
			return fmt.Errorf("failed to load namespace BPF objects: %w", err)
		}
	} else {
		a.namespaceObjs = &bpfgen.NamespaceObjects{}
		if err = bpfgen.LoadNamespaceObjects(a.namespaceObjs, nil); err != nil {
			return fmt.Errorf("failed to load namespace BPF objects: %w", err)
		}
	}
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Loaded namespace BPF program")
	}

	// Load capability monitoring program
	if perf {
		a.perfCapsObjs = &bpfgen.PerfcapsObjects{}
		if err = bpfgen.LoadPerfcapsObjects(a.perfCapsObjs, nil); err != nil {
			return fmt.Errorf("failed to load capability BPF objects: %w", err)
		}
	} else {
		a.capsObjs = &bpfgen.CapsObjects{}
		if err = bpfgen.LoadCapsObjects(a.capsObjs, nil); err != nil {
			return fmt.Errorf("failed to load capability BPF objects: %w", err)
		}
	}
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Loaded capability BPF program")
	}

	// Load data exfiltration monitoring program
	if perf {
		a.perfDataexfilObjs = &bpfgen.PerfdataexfilObjects{}
		if err = bpfgen.LoadPerfdataexfilObjects(a.perfDataexfilObjs, nil); err != nil {
			return fmt.Errorf("failed to load dataexfil BPF objects: %w", err)
		}
	} else {
		a.dataexfilObjs = &bpfgen.DataexfilObjects{}
		if err = bpfgen.LoadDataexfilObjects(a.dataexfilObjs, nil); err != nil {
			return fmt.Errorf("failed to load dataexfil BPF objects: %w", err)
		}
	}
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Loaded data exfiltration BPF program")
	}

	// Load directory operations monitoring program
	if perf {
		a.perfDiropsObjs = &bpfgen.PerfdiropsObjects{}
		if err = bpfgen.LoadPerfdiropsObjects(a.perfDiropsObjs, nil); err != nil {
			return fmt.Errorf("failed to load dirops BPF objects: %w", err)
		}
	} else {
		a.diropsObjs = &bpfgen.DiropsObjects{}
		if err = bpfgen.LoadDiropsObjects(a.diropsObjs, nil); err != nil {
			return fmt.Errorf("failed to load dirops BPF objects: %w", err)
		}
	}
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Loaded directory operations BPF program")
	}


	// Load VFS kprobe monitoring program (optional - requires kprobe support)
	// Use vfs_hooks as a "canary": if it fails with a verifier/CO-RE
	// incompatibility we skip cred_hooks too, avoiding duplicate warnings.
	if a.kernelSupport.HasKprobe {
		var vfsErr error
		if perf {
			a.perfVfshooksObjs = &bpfgen.PerfvfshooksObjects{}
			vfsErr = bpfgen.LoadPerfvfshooksObjects(a.perfVfshooksObjs, nil)
			if vfsErr != nil {
				a.perfVfshooksObjs = nil
			}
		} else {
			a.vfshooksObjs = &bpfgen.VfshooksObjects{}
			vfsErr = bpfgen.LoadVfshooksObjects(a.vfshooksObjs, nil)
			if vfsErr != nil {
				a.vfshooksObjs = nil
			}
		}

		if vfsErr != nil && IsBPFVerifierIncompat(vfsErr) {
			// CO-RE / verifier incompatibility — kprobe programs were compiled
			// against kernel types not present on this kernel.  Skip both VFS
			// and credential hooks with a single informational message.
			a.kernelSupport.HasKprobeCompat = false
			nativeLog.Info().Msg("Kprobe BPF programs are not compatible with this kernel, skipping VFS and credential hooks")
		} else if vfsErr != nil {
			// Some other failure (permissions, lockdown, etc.) — warn and still
			// attempt cred_hooks in case the issue is VFS-specific.
			a.kernelSupport.HasKprobeCompat = false
			nativeLog.Warn().Err(vfsErr).Msg("Failed to load VFS hooks BPF objects (kprobes may not be available)")

			// Load credential hooks monitoring program (optional - requires kprobe support)
			if perf {
				a.perfCredhooksObjs = &bpfgen.PerfcredhooksObjects{}
				if err = bpfgen.LoadPerfcredhooksObjects(a.perfCredhooksObjs, nil); err != nil {
					nativeLog.Warn().Err(err).Msg("Failed to load credential hooks BPF objects (kprobes may not be available)")
					a.perfCredhooksObjs = nil
				}
			} else {
				a.credhooksObjs = &bpfgen.CredhooksObjects{}
				if err = bpfgen.LoadCredhooksObjects(a.credhooksObjs, nil); err != nil {
					nativeLog.Warn().Err(err).Msg("Failed to load credential hooks BPF objects (kprobes may not be available)")
					a.credhooksObjs = nil
				}
			}
			if logger.IsSectionEnabled(logger.SectionEBPF) {
				nativeLog.Debug().Msg("Loaded credential hooks BPF program")
			}
		} else {
			// vfs_hooks loaded successfully — kprobes are compatible.
			a.kernelSupport.HasKprobeCompat = true
			if logger.IsSectionEnabled(logger.SectionEBPF) {
				nativeLog.Debug().Msg("Loaded VFS hooks BPF program")
			}

			// Load credential hooks monitoring program
			if perf {
				a.perfCredhooksObjs = &bpfgen.PerfcredhooksObjects{}
				if err = bpfgen.LoadPerfcredhooksObjects(a.perfCredhooksObjs, nil); err != nil {
					nativeLog.Warn().Err(err).Msg("Failed to load credential hooks BPF objects")
					a.perfCredhooksObjs = nil
				}
			} else {
				a.credhooksObjs = &bpfgen.CredhooksObjects{}
				if err = bpfgen.LoadCredhooksObjects(a.credhooksObjs, nil); err != nil {
					nativeLog.Warn().Err(err).Msg("Failed to load credential hooks BPF objects")
					a.credhooksObjs = nil
				}
			}
			if logger.IsSectionEnabled(logger.SectionEBPF) {
				nativeLog.Debug().Msg("Loaded credential hooks BPF program")
			}
		}
	}

	// Load ioctl program
	if perf {
		a.perfIoctlObjs = &bpfgen.PerfioctlObjects{}
		if err = bpfgen.LoadPerfioctlObjects(a.perfIoctlObjs, nil); err != nil {
			return fmt.Errorf("failed to load ioctl BPF objects: %w", err)
		}
	} else {
		a.ioctlObjs = &bpfgen.IoctlObjects{}
		if err = bpfgen.LoadIoctlObjects(a.ioctlObjs, nil); err != nil {
			return fmt.Errorf("failed to load ioctl BPF objects: %w", err)
		}
	}
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Loaded ioctl BPF program")
	}

	nativeLog.Info().Str("mode", a.outputMode.String()).Msg("All BPF programs loaded")
	return nil
}

// pinAllPrograms pins all loaded BPF programs to the filesystem for lifecycle management
func (a *NativeEBPFAgent) pinAllPrograms() error {
	var lastErr error
	perf := a.outputMode == OutputModePerf

	// Pin execve program
	if perf {
		if a.perfExecveObjs != nil && a.perfExecveObjs.TracepointSyscallsSysEnterExecve != nil {
			if err := a.pinManager.PinProgram(a.perfExecveObjs.TracepointSyscallsSysEnterExecve, "execve_enter"); err != nil {
				nativeLog.Warn().Err(err).Msg("Failed to pin execve program")
				lastErr = err
			}
		}
	} else {
		if a.execveObjs != nil && a.execveObjs.TracepointSyscallsSysEnterExecve != nil {
			if err := a.pinManager.PinProgram(a.execveObjs.TracepointSyscallsSysEnterExecve, "execve_enter"); err != nil {
				nativeLog.Warn().Err(err).Msg("Failed to pin execve program")
				lastErr = err
			}
		}
	}

	// Pin fileops programs
	if perf {
		if a.perfFileopsObjs != nil {
			if a.perfFileopsObjs.TracepointSyscallsSysEnterOpenat != nil {
				if err := a.pinManager.PinProgram(a.perfFileopsObjs.TracepointSyscallsSysEnterOpenat, "openat_enter"); err != nil {
					lastErr = err
				}
			}
			if a.perfFileopsObjs.TracepointSyscallsSysEnterUnlinkat != nil {
				if err := a.pinManager.PinProgram(a.perfFileopsObjs.TracepointSyscallsSysEnterUnlinkat, "unlinkat_enter"); err != nil {
					lastErr = err
				}
			}
		}
	} else {
		if a.fileopsObjs != nil {
			if a.fileopsObjs.TracepointSyscallsSysEnterOpenat != nil {
				if err := a.pinManager.PinProgram(a.fileopsObjs.TracepointSyscallsSysEnterOpenat, "openat_enter"); err != nil {
					lastErr = err
				}
			}
			if a.fileopsObjs.TracepointSyscallsSysEnterUnlinkat != nil {
				if err := a.pinManager.PinProgram(a.fileopsObjs.TracepointSyscallsSysEnterUnlinkat, "unlinkat_enter"); err != nil {
					lastErr = err
				}
			}
		}
	}

	// Pin network programs
	if perf {
		if a.perfNetworkObjs != nil && a.perfNetworkObjs.TracepointSyscallsSysEnterConnect != nil {
			if err := a.pinManager.PinProgram(a.perfNetworkObjs.TracepointSyscallsSysEnterConnect, "connect_enter"); err != nil {
				lastErr = err
			}
		}
	} else {
		if a.networkObjs != nil && a.networkObjs.TracepointSyscallsSysEnterConnect != nil {
			if err := a.pinManager.PinProgram(a.networkObjs.TracepointSyscallsSysEnterConnect, "connect_enter"); err != nil {
				lastErr = err
			}
		}
	}

	// Pin process programs
	if perf {
		if a.perfProcessObjs != nil {
			if a.perfProcessObjs.TracepointSyscallsSysEnterClone != nil {
				if err := a.pinManager.PinProgram(a.perfProcessObjs.TracepointSyscallsSysEnterClone, "clone_enter"); err != nil {
					lastErr = err
				}
			}
		}
	} else {
		if a.processObjs != nil {
			if a.processObjs.TracepointSyscallsSysEnterClone != nil {
				if err := a.pinManager.PinProgram(a.processObjs.TracepointSyscallsSysEnterClone, "clone_enter"); err != nil {
					lastErr = err
				}
			}
		}
	}

	// Pin privilege programs
	if perf {
		if a.perfPrivilegeObjs != nil && a.perfPrivilegeObjs.TracepointSyscallsSysEnterSetuid != nil {
			if err := a.pinManager.PinProgram(a.perfPrivilegeObjs.TracepointSyscallsSysEnterSetuid, "setuid_enter"); err != nil {
				lastErr = err
			}
		}
	} else {
		if a.privilegeObjs != nil && a.privilegeObjs.TracepointSyscallsSysEnterSetuid != nil {
			if err := a.pinManager.PinProgram(a.privilegeObjs.TracepointSyscallsSysEnterSetuid, "setuid_enter"); err != nil {
				lastErr = err
			}
		}
	}

	// Pin mount programs
	if perf {
		if a.perfMountObjs != nil && a.perfMountObjs.TracepointSyscallsSysEnterMount != nil {
			if err := a.pinManager.PinProgram(a.perfMountObjs.TracepointSyscallsSysEnterMount, "mount_enter"); err != nil {
				lastErr = err
			}
		}
	} else {
		if a.mountObjs != nil && a.mountObjs.TracepointSyscallsSysEnterMount != nil {
			if err := a.pinManager.PinProgram(a.mountObjs.TracepointSyscallsSysEnterMount, "mount_enter"); err != nil {
				lastErr = err
			}
		}
	}

	// Pin module programs
	if perf {
		if a.perfModuleObjs != nil && a.perfModuleObjs.TracepointSyscallsSysEnterInitModule != nil {
			if err := a.pinManager.PinProgram(a.perfModuleObjs.TracepointSyscallsSysEnterInitModule, "init_module_enter"); err != nil {
				lastErr = err
			}
		}
	} else {
		if a.moduleObjs != nil && a.moduleObjs.TracepointSyscallsSysEnterInitModule != nil {
			if err := a.pinManager.PinProgram(a.moduleObjs.TracepointSyscallsSysEnterInitModule, "init_module_enter"); err != nil {
				lastErr = err
			}
		}
	}

	// Pin memory programs
	if perf {
		if a.perfMemoryObjs != nil {
			if a.perfMemoryObjs.TracepointSyscallsSysEnterMprotect != nil {
				if err := a.pinManager.PinProgram(a.perfMemoryObjs.TracepointSyscallsSysEnterMprotect, "mprotect_enter"); err != nil {
					lastErr = err
				}
			}
			if a.perfMemoryObjs.TracepointSyscallsSysEnterMmap != nil {
				if err := a.pinManager.PinProgram(a.perfMemoryObjs.TracepointSyscallsSysEnterMmap, "mmap_enter"); err != nil {
					lastErr = err
				}
			}
		}
	} else {
		if a.memoryObjs != nil {
			if a.memoryObjs.TracepointSyscallsSysEnterMprotect != nil {
				if err := a.pinManager.PinProgram(a.memoryObjs.TracepointSyscallsSysEnterMprotect, "mprotect_enter"); err != nil {
					lastErr = err
				}
			}
			if a.memoryObjs.TracepointSyscallsSysEnterMmap != nil {
				if err := a.pinManager.PinProgram(a.memoryObjs.TracepointSyscallsSysEnterMmap, "mmap_enter"); err != nil {
					lastErr = err
				}
			}
		}
	}

	// Pin DNS programs
	if perf {
		if a.perfDnsObjs != nil {
			if a.perfDnsObjs.TracepointSyscallsSysEnterSendto != nil {
				if err := a.pinManager.PinProgram(a.perfDnsObjs.TracepointSyscallsSysEnterSendto, "dns_sendto_enter"); err != nil {
					lastErr = err
				}
			}
			if a.perfDnsObjs.TracepointSyscallsSysEnterSendmsg != nil {
				if err := a.pinManager.PinProgram(a.perfDnsObjs.TracepointSyscallsSysEnterSendmsg, "dns_sendmsg_enter"); err != nil {
					lastErr = err
				}
			}
		}
	} else {
		if a.dnsObjs != nil {
			if a.dnsObjs.TracepointSyscallsSysEnterSendto != nil {
				if err := a.pinManager.PinProgram(a.dnsObjs.TracepointSyscallsSysEnterSendto, "dns_sendto_enter"); err != nil {
					lastErr = err
				}
			}
			if a.dnsObjs.TracepointSyscallsSysEnterSendmsg != nil {
				if err := a.pinManager.PinProgram(a.dnsObjs.TracepointSyscallsSysEnterSendmsg, "dns_sendmsg_enter"); err != nil {
					lastErr = err
				}
			}
		}
	}

	// Pin IMDS programs
	if perf {
		if a.perfImdsObjs != nil && a.perfImdsObjs.TracepointSyscallsSysEnterConnect != nil {
			if err := a.pinManager.PinProgram(a.perfImdsObjs.TracepointSyscallsSysEnterConnect, "imds_connect_enter"); err != nil {
				lastErr = err
			}
		}
	} else {
		if a.imdsObjs != nil && a.imdsObjs.TracepointSyscallsSysEnterConnect != nil {
			if err := a.pinManager.PinProgram(a.imdsObjs.TracepointSyscallsSysEnterConnect, "imds_connect_enter"); err != nil {
				lastErr = err
			}
		}
	}

	// Pin BPF syscall monitoring program
	if perf {
		if a.perfBpfsyscallObjs != nil && a.perfBpfsyscallObjs.TracepointSyscallsSysEnterBpf != nil {
			if err := a.pinManager.PinProgram(a.perfBpfsyscallObjs.TracepointSyscallsSysEnterBpf, "bpf_enter"); err != nil {
				lastErr = err
			}
		}
	} else {
		if a.bpfsyscallObjs != nil && a.bpfsyscallObjs.TracepointSyscallsSysEnterBpf != nil {
			if err := a.pinManager.PinProgram(a.bpfsyscallObjs.TracepointSyscallsSysEnterBpf, "bpf_enter"); err != nil {
				lastErr = err
			}
		}
	}

	// Pin memfd/execveat programs
	if perf {
		if a.perfMemfdObjs != nil {
			if a.perfMemfdObjs.TracepointSyscallsSysEnterMemfdCreate != nil {
				if err := a.pinManager.PinProgram(a.perfMemfdObjs.TracepointSyscallsSysEnterMemfdCreate, "memfd_create_enter"); err != nil {
					lastErr = err
				}
			}
			if a.perfMemfdObjs.TracepointSyscallsSysEnterExecveat != nil {
				if err := a.pinManager.PinProgram(a.perfMemfdObjs.TracepointSyscallsSysEnterExecveat, "execveat_enter"); err != nil {
					lastErr = err
				}
			}
		}
	} else {
		if a.memfdObjs != nil {
			if a.memfdObjs.TracepointSyscallsSysEnterMemfdCreate != nil {
				if err := a.pinManager.PinProgram(a.memfdObjs.TracepointSyscallsSysEnterMemfdCreate, "memfd_create_enter"); err != nil {
					lastErr = err
				}
			}
			if a.memfdObjs.TracepointSyscallsSysEnterExecveat != nil {
				if err := a.pinManager.PinProgram(a.memfdObjs.TracepointSyscallsSysEnterExecveat, "execveat_enter"); err != nil {
					lastErr = err
				}
			}
		}
	}

	// Pin io_uring programs
	if perf {
		if a.perfIouringObjs != nil {
			if a.perfIouringObjs.TracepointSyscallsSysEnterIoUringSetup != nil {
				if err := a.pinManager.PinProgram(a.perfIouringObjs.TracepointSyscallsSysEnterIoUringSetup, "io_uring_setup_enter"); err != nil {
					lastErr = err
				}
			}
			if a.perfIouringObjs.TracepointSyscallsSysEnterIoUringRegister != nil {
				if err := a.pinManager.PinProgram(a.perfIouringObjs.TracepointSyscallsSysEnterIoUringRegister, "io_uring_register_enter"); err != nil {
					lastErr = err
				}
			}
		}
	} else {
		if a.iouringObjs != nil {
			if a.iouringObjs.TracepointSyscallsSysEnterIoUringSetup != nil {
				if err := a.pinManager.PinProgram(a.iouringObjs.TracepointSyscallsSysEnterIoUringSetup, "io_uring_setup_enter"); err != nil {
					lastErr = err
				}
			}
			if a.iouringObjs.TracepointSyscallsSysEnterIoUringRegister != nil {
				if err := a.pinManager.PinProgram(a.iouringObjs.TracepointSyscallsSysEnterIoUringRegister, "io_uring_register_enter"); err != nil {
					lastErr = err
				}
			}
		}
	}

	// Pin namespace programs
	if perf {
		if a.perfNamespaceObjs != nil {
			if a.perfNamespaceObjs.TracepointSyscallsSysEnterSetns != nil {
				if err := a.pinManager.PinProgram(a.perfNamespaceObjs.TracepointSyscallsSysEnterSetns, "setns_enter"); err != nil {
					lastErr = err
				}
			}
			if a.perfNamespaceObjs.TracepointSyscallsSysEnterUnshare != nil {
				if err := a.pinManager.PinProgram(a.perfNamespaceObjs.TracepointSyscallsSysEnterUnshare, "unshare_enter"); err != nil {
					lastErr = err
				}
			}
		}
	} else {
		if a.namespaceObjs != nil {
			if a.namespaceObjs.TracepointSyscallsSysEnterSetns != nil {
				if err := a.pinManager.PinProgram(a.namespaceObjs.TracepointSyscallsSysEnterSetns, "setns_enter"); err != nil {
					lastErr = err
				}
			}
			if a.namespaceObjs.TracepointSyscallsSysEnterUnshare != nil {
				if err := a.pinManager.PinProgram(a.namespaceObjs.TracepointSyscallsSysEnterUnshare, "unshare_enter"); err != nil {
					lastErr = err
				}
			}
		}
	}

	// Pin capability programs
	if perf {
		if a.perfCapsObjs != nil {
			if a.perfCapsObjs.TracepointSyscallsSysEnterCapset != nil {
				if err := a.pinManager.PinProgram(a.perfCapsObjs.TracepointSyscallsSysEnterCapset, "capset_enter"); err != nil {
					lastErr = err
				}
			}
		}
	} else {
		if a.capsObjs != nil {
			if a.capsObjs.TracepointSyscallsSysEnterCapset != nil {
				if err := a.pinManager.PinProgram(a.capsObjs.TracepointSyscallsSysEnterCapset, "capset_enter"); err != nil {
					lastErr = err
				}
			}
		}
	}

	if lastErr != nil {
		return fmt.Errorf("some programs failed to pin: %w", lastErr)
	}

	nativeLog.Info().Str("path", BPFPinProgsPath).Msg("All BPF programs pinned successfully")
	return nil
}

// closeAllObjects closes all BPF objects
func (a *NativeEBPFAgent) closeAllObjects() {
	if a.processCacheObjs != nil {
		a.processCacheObjs.Close()
		a.processCacheObjs = nil
	}
	if a.execveObjs != nil {
		a.execveObjs.Close()
		a.execveObjs = nil
	}
	if a.perfExecveObjs != nil {
		a.perfExecveObjs.Close()
		a.perfExecveObjs = nil
	}
	if a.fileopsObjs != nil {
		a.fileopsObjs.Close()
		a.fileopsObjs = nil
	}
	if a.perfFileopsObjs != nil {
		a.perfFileopsObjs.Close()
		a.perfFileopsObjs = nil
	}
	if a.networkObjs != nil {
		a.networkObjs.Close()
		a.networkObjs = nil
	}
	if a.perfNetworkObjs != nil {
		a.perfNetworkObjs.Close()
		a.perfNetworkObjs = nil
	}
	if a.processObjs != nil {
		a.processObjs.Close()
		a.processObjs = nil
	}
	if a.perfProcessObjs != nil {
		a.perfProcessObjs.Close()
		a.perfProcessObjs = nil
	}
	// Compliance objects
	if a.privilegeObjs != nil {
		a.privilegeObjs.Close()
		a.privilegeObjs = nil
	}
	if a.perfPrivilegeObjs != nil {
		a.perfPrivilegeObjs.Close()
		a.perfPrivilegeObjs = nil
	}
	if a.mountObjs != nil {
		a.mountObjs.Close()
		a.mountObjs = nil
	}
	if a.perfMountObjs != nil {
		a.perfMountObjs.Close()
		a.perfMountObjs = nil
	}
	if a.moduleObjs != nil {
		a.moduleObjs.Close()
		a.moduleObjs = nil
	}
	if a.perfModuleObjs != nil {
		a.perfModuleObjs.Close()
		a.perfModuleObjs = nil
	}
	if a.memoryObjs != nil {
		a.memoryObjs.Close()
		a.memoryObjs = nil
	}
	if a.perfMemoryObjs != nil {
		a.perfMemoryObjs.Close()
		a.perfMemoryObjs = nil
	}
	if a.dnsObjs != nil {
		a.dnsObjs.Close()
		a.dnsObjs = nil
	}
	if a.perfDnsObjs != nil {
		a.perfDnsObjs.Close()
		a.perfDnsObjs = nil
	}
	if a.imdsObjs != nil {
		a.imdsObjs.Close()
		a.imdsObjs = nil
	}
	if a.perfImdsObjs != nil {
		a.perfImdsObjs.Close()
		a.perfImdsObjs = nil
	}
	if a.bpfsyscallObjs != nil {
		a.bpfsyscallObjs.Close()
		a.bpfsyscallObjs = nil
	}
	if a.perfBpfsyscallObjs != nil {
		a.perfBpfsyscallObjs.Close()
		a.perfBpfsyscallObjs = nil
	}
	if a.memfdObjs != nil {
		a.memfdObjs.Close()
		a.memfdObjs = nil
	}
	if a.perfMemfdObjs != nil {
		a.perfMemfdObjs.Close()
		a.perfMemfdObjs = nil
	}
	if a.iouringObjs != nil {
		a.iouringObjs.Close()
		a.iouringObjs = nil
	}
	if a.perfIouringObjs != nil {
		a.perfIouringObjs.Close()
		a.perfIouringObjs = nil
	}
	if a.namespaceObjs != nil {
		a.namespaceObjs.Close()
		a.namespaceObjs = nil
	}
	if a.perfNamespaceObjs != nil {
		a.perfNamespaceObjs.Close()
		a.perfNamespaceObjs = nil
	}
	if a.capsObjs != nil {
		a.capsObjs.Close()
		a.capsObjs = nil
	}
	if a.perfCapsObjs != nil {
		a.perfCapsObjs.Close()
		a.perfCapsObjs = nil
	}
	if a.dataexfilObjs != nil {
		a.dataexfilObjs.Close()
		a.dataexfilObjs = nil
	}
	if a.perfDataexfilObjs != nil {
		a.perfDataexfilObjs.Close()
		a.perfDataexfilObjs = nil
	}
	if a.diropsObjs != nil {
		a.diropsObjs.Close()
		a.diropsObjs = nil
	}
	if a.perfDiropsObjs != nil {
		a.perfDiropsObjs.Close()
		a.perfDiropsObjs = nil
	}
	if a.vfshooksObjs != nil {
		a.vfshooksObjs.Close()
		a.vfshooksObjs = nil
	}
	if a.perfVfshooksObjs != nil {
		a.perfVfshooksObjs.Close()
		a.perfVfshooksObjs = nil
	}
	if a.credhooksObjs != nil {
		a.credhooksObjs.Close()
		a.credhooksObjs = nil
	}
	if a.perfCredhooksObjs != nil {
		a.perfCredhooksObjs.Close()
		a.perfCredhooksObjs = nil
	}
	if a.ioctlObjs != nil {
		a.ioctlObjs.Close()
		a.ioctlObjs = nil
	}
	if a.perfIoctlObjs != nil {
		a.perfIoctlObjs.Close()
		a.perfIoctlObjs = nil
	}
}

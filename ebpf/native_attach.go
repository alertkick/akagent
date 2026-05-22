//go:build linux

package ebpf

import (
	"fmt"

	"akagent/logger"

	"github.com/cilium/ebpf/link"
)

// attachAllTracepoints attaches all tracepoint programs
func (a *NativeEBPFAgent) attachAllTracepoints() error {
	var tp link.Link
	var err error
	perf := a.outputMode == OutputModePerf

	// Process cache tracepoints (always attached first if loaded)
	if a.processCacheObjs != nil {
		a.procExecLink, err = link.Tracepoint("sched", "sched_process_exec", a.processCacheObjs.HandleSchedProcessExec, nil)
		if err != nil {
			nativeLog.Warn().Err(err).Msg("Failed to attach sched_process_exec for process cache")
		}
		a.procExitLink, err = link.Tracepoint("sched", "sched_process_exit", a.processCacheObjs.HandleSchedProcessExit, nil)
		if err != nil {
			nativeLog.Warn().Err(err).Msg("Failed to attach sched_process_exit for process cache")
		}
		a.procForkLink, err = link.Tracepoint("sched", "sched_process_fork", a.processCacheObjs.HandleSchedProcessFork, nil)
		if err != nil {
			nativeLog.Warn().Err(err).Msg("Failed to attach sched_process_fork for process cache")
		}
		nativeLog.Info().Msg("Process cache tracepoints attached")
	}

	// Execve tracepoint
	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_execve", a.perfExecveObjs.TracepointSyscallsSysEnterExecve, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_execve", a.execveObjs.TracepointSyscallsSysEnterExecve, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_execve: %w", err)
	}
	a.links = append(a.links, tp)
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Attached sys_enter_execve tracepoint")
	}

	// File operation tracepoints
	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_openat", a.perfFileopsObjs.TracepointSyscallsSysEnterOpenat, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_openat", a.fileopsObjs.TracepointSyscallsSysEnterOpenat, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_openat: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_unlinkat", a.perfFileopsObjs.TracepointSyscallsSysEnterUnlinkat, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_unlinkat", a.fileopsObjs.TracepointSyscallsSysEnterUnlinkat, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_unlinkat: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_renameat2", a.perfFileopsObjs.TracepointSyscallsSysEnterRenameat2, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_renameat2", a.fileopsObjs.TracepointSyscallsSysEnterRenameat2, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_renameat2: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_fchmodat", a.perfFileopsObjs.TracepointSyscallsSysEnterFchmodat, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_fchmodat", a.fileopsObjs.TracepointSyscallsSysEnterFchmodat, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_fchmodat: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_fchownat", a.perfFileopsObjs.TracepointSyscallsSysEnterFchownat, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_fchownat", a.fileopsObjs.TracepointSyscallsSysEnterFchownat, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_fchownat: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_mkdirat", a.perfFileopsObjs.TracepointSyscallsSysEnterMkdirat, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_mkdirat", a.fileopsObjs.TracepointSyscallsSysEnterMkdirat, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_mkdirat: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_linkat", a.perfFileopsObjs.TracepointSyscallsSysEnterLinkat, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_linkat", a.fileopsObjs.TracepointSyscallsSysEnterLinkat, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_linkat: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_symlinkat", a.perfFileopsObjs.TracepointSyscallsSysEnterSymlinkat, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_symlinkat", a.fileopsObjs.TracepointSyscallsSysEnterSymlinkat, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_symlinkat: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_setxattr", a.perfFileopsObjs.TracepointSyscallsSysEnterSetxattr, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_setxattr", a.fileopsObjs.TracepointSyscallsSysEnterSetxattr, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_setxattr: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_removexattr", a.perfFileopsObjs.TracepointSyscallsSysEnterRemovexattr, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_removexattr", a.fileopsObjs.TracepointSyscallsSysEnterRemovexattr, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_removexattr: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_utimensat", a.perfFileopsObjs.TracepointSyscallsSysEnterUtimensat, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_utimensat", a.fileopsObjs.TracepointSyscallsSysEnterUtimensat, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_utimensat: %w", err)
	}
	a.links = append(a.links, tp)

	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Attached file operation tracepoints (11 total)")
	}

	// Legacy file operation tracepoints (non-at variants)
	// These use graceful attachment since some architectures (like aarch64) may not have them
	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_open", a.perfFileopsObjs.TracepointSyscallsSysEnterOpen, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_open", a.fileopsObjs.TracepointSyscallsSysEnterOpen, nil)
	}
	if err != nil {
		nativeLog.Debug().Err(err).Msg("sys_enter_open tracepoint not available (expected on aarch64)")
	} else {
		a.links = append(a.links, tp)
	}

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_rename", a.perfFileopsObjs.TracepointSyscallsSysEnterRename, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_rename", a.fileopsObjs.TracepointSyscallsSysEnterRename, nil)
	}
	if err != nil {
		nativeLog.Debug().Err(err).Msg("sys_enter_rename tracepoint not available")
	} else {
		a.links = append(a.links, tp)
	}

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_renameat", a.perfFileopsObjs.TracepointSyscallsSysEnterRenameat, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_renameat", a.fileopsObjs.TracepointSyscallsSysEnterRenameat, nil)
	}
	if err != nil {
		nativeLog.Debug().Err(err).Msg("sys_enter_renameat tracepoint not available")
	} else {
		a.links = append(a.links, tp)
	}

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_unlink", a.perfFileopsObjs.TracepointSyscallsSysEnterUnlink, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_unlink", a.fileopsObjs.TracepointSyscallsSysEnterUnlink, nil)
	}
	if err != nil {
		nativeLog.Debug().Err(err).Msg("sys_enter_unlink tracepoint not available")
	} else {
		a.links = append(a.links, tp)
	}

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_mkdir", a.perfFileopsObjs.TracepointSyscallsSysEnterMkdir, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_mkdir", a.fileopsObjs.TracepointSyscallsSysEnterMkdir, nil)
	}
	if err != nil {
		nativeLog.Debug().Err(err).Msg("sys_enter_mkdir tracepoint not available")
	} else {
		a.links = append(a.links, tp)
	}

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_rmdir", a.perfFileopsObjs.TracepointSyscallsSysEnterRmdir, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_rmdir", a.fileopsObjs.TracepointSyscallsSysEnterRmdir, nil)
	}
	if err != nil {
		nativeLog.Debug().Err(err).Msg("sys_enter_rmdir tracepoint not available")
	} else {
		a.links = append(a.links, tp)
	}

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_chmod", a.perfFileopsObjs.TracepointSyscallsSysEnterChmod, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_chmod", a.fileopsObjs.TracepointSyscallsSysEnterChmod, nil)
	}
	if err != nil {
		nativeLog.Debug().Err(err).Msg("sys_enter_chmod tracepoint not available")
	} else {
		a.links = append(a.links, tp)
	}

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_fchmod", a.perfFileopsObjs.TracepointSyscallsSysEnterFchmod, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_fchmod", a.fileopsObjs.TracepointSyscallsSysEnterFchmod, nil)
	}
	if err != nil {
		nativeLog.Debug().Err(err).Msg("sys_enter_fchmod tracepoint not available")
	} else {
		a.links = append(a.links, tp)
	}

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_chown", a.perfFileopsObjs.TracepointSyscallsSysEnterChown, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_chown", a.fileopsObjs.TracepointSyscallsSysEnterChown, nil)
	}
	if err != nil {
		nativeLog.Debug().Err(err).Msg("sys_enter_chown tracepoint not available")
	} else {
		a.links = append(a.links, tp)
	}

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_fchown", a.perfFileopsObjs.TracepointSyscallsSysEnterFchown, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_fchown", a.fileopsObjs.TracepointSyscallsSysEnterFchown, nil)
	}
	if err != nil {
		nativeLog.Debug().Err(err).Msg("sys_enter_fchown tracepoint not available")
	} else {
		a.links = append(a.links, tp)
	}

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_lchown", a.perfFileopsObjs.TracepointSyscallsSysEnterLchown, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_lchown", a.fileopsObjs.TracepointSyscallsSysEnterLchown, nil)
	}
	if err != nil {
		nativeLog.Debug().Err(err).Msg("sys_enter_lchown tracepoint not available")
	} else {
		a.links = append(a.links, tp)
	}

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_fsetxattr", a.perfFileopsObjs.TracepointSyscallsSysEnterFsetxattr, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_fsetxattr", a.fileopsObjs.TracepointSyscallsSysEnterFsetxattr, nil)
	}
	if err != nil {
		nativeLog.Debug().Err(err).Msg("sys_enter_fsetxattr tracepoint not available")
	} else {
		a.links = append(a.links, tp)
	}

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_lsetxattr", a.perfFileopsObjs.TracepointSyscallsSysEnterLsetxattr, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_lsetxattr", a.fileopsObjs.TracepointSyscallsSysEnterLsetxattr, nil)
	}
	if err != nil {
		nativeLog.Debug().Err(err).Msg("sys_enter_lsetxattr tracepoint not available")
	} else {
		a.links = append(a.links, tp)
	}

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_fremovexattr", a.perfFileopsObjs.TracepointSyscallsSysEnterFremovexattr, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_fremovexattr", a.fileopsObjs.TracepointSyscallsSysEnterFremovexattr, nil)
	}
	if err != nil {
		nativeLog.Debug().Err(err).Msg("sys_enter_fremovexattr tracepoint not available")
	} else {
		a.links = append(a.links, tp)
	}

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_lremovexattr", a.perfFileopsObjs.TracepointSyscallsSysEnterLremovexattr, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_lremovexattr", a.fileopsObjs.TracepointSyscallsSysEnterLremovexattr, nil)
	}
	if err != nil {
		nativeLog.Debug().Err(err).Msg("sys_enter_lremovexattr tracepoint not available")
	} else {
		a.links = append(a.links, tp)
	}

	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Attached legacy file operation tracepoints (non-at variants)")
	}

	// Network tracepoints
	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_connect", a.perfNetworkObjs.TracepointSyscallsSysEnterConnect, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_connect", a.networkObjs.TracepointSyscallsSysEnterConnect, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_connect: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_accept4", a.perfNetworkObjs.TracepointSyscallsSysEnterAccept4, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_accept4", a.networkObjs.TracepointSyscallsSysEnterAccept4, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_accept4: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_bind", a.perfNetworkObjs.TracepointSyscallsSysEnterBind, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_bind", a.networkObjs.TracepointSyscallsSysEnterBind, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_bind: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_socket", a.perfNetworkObjs.TracepointSyscallsSysEnterSocket, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_socket", a.networkObjs.TracepointSyscallsSysEnterSocket, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_socket: %w", err)
	}
	a.links = append(a.links, tp)
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Attached network tracepoints")
	}

	// Process tracepoints
	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_clone", a.perfProcessObjs.TracepointSyscallsSysEnterClone, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_clone", a.processObjs.TracepointSyscallsSysEnterClone, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_clone: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_kill", a.perfProcessObjs.TracepointSyscallsSysEnterKill, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_kill", a.processObjs.TracepointSyscallsSysEnterKill, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_kill: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_ptrace", a.perfProcessObjs.TracepointSyscallsSysEnterPtrace, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_ptrace", a.processObjs.TracepointSyscallsSysEnterPtrace, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_ptrace: %w", err)
	}
	a.links = append(a.links, tp)
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Attached process tracepoints")
	}

	// Privilege escalation tracepoints (SOX/PCI compliance)
	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_setuid", a.perfPrivilegeObjs.TracepointSyscallsSysEnterSetuid, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_setuid", a.privilegeObjs.TracepointSyscallsSysEnterSetuid, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_setuid: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_setgid", a.perfPrivilegeObjs.TracepointSyscallsSysEnterSetgid, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_setgid", a.privilegeObjs.TracepointSyscallsSysEnterSetgid, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_setgid: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_setreuid", a.perfPrivilegeObjs.TracepointSyscallsSysEnterSetreuid, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_setreuid", a.privilegeObjs.TracepointSyscallsSysEnterSetreuid, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_setreuid: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_setregid", a.perfPrivilegeObjs.TracepointSyscallsSysEnterSetregid, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_setregid", a.privilegeObjs.TracepointSyscallsSysEnterSetregid, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_setregid: %w", err)
	}
	a.links = append(a.links, tp)
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Attached privilege escalation tracepoints")
	}

	// Mount tracepoints (SOX/PCI compliance)
	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_mount", a.perfMountObjs.TracepointSyscallsSysEnterMount, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_mount", a.mountObjs.TracepointSyscallsSysEnterMount, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_mount: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_umount", a.perfMountObjs.TracepointSyscallsSysEnterUmount, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_umount", a.mountObjs.TracepointSyscallsSysEnterUmount, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_umount: %w", err)
	}
	a.links = append(a.links, tp)
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Attached mount tracepoints")
	}

	// Kernel module tracepoints (SOX/PCI compliance)
	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_init_module", a.perfModuleObjs.TracepointSyscallsSysEnterInitModule, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_init_module", a.moduleObjs.TracepointSyscallsSysEnterInitModule, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_init_module: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_finit_module", a.perfModuleObjs.TracepointSyscallsSysEnterFinitModule, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_finit_module", a.moduleObjs.TracepointSyscallsSysEnterFinitModule, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_finit_module: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_delete_module", a.perfModuleObjs.TracepointSyscallsSysEnterDeleteModule, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_delete_module", a.moduleObjs.TracepointSyscallsSysEnterDeleteModule, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_delete_module: %w", err)
	}
	a.links = append(a.links, tp)
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Attached kernel module tracepoints")
	}

	// Memory protection tracepoints (code injection detection)
	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_mprotect", a.perfMemoryObjs.TracepointSyscallsSysEnterMprotect, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_mprotect", a.memoryObjs.TracepointSyscallsSysEnterMprotect, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_mprotect: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_mmap", a.perfMemoryObjs.TracepointSyscallsSysEnterMmap, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_mmap", a.memoryObjs.TracepointSyscallsSysEnterMmap, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_mmap: %w", err)
	}
	a.links = append(a.links, tp)

	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Attached memory protection tracepoints (mprotect + mmap)")
	}

	// DNS query tracepoints
	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_sendto", a.perfDnsObjs.TracepointSyscallsSysEnterSendto, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_sendto", a.dnsObjs.TracepointSyscallsSysEnterSendto, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_sendto (dns): %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_sendmsg", a.perfDnsObjs.TracepointSyscallsSysEnterSendmsg, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_sendmsg", a.dnsObjs.TracepointSyscallsSysEnterSendmsg, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_sendmsg (dns): %w", err)
	}
	a.links = append(a.links, tp)
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Attached DNS query tracepoints")
	}

	// IMDS detection tracepoint
	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_connect", a.perfImdsObjs.TracepointSyscallsSysEnterConnect, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_connect", a.imdsObjs.TracepointSyscallsSysEnterConnect, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_connect (imds): %w", err)
	}
	a.links = append(a.links, tp)
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Attached IMDS detection tracepoint")
	}

	// BPF syscall monitoring tracepoint (rootkit detection)
	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_bpf", a.perfBpfsyscallObjs.TracepointSyscallsSysEnterBpf, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_bpf", a.bpfsyscallObjs.TracepointSyscallsSysEnterBpf, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_bpf: %w", err)
	}
	a.links = append(a.links, tp)
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Attached BPF syscall monitoring tracepoint")
	}

	// Fileless execution tracepoints (memfd_create + execveat)
	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_memfd_create", a.perfMemfdObjs.TracepointSyscallsSysEnterMemfdCreate, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_memfd_create", a.memfdObjs.TracepointSyscallsSysEnterMemfdCreate, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_memfd_create: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_execveat", a.perfMemfdObjs.TracepointSyscallsSysEnterExecveat, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_execveat", a.memfdObjs.TracepointSyscallsSysEnterExecveat, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_execveat: %w", err)
	}
	a.links = append(a.links, tp)
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Attached fileless execution tracepoints (memfd_create, execveat)")
	}

	// io_uring monitoring tracepoints (seccomp bypass detection)
	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_io_uring_setup", a.perfIouringObjs.TracepointSyscallsSysEnterIoUringSetup, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_io_uring_setup", a.iouringObjs.TracepointSyscallsSysEnterIoUringSetup, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_io_uring_setup: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_io_uring_register", a.perfIouringObjs.TracepointSyscallsSysEnterIoUringRegister, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_io_uring_register", a.iouringObjs.TracepointSyscallsSysEnterIoUringRegister, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_io_uring_register: %w", err)
	}
	a.links = append(a.links, tp)
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Attached io_uring monitoring tracepoints")
	}

	// Namespace tracepoints (container breakout detection)
	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_setns", a.perfNamespaceObjs.TracepointSyscallsSysEnterSetns, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_setns", a.namespaceObjs.TracepointSyscallsSysEnterSetns, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_setns: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_unshare", a.perfNamespaceObjs.TracepointSyscallsSysEnterUnshare, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_unshare", a.namespaceObjs.TracepointSyscallsSysEnterUnshare, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_unshare: %w", err)
	}
	a.links = append(a.links, tp)
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Attached namespace monitoring tracepoints (setns + unshare)")
	}

	// Capability tracepoints (privilege abuse detection)
	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_capset", a.perfCapsObjs.TracepointSyscallsSysEnterCapset, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_capset", a.capsObjs.TracepointSyscallsSysEnterCapset, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_capset: %w", err)
	}
	a.links = append(a.links, tp)
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Attached capability monitoring tracepoint (capset)")
	}

	// Extended signal tracepoints (tgkill + tkill use process BPF program)
	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_tgkill", a.perfProcessObjs.TracepointSyscallsSysEnterTgkill, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_tgkill", a.processObjs.TracepointSyscallsSysEnterTgkill, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_tgkill: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_tkill", a.perfProcessObjs.TracepointSyscallsSysEnterTkill, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_tkill", a.processObjs.TracepointSyscallsSysEnterTkill, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_tkill: %w", err)
	}
	a.links = append(a.links, tp)
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Attached extended signal tracepoints (tgkill + tkill)")
	}

	// Data exfiltration tracepoints (splice, sendfile, copy_file_range, tee)
	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_splice", a.perfDataexfilObjs.TracepointSyscallsSysEnterSplice, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_splice", a.dataexfilObjs.TracepointSyscallsSysEnterSplice, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_splice: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_sendfile64", a.perfDataexfilObjs.TracepointSyscallsSysEnterSendfile64, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_sendfile64", a.dataexfilObjs.TracepointSyscallsSysEnterSendfile64, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_sendfile64: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_copy_file_range", a.perfDataexfilObjs.TracepointSyscallsSysEnterCopyFileRange, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_copy_file_range", a.dataexfilObjs.TracepointSyscallsSysEnterCopyFileRange, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_copy_file_range: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_tee", a.perfDataexfilObjs.TracepointSyscallsSysEnterTee, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_tee", a.dataexfilObjs.TracepointSyscallsSysEnterTee, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_tee: %w", err)
	}
	a.links = append(a.links, tp)
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Attached data exfiltration tracepoints (splice, sendfile, copy_file_range, tee)")
	}

	// Directory operation tracepoints (chdir, fchdir, chroot, pivot_root)
	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_chdir", a.perfDiropsObjs.TracepointSyscallsSysEnterChdir, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_chdir", a.diropsObjs.TracepointSyscallsSysEnterChdir, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_chdir: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_fchdir", a.perfDiropsObjs.TracepointSyscallsSysEnterFchdir, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_fchdir", a.diropsObjs.TracepointSyscallsSysEnterFchdir, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_fchdir: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_chroot", a.perfDiropsObjs.TracepointSyscallsSysEnterChroot, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_chroot", a.diropsObjs.TracepointSyscallsSysEnterChroot, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_chroot: %w", err)
	}
	a.links = append(a.links, tp)

	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_pivot_root", a.perfDiropsObjs.TracepointSyscallsSysEnterPivotRoot, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_pivot_root", a.diropsObjs.TracepointSyscallsSysEnterPivotRoot, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_pivot_root: %w", err)
	}
	a.links = append(a.links, tp)
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Attached directory operation tracepoints (chdir, fchdir, chroot, pivot_root)")
	}

	// Attach ioctl tracepoint
	if perf {
		tp, err = link.Tracepoint("syscalls", "sys_enter_ioctl", a.perfIoctlObjs.TracepointSyscallsSysEnterIoctl, nil)
	} else {
		tp, err = link.Tracepoint("syscalls", "sys_enter_ioctl", a.ioctlObjs.TracepointSyscallsSysEnterIoctl, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_ioctl: %w", err)
	}
	a.links = append(a.links, tp)
	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Attached ioctl tracepoint")
	}

	// Syscall exit tracepoints (return value capture)
	// These use graceful fallback - exit tracing is optional
	a.attachExitTracepoints(perf)

	// Kprobe attachments (optional - require kprobe support and may fail in lockdown mode)
	a.attachKprobes()

	return nil
}

// attachKprobes attaches kprobe-based BPF programs for VFS and credential monitoring.
// All failures are non-fatal since kprobes may not be available (lockdown mode, etc.)
func (a *NativeEBPFAgent) attachKprobes() {
	var kp link.Link
	var err error

	// VFS kprobes
	if a.vfshooksObjs != nil {
		kp, err = link.Kprobe("vfs_open", a.vfshooksObjs.KprobeVfsOpen, nil)
		if err == nil {
			a.links = append(a.links, kp)
		} else {
			nativeLog.Debug().Err(err).Msg("Failed to attach kprobe/vfs_open (optional)")
		}

		kp, err = link.Kprobe("vfs_unlink", a.vfshooksObjs.KprobeVfsUnlink, nil)
		if err == nil {
			a.links = append(a.links, kp)
		} else {
			nativeLog.Debug().Err(err).Msg("Failed to attach kprobe/vfs_unlink (optional)")
		}

		kp, err = link.Kprobe("vfs_rename", a.vfshooksObjs.KprobeVfsRename, nil)
		if err == nil {
			a.links = append(a.links, kp)
		} else {
			nativeLog.Debug().Err(err).Msg("Failed to attach kprobe/vfs_rename (optional)")
		}

		kp, err = link.Kprobe("security_inode_setattr", a.vfshooksObjs.KprobeSecurityInodeSetattr, nil)
		if err == nil {
			a.links = append(a.links, kp)
		} else {
			nativeLog.Debug().Err(err).Msg("Failed to attach kprobe/security_inode_setattr (optional)")
		}

		if logger.IsSectionEnabled(logger.SectionEBPF) {
			nativeLog.Debug().Msg("Attached VFS kprobes (vfs_open, vfs_unlink, vfs_rename, security_inode_setattr)")
		}
	}

	if a.perfVfshooksObjs != nil {
		kp, err = link.Kprobe("vfs_open", a.perfVfshooksObjs.KprobeVfsOpen, nil)
		if err == nil {
			a.links = append(a.links, kp)
		} else {
			nativeLog.Debug().Err(err).Msg("Failed to attach kprobe/vfs_open perf (optional)")
		}

		kp, err = link.Kprobe("vfs_unlink", a.perfVfshooksObjs.KprobeVfsUnlink, nil)
		if err == nil {
			a.links = append(a.links, kp)
		} else {
			nativeLog.Debug().Err(err).Msg("Failed to attach kprobe/vfs_unlink perf (optional)")
		}

		kp, err = link.Kprobe("vfs_rename", a.perfVfshooksObjs.KprobeVfsRename, nil)
		if err == nil {
			a.links = append(a.links, kp)
		} else {
			nativeLog.Debug().Err(err).Msg("Failed to attach kprobe/vfs_rename perf (optional)")
		}

		kp, err = link.Kprobe("security_inode_setattr", a.perfVfshooksObjs.KprobeSecurityInodeSetattr, nil)
		if err == nil {
			a.links = append(a.links, kp)
		} else {
			nativeLog.Debug().Err(err).Msg("Failed to attach kprobe/security_inode_setattr perf (optional)")
		}

		if logger.IsSectionEnabled(logger.SectionEBPF) {
			nativeLog.Debug().Msg("Attached VFS kprobes in perf mode")
		}
	}

	// Credential kprobes
	if a.credhooksObjs != nil {
		kp, err = link.Kprobe("commit_creds", a.credhooksObjs.KprobeCommitCreds, nil)
		if err == nil {
			a.links = append(a.links, kp)
		} else {
			nativeLog.Debug().Err(err).Msg("Failed to attach kprobe/commit_creds (optional)")
		}

		kp, err = link.Kprobe("do_exit", a.credhooksObjs.KprobeDoExit, nil)
		if err == nil {
			a.links = append(a.links, kp)
		} else {
			nativeLog.Debug().Err(err).Msg("Failed to attach kprobe/do_exit (optional)")
		}

		if logger.IsSectionEnabled(logger.SectionEBPF) {
			nativeLog.Debug().Msg("Attached credential kprobes (commit_creds, do_exit)")
		}
	}

	if a.perfCredhooksObjs != nil {
		kp, err = link.Kprobe("commit_creds", a.perfCredhooksObjs.KprobeCommitCreds, nil)
		if err == nil {
			a.links = append(a.links, kp)
		} else {
			nativeLog.Debug().Err(err).Msg("Failed to attach kprobe/commit_creds perf (optional)")
		}

		kp, err = link.Kprobe("do_exit", a.perfCredhooksObjs.KprobeDoExit, nil)
		if err == nil {
			a.links = append(a.links, kp)
		} else {
			nativeLog.Debug().Err(err).Msg("Failed to attach kprobe/do_exit perf (optional)")
		}

		if logger.IsSectionEnabled(logger.SectionEBPF) {
			nativeLog.Debug().Msg("Attached credential kprobes in perf mode")
		}
	}
}

// attachExitTracepoints attaches sys_exit tracepoints for return value capture.
// Failures are logged but not fatal since exit tracing is optional.
func (a *NativeEBPFAgent) attachExitTracepoints(perf bool) {
	var tp link.Link
	var err error

	// sys_exit_openat
	if !perf && a.fileopsObjs != nil {
		tp, err = link.Tracepoint("syscalls", "sys_exit_openat", a.fileopsObjs.TracepointSyscallsSysExitOpenat, nil)
		if err == nil {
			a.links = append(a.links, tp)
		} else {
			nativeLog.Debug().Err(err).Msg("Failed to attach sys_exit_openat (optional)")
		}
	}

	// sys_exit_connect
	if !perf && a.networkObjs != nil {
		tp, err = link.Tracepoint("syscalls", "sys_exit_connect", a.networkObjs.TracepointSyscallsSysExitConnect, nil)
		if err == nil {
			a.links = append(a.links, tp)
		} else {
			nativeLog.Debug().Err(err).Msg("Failed to attach sys_exit_connect (optional)")
		}
	}

	// sys_exit_execve
	if !perf && a.execveObjs != nil {
		tp, err = link.Tracepoint("syscalls", "sys_exit_execve", a.execveObjs.TracepointSyscallsSysExitExecve, nil)
		if err == nil {
			a.links = append(a.links, tp)
		} else {
			nativeLog.Debug().Err(err).Msg("Failed to attach sys_exit_execve (optional)")
		}
	}

	// sys_exit privilege syscalls
	if !perf && a.privilegeObjs != nil {
		tp, err = link.Tracepoint("syscalls", "sys_exit_setuid", a.privilegeObjs.TracepointSyscallsSysExitSetuid, nil)
		if err == nil {
			a.links = append(a.links, tp)
		} else {
			nativeLog.Debug().Err(err).Msg("Failed to attach sys_exit_setuid (optional)")
		}

		tp, err = link.Tracepoint("syscalls", "sys_exit_setgid", a.privilegeObjs.TracepointSyscallsSysExitSetgid, nil)
		if err == nil {
			a.links = append(a.links, tp)
		} else {
			nativeLog.Debug().Err(err).Msg("Failed to attach sys_exit_setgid (optional)")
		}

		tp, err = link.Tracepoint("syscalls", "sys_exit_setreuid", a.privilegeObjs.TracepointSyscallsSysExitSetreuid, nil)
		if err == nil {
			a.links = append(a.links, tp)
		} else {
			nativeLog.Debug().Err(err).Msg("Failed to attach sys_exit_setreuid (optional)")
		}

		tp, err = link.Tracepoint("syscalls", "sys_exit_setregid", a.privilegeObjs.TracepointSyscallsSysExitSetregid, nil)
		if err == nil {
			a.links = append(a.links, tp)
		} else {
			nativeLog.Debug().Err(err).Msg("Failed to attach sys_exit_setregid (optional)")
		}
	}

	// sys_exit_mount
	if !perf && a.mountObjs != nil {
		tp, err = link.Tracepoint("syscalls", "sys_exit_mount", a.mountObjs.TracepointSyscallsSysExitMount, nil)
		if err == nil {
			a.links = append(a.links, tp)
		} else {
			nativeLog.Debug().Err(err).Msg("Failed to attach sys_exit_mount (optional)")
		}
	}

	// sys_exit module syscalls
	if !perf && a.moduleObjs != nil {
		tp, err = link.Tracepoint("syscalls", "sys_exit_init_module", a.moduleObjs.TracepointSyscallsSysExitInitModule, nil)
		if err == nil {
			a.links = append(a.links, tp)
		} else {
			nativeLog.Debug().Err(err).Msg("Failed to attach sys_exit_init_module (optional)")
		}

		tp, err = link.Tracepoint("syscalls", "sys_exit_finit_module", a.moduleObjs.TracepointSyscallsSysExitFinitModule, nil)
		if err == nil {
			a.links = append(a.links, tp)
		} else {
			nativeLog.Debug().Err(err).Msg("Failed to attach sys_exit_finit_module (optional)")
		}
	}

	// sys_exit_bpf
	if !perf && a.bpfsyscallObjs != nil {
		tp, err = link.Tracepoint("syscalls", "sys_exit_bpf", a.bpfsyscallObjs.TracepointSyscallsSysExitBpf, nil)
		if err == nil {
			a.links = append(a.links, tp)
		} else {
			nativeLog.Debug().Err(err).Msg("Failed to attach sys_exit_bpf (optional)")
		}
	}

	// sys_exit_memfd_create
	if !perf && a.memfdObjs != nil {
		tp, err = link.Tracepoint("syscalls", "sys_exit_memfd_create", a.memfdObjs.TracepointSyscallsSysExitMemfdCreate, nil)
		if err == nil {
			a.links = append(a.links, tp)
		} else {
			nativeLog.Debug().Err(err).Msg("Failed to attach sys_exit_memfd_create (optional)")
		}
	}

	if logger.IsSectionEnabled(logger.SectionEBPF) {
		nativeLog.Debug().Msg("Attached syscall exit tracepoints (return value capture)")
	}
}

// closeAllLinks closes all tracepoint links
func (a *NativeEBPFAgent) closeAllLinks() {
	// Close process cache tracepoint links
	if a.procExecLink != nil {
		a.procExecLink.Close()
		a.procExecLink = nil
	}
	if a.procExitLink != nil {
		a.procExitLink.Close()
		a.procExitLink = nil
	}
	if a.procForkLink != nil {
		a.procForkLink.Close()
		a.procForkLink = nil
	}

	for _, l := range a.links {
		l.Close()
	}
	a.links = nil
}

func (a *NativeEBPFAgent) registerDiscarderMaps() {
	// Helper to safely get a map by name from a collection of maps
	type mapHolder interface {
		Close() error
	}

	// Register maps from each program by looking up the map objects
	// After bpf2go regeneration, the generated Objects structs will have
	// DiscardConfig, DiscardComms, DiscardPids, DiscardStats fields.
	// For now, we access them through the Maps field using reflection-free approach.

	registerFromExecve := func() {
		if a.outputMode == OutputModePerf {
			if a.perfExecveObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.perfExecveObjs.DiscardConfig,
				a.perfExecveObjs.DiscardComms,
				a.perfExecveObjs.DiscardPids,
				a.perfExecveObjs.DiscardStats,
			)
		} else {
			if a.execveObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.execveObjs.DiscardConfig,
				a.execveObjs.DiscardComms,
				a.execveObjs.DiscardPids,
				a.execveObjs.DiscardStats,
			)
		}
	}

	registerFromFileops := func() {
		if a.outputMode == OutputModePerf {
			if a.perfFileopsObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.perfFileopsObjs.DiscardConfig,
				a.perfFileopsObjs.DiscardComms,
				a.perfFileopsObjs.DiscardPids,
				a.perfFileopsObjs.DiscardStats,
			)
		} else {
			if a.fileopsObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.fileopsObjs.DiscardConfig,
				a.fileopsObjs.DiscardComms,
				a.fileopsObjs.DiscardPids,
				a.fileopsObjs.DiscardStats,
			)
		}
	}

	registerFromNetwork := func() {
		if a.outputMode == OutputModePerf {
			if a.perfNetworkObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.perfNetworkObjs.DiscardConfig,
				a.perfNetworkObjs.DiscardComms,
				a.perfNetworkObjs.DiscardPids,
				a.perfNetworkObjs.DiscardStats,
			)
		} else {
			if a.networkObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.networkObjs.DiscardConfig,
				a.networkObjs.DiscardComms,
				a.networkObjs.DiscardPids,
				a.networkObjs.DiscardStats,
			)
		}
	}

	registerFromProcess := func() {
		if a.outputMode == OutputModePerf {
			if a.perfProcessObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.perfProcessObjs.DiscardConfig,
				a.perfProcessObjs.DiscardComms,
				a.perfProcessObjs.DiscardPids,
				a.perfProcessObjs.DiscardStats,
			)
		} else {
			if a.processObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.processObjs.DiscardConfig,
				a.processObjs.DiscardComms,
				a.processObjs.DiscardPids,
				a.processObjs.DiscardStats,
			)
		}
	}

	registerFromPrivilege := func() {
		if a.outputMode == OutputModePerf {
			if a.perfPrivilegeObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.perfPrivilegeObjs.DiscardConfig,
				a.perfPrivilegeObjs.DiscardComms,
				a.perfPrivilegeObjs.DiscardPids,
				a.perfPrivilegeObjs.DiscardStats,
			)
		} else {
			if a.privilegeObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.privilegeObjs.DiscardConfig,
				a.privilegeObjs.DiscardComms,
				a.privilegeObjs.DiscardPids,
				a.privilegeObjs.DiscardStats,
			)
		}
	}

	registerFromMount := func() {
		if a.outputMode == OutputModePerf {
			if a.perfMountObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.perfMountObjs.DiscardConfig,
				a.perfMountObjs.DiscardComms,
				a.perfMountObjs.DiscardPids,
				a.perfMountObjs.DiscardStats,
			)
		} else {
			if a.mountObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.mountObjs.DiscardConfig,
				a.mountObjs.DiscardComms,
				a.mountObjs.DiscardPids,
				a.mountObjs.DiscardStats,
			)
		}
	}

	registerFromModule := func() {
		if a.outputMode == OutputModePerf {
			if a.perfModuleObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.perfModuleObjs.DiscardConfig,
				a.perfModuleObjs.DiscardComms,
				a.perfModuleObjs.DiscardPids,
				a.perfModuleObjs.DiscardStats,
			)
		} else {
			if a.moduleObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.moduleObjs.DiscardConfig,
				a.moduleObjs.DiscardComms,
				a.moduleObjs.DiscardPids,
				a.moduleObjs.DiscardStats,
			)
		}
	}

	registerFromMemory := func() {
		if a.outputMode == OutputModePerf {
			if a.perfMemoryObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.perfMemoryObjs.DiscardConfig,
				a.perfMemoryObjs.DiscardComms,
				a.perfMemoryObjs.DiscardPids,
				a.perfMemoryObjs.DiscardStats,
			)
		} else {
			if a.memoryObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.memoryObjs.DiscardConfig,
				a.memoryObjs.DiscardComms,
				a.memoryObjs.DiscardPids,
				a.memoryObjs.DiscardStats,
			)
		}
	}

	registerFromDns := func() {
		if a.outputMode == OutputModePerf {
			if a.perfDnsObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.perfDnsObjs.DiscardConfig,
				a.perfDnsObjs.DiscardComms,
				a.perfDnsObjs.DiscardPids,
				a.perfDnsObjs.DiscardStats,
			)
		} else {
			if a.dnsObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.dnsObjs.DiscardConfig,
				a.dnsObjs.DiscardComms,
				a.dnsObjs.DiscardPids,
				a.dnsObjs.DiscardStats,
			)
		}
	}

	registerFromImds := func() {
		if a.outputMode == OutputModePerf {
			if a.perfImdsObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.perfImdsObjs.DiscardConfig,
				a.perfImdsObjs.DiscardComms,
				a.perfImdsObjs.DiscardPids,
				a.perfImdsObjs.DiscardStats,
			)
		} else {
			if a.imdsObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.imdsObjs.DiscardConfig,
				a.imdsObjs.DiscardComms,
				a.imdsObjs.DiscardPids,
				a.imdsObjs.DiscardStats,
			)
		}
	}

	registerFromBpfsyscall := func() {
		if a.outputMode == OutputModePerf {
			if a.perfBpfsyscallObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.perfBpfsyscallObjs.DiscardConfig,
				a.perfBpfsyscallObjs.DiscardComms,
				a.perfBpfsyscallObjs.DiscardPids,
				a.perfBpfsyscallObjs.DiscardStats,
			)
		} else {
			if a.bpfsyscallObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.bpfsyscallObjs.DiscardConfig,
				a.bpfsyscallObjs.DiscardComms,
				a.bpfsyscallObjs.DiscardPids,
				a.bpfsyscallObjs.DiscardStats,
			)
		}
	}

	registerFromMemfd := func() {
		if a.outputMode == OutputModePerf {
			if a.perfMemfdObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.perfMemfdObjs.DiscardConfig,
				a.perfMemfdObjs.DiscardComms,
				a.perfMemfdObjs.DiscardPids,
				a.perfMemfdObjs.DiscardStats,
			)
		} else {
			if a.memfdObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.memfdObjs.DiscardConfig,
				a.memfdObjs.DiscardComms,
				a.memfdObjs.DiscardPids,
				a.memfdObjs.DiscardStats,
			)
		}
	}

	registerFromIouring := func() {
		if a.outputMode == OutputModePerf {
			if a.perfIouringObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.perfIouringObjs.DiscardConfig,
				a.perfIouringObjs.DiscardComms,
				a.perfIouringObjs.DiscardPids,
				a.perfIouringObjs.DiscardStats,
			)
		} else {
			if a.iouringObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.iouringObjs.DiscardConfig,
				a.iouringObjs.DiscardComms,
				a.iouringObjs.DiscardPids,
				a.iouringObjs.DiscardStats,
			)
		}
	}

	registerFromNamespace := func() {
		if a.outputMode == OutputModePerf {
			if a.perfNamespaceObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.perfNamespaceObjs.DiscardConfig,
				a.perfNamespaceObjs.DiscardComms,
				a.perfNamespaceObjs.DiscardPids,
				a.perfNamespaceObjs.DiscardStats,
			)
		} else {
			if a.namespaceObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.namespaceObjs.DiscardConfig,
				a.namespaceObjs.DiscardComms,
				a.namespaceObjs.DiscardPids,
				a.namespaceObjs.DiscardStats,
			)
		}
	}

	registerFromCaps := func() {
		if a.outputMode == OutputModePerf {
			if a.perfCapsObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.perfCapsObjs.DiscardConfig,
				a.perfCapsObjs.DiscardComms,
				a.perfCapsObjs.DiscardPids,
				a.perfCapsObjs.DiscardStats,
			)
		} else {
			if a.capsObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.capsObjs.DiscardConfig,
				a.capsObjs.DiscardComms,
				a.capsObjs.DiscardPids,
				a.capsObjs.DiscardStats,
			)
		}
	}

	registerFromExecve()
	registerFromFileops()
	registerFromNetwork()
	registerFromProcess()
	registerFromPrivilege()
	registerFromMount()
	registerFromModule()
	registerFromMemory()
	registerFromDns()
	registerFromImds()
	registerFromBpfsyscall()
	registerFromMemfd()
	registerFromIouring()
	registerFromNamespace()
	registerFromCaps()

	registerFromDataexfil := func() {
		if a.outputMode == OutputModePerf {
			if a.perfDataexfilObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.perfDataexfilObjs.DiscardConfig,
				a.perfDataexfilObjs.DiscardComms,
				a.perfDataexfilObjs.DiscardPids,
				a.perfDataexfilObjs.DiscardStats,
			)
		} else {
			if a.dataexfilObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.dataexfilObjs.DiscardConfig,
				a.dataexfilObjs.DiscardComms,
				a.dataexfilObjs.DiscardPids,
				a.dataexfilObjs.DiscardStats,
			)
		}
	}

	registerFromDirops := func() {
		if a.outputMode == OutputModePerf {
			if a.perfDiropsObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.perfDiropsObjs.DiscardConfig,
				a.perfDiropsObjs.DiscardComms,
				a.perfDiropsObjs.DiscardPids,
				a.perfDiropsObjs.DiscardStats,
			)
		} else {
			if a.diropsObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.diropsObjs.DiscardConfig,
				a.diropsObjs.DiscardComms,
				a.diropsObjs.DiscardPids,
				a.diropsObjs.DiscardStats,
			)
		}
	}

	registerFromDataexfil()
	registerFromDirops()

	registerFromVfshooks := func() {
		if a.outputMode == OutputModePerf {
			if a.perfVfshooksObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.perfVfshooksObjs.DiscardConfig,
				a.perfVfshooksObjs.DiscardComms,
				a.perfVfshooksObjs.DiscardPids,
				a.perfVfshooksObjs.DiscardStats,
			)
		} else {
			if a.vfshooksObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.vfshooksObjs.DiscardConfig,
				a.vfshooksObjs.DiscardComms,
				a.vfshooksObjs.DiscardPids,
				a.vfshooksObjs.DiscardStats,
			)
		}
	}

	registerFromCredhooks := func() {
		if a.outputMode == OutputModePerf {
			if a.perfCredhooksObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.perfCredhooksObjs.DiscardConfig,
				a.perfCredhooksObjs.DiscardComms,
				a.perfCredhooksObjs.DiscardPids,
				a.perfCredhooksObjs.DiscardStats,
			)
		} else {
			if a.credhooksObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.credhooksObjs.DiscardConfig,
				a.credhooksObjs.DiscardComms,
				a.credhooksObjs.DiscardPids,
				a.credhooksObjs.DiscardStats,
			)
		}
	}

	registerFromIoctl := func() {
		if a.outputMode == OutputModePerf {
			if a.perfIoctlObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.perfIoctlObjs.DiscardConfig,
				a.perfIoctlObjs.DiscardComms,
				a.perfIoctlObjs.DiscardPids,
				a.perfIoctlObjs.DiscardStats,
			)
		} else {
			if a.ioctlObjs == nil {
				return
			}
			a.discarders.RegisterMaps(
				a.ioctlObjs.DiscardConfig,
				a.ioctlObjs.DiscardComms,
				a.ioctlObjs.DiscardPids,
				a.ioctlObjs.DiscardStats,
			)
		}
	}

	registerFromVfshooks()
	registerFromCredhooks()
	registerFromIoctl()

	nativeLog.Info().Int("programs", a.discarders.MapCount()).Msg("Registered discarder maps from BPF programs")
}


//! Self-imposed process restrictions. The scanner parses hostile input, so
//! once its inputs are known the process gives up everything it does not
//! need: the file system (Landlock), dangerous system calls (seccomp) and
//! unbounded memory (rlimit). A parser bug then has nowhere to go.
//!
//! Every layer is optional at run time: old kernels and containers with
//! their own seccomp profile may refuse some of them.

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Off,
    /// Apply what the kernel supports.
    BestEffort,
    /// Fail unless file system and system call restrictions both apply.
    Require,
}

/// Which layers took effect.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Status {
    pub filesystem: bool,
    pub syscalls: bool,
    pub memory: bool,
}

/// Restrict the current process. Afterwards only `readable` files can be
/// opened, and only for reading; already open descriptors keep working.
pub fn enter(mode: Mode, readable: &[&Path], memory_limit: Option<u64>) -> Result<Status, String> {
    if mode == Mode::Off {
        return Ok(Status::default());
    }
    let status = imp::enter(readable, memory_limit);
    if mode == Mode::Require && !(status.filesystem && status.syscalls) {
        return Err(format!(
            "sandbox could not be fully applied (file system: {}, system calls: {})",
            status.filesystem, status.syscalls
        ));
    }
    Ok(status)
}

#[cfg(target_os = "linux")]
mod imp {
    use std::collections::BTreeMap;
    use std::path::Path;

    use landlock::{
        ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetError, RulesetStatus,
    };
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};

    use super::Status;

    /// Calls a scanner never makes and an attacker with code execution wants:
    /// running programs, opening sockets, touching other processes, changing
    /// identity or namespaces, loading kernel code.
    const DENIED_SYSCALLS: &[libc::c_long] = &[
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_chroot,
        libc::SYS_pivot_root,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_setuid,
        libc::SYS_setgid,
        libc::SYS_kexec_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_userfaultfd,
        libc::SYS_io_uring_setup,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
    ];

    pub fn enter(readable: &[&Path], memory_limit: Option<u64>) -> Status {
        let memory = memory_limit.is_some_and(limit_memory);
        let unprivileged = no_new_privileges();
        Status {
            filesystem: unprivileged && restrict_filesystem(readable).unwrap_or(false),
            syscalls: unprivileged && restrict_syscalls().is_some(),
            memory,
        }
    }

    #[allow(unsafe_code)]
    fn limit_memory(bytes: u64) -> bool {
        let limit = libc::rlimit {
            rlim_cur: bytes,
            rlim_max: bytes,
        };
        // SAFETY: `limit` is a valid rlimit for the duration of the call.
        unsafe { libc::setrlimit(libc::RLIMIT_AS, &limit) == 0 }
    }

    /// Required before an unprivileged process may install either filter.
    #[allow(unsafe_code)]
    fn no_new_privileges() -> bool {
        // SAFETY: prctl with these constant arguments has no memory effects.
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 }
    }

    fn restrict_filesystem(readable: &[&Path]) -> Result<bool, RulesetError> {
        // Handle every access right the newest known ABI defines; the crate
        // drops the ones an older kernel does not know.
        let rules = readable
            .iter()
            // A path that does not exist gets no rule; opening it fails later
            // exactly as it would have without the sandbox.
            .filter_map(|path| PathFd::new(path).ok())
            .map(|fd| Ok::<_, RulesetError>(PathBeneath::new(fd, AccessFs::ReadFile)));
        let status = Ruleset::default()
            .handle_access(AccessFs::from_all(ABI::V5))?
            .create()?
            .add_rules(rules)?
            .restrict_self()?;
        Ok(status.ruleset != RulesetStatus::NotEnforced)
    }

    // `c_long` is 32 bits wide on 32-bit targets, where the conversion is real.
    #[allow(clippy::useless_conversion)]
    fn restrict_syscalls() -> Option<()> {
        let rules: BTreeMap<i64, Vec<_>> = DENIED_SYSCALLS
            .iter()
            .map(|&number| (i64::from(number), Vec::new()))
            .collect();
        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EPERM as u32),
            std::env::consts::ARCH.try_into().ok()?,
        )
        .ok()?;
        let program: BpfProgram = filter.try_into().ok()?;
        seccompiler::apply_filter(&program).ok()
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::path::Path;

    use super::Status;

    pub fn enter(_readable: &[&Path], _memory_limit: Option<u64>) -> Status {
        Status::default()
    }
}

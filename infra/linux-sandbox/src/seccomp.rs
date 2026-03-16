use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use af_sandbox::SyscallPolicy;

const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_NATIVE: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_NATIVE: u32 = 0xC000_00B7;

#[derive(Debug, Clone)]
pub(crate) struct PreparedSeccompFilter {
    instructions: Vec<libc::sock_filter>,
}

pub(crate) fn prepare_current_thread_filter(
    policy: SyscallPolicy,
) -> io::Result<Option<PreparedSeccompFilter>> {
    let prepared = match policy {
        SyscallPolicy::Unconfined => None,
        SyscallPolicy::Baseline => Some(PreparedSeccompFilter {
            instructions: baseline_filter(),
        }),
    };
    Ok(prepared)
}

pub(crate) fn apply_prepared_to_current_thread(filter: &PreparedSeccompFilter) -> io::Result<()> {
    apply_filter(&filter.instructions)
}

pub(crate) fn prepare_bwrap_seccomp_fd(policy: SyscallPolicy) -> io::Result<Option<OwnedFd>> {
    match policy {
        SyscallPolicy::Unconfined => Ok(None),
        SyscallPolicy::Baseline => {
            let filter = PreparedSeccompFilter {
                instructions: baseline_filter(),
            };
            Ok(Some(filter_to_fd(&filter.instructions)?))
        }
    }
}

fn apply_filter(filter: &[libc::sock_filter]) -> io::Result<()> {
    let mut program = libc::sock_fprog {
        len: u16::try_from(filter.len()).unwrap_or(u16::MAX),
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    let rc = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &mut program as *mut libc::sock_fprog,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn filter_to_fd(filter: &[libc::sock_filter]) -> io::Result<OwnedFd> {
    let name = CString::new("af-seccomp").expect("seccomp memfd name");
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let bytes = unsafe {
        std::slice::from_raw_parts(filter.as_ptr() as *const u8, std::mem::size_of_val(filter))
    };
    write_all_fd(fd.as_raw_fd(), bytes)?;

    let seek_rc = unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_SET) };
    if seek_rc < 0 {
        return Err(io::Error::last_os_error());
    }

    set_fd_inheritable(fd.as_raw_fd())?;
    Ok(fd)
}

fn set_fd_inheritable(fd: libc::c_int) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn write_all_fd(fd: libc::c_int, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        let written =
            unsafe { libc::write(fd, bytes.as_ptr() as *const libc::c_void, bytes.len()) };
        if written < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        let written = usize::try_from(written).unwrap_or(0);
        bytes = &bytes[written..];
    }
    Ok(())
}

fn baseline_filter() -> Vec<libc::sock_filter> {
    let mut instructions = vec![
        stmt(
            (libc::BPF_LD + libc::BPF_W + libc::BPF_ABS) as u16,
            SECCOMP_DATA_ARCH_OFFSET,
        ),
        jump(
            (libc::BPF_JMP + libc::BPF_JEQ + libc::BPF_K) as u16,
            AUDIT_ARCH_NATIVE,
            1,
            0,
        ),
        stmt(
            (libc::BPF_RET + libc::BPF_K) as u16,
            libc::SECCOMP_RET_KILL_PROCESS,
        ),
        stmt(
            (libc::BPF_LD + libc::BPF_W + libc::BPF_ABS) as u16,
            SECCOMP_DATA_NR_OFFSET,
        ),
    ];

    for syscall in blocked_syscalls() {
        instructions.push(jump(
            (libc::BPF_JMP + libc::BPF_JEQ + libc::BPF_K) as u16,
            *syscall as u32,
            0,
            1,
        ));
        instructions.push(stmt(
            (libc::BPF_RET + libc::BPF_K) as u16,
            libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32),
        ));
    }

    instructions.push(stmt(
        (libc::BPF_RET + libc::BPF_K) as u16,
        libc::SECCOMP_RET_ALLOW,
    ));
    instructions
}

fn blocked_syscalls() -> &'static [libc::c_long] {
    &[
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_keyctl,
        libc::SYS_kexec_load,
    ]
}

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;
    use std::os::fd::AsRawFd;

    use af_sandbox::SyscallPolicy;

    use super::{baseline_filter, prepare_bwrap_seccomp_fd};

    #[test]
    fn baseline_filter_is_non_empty_and_8byte_aligned() {
        let filter = baseline_filter();
        assert!(filter.len() > 5);
        assert_eq!(size_of::<libc::sock_filter>(), 8);
    }

    #[test]
    fn can_prepare_seccomp_fd_for_bwrap() {
        let fd = prepare_bwrap_seccomp_fd(SyscallPolicy::Baseline)
            .expect("create seccomp fd")
            .expect("baseline profile should produce a fd");
        assert!(fd.as_raw_fd() >= 0);
    }
}

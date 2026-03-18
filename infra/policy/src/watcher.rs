use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use crate::directory_loader::collect_watched_directories;
use crate::{PolicyInfraError, PolicyInfraResult, PolicyWatchEvent};

pub struct PolicyDirectoryWatcher {
    receiver: Receiver<PolicyInfraResult<PolicyWatchEvent>>,
    #[cfg(target_os = "linux")]
    shutdown_write_fd: std::os::fd::OwnedFd,
    #[cfg(target_os = "linux")]
    thread: Option<std::thread::JoinHandle<()>>,
}

impl PolicyDirectoryWatcher {
    pub fn start(root: impl Into<PathBuf>) -> PolicyInfraResult<Self> {
        let root = root.into();

        #[cfg(target_os = "linux")]
        {
            let (tx, rx) = mpsc::channel();
            let (ready_tx, ready_rx) = mpsc::channel();
            let (shutdown_read_fd, shutdown_write_fd) = new_shutdown_pipe()?;
            let thread_root = root.clone();
            let thread = std::thread::spawn(move || {
                if let Err(error) =
                    watch_loop(thread_root.clone(), shutdown_read_fd, tx.clone(), ready_tx)
                {
                    let _ = tx.send(Err(error));
                }
            });

            match ready_rx.recv() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(PolicyInfraError::WatchChannelClosed),
            }

            Ok(Self {
                receiver: rx,
                shutdown_write_fd,
                thread: Some(thread),
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = root;
            Err(PolicyInfraError::UnsupportedPlatform)
        }
    }

    pub fn recv(&self) -> PolicyInfraResult<PolicyWatchEvent> {
        match self.receiver.recv() {
            Ok(result) => result,
            Err(_) => Err(PolicyInfraError::WatchChannelClosed),
        }
    }

    pub fn recv_timeout(&self, timeout: Duration) -> PolicyInfraResult<Option<PolicyWatchEvent>> {
        match self.receiver.recv_timeout(timeout) {
            Ok(result) => result.map(Some),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(PolicyInfraError::WatchChannelClosed),
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for PolicyDirectoryWatcher {
    fn drop(&mut self) {
        let _ = signal_shutdown(&self.shutdown_write_fd);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl Drop for PolicyDirectoryWatcher {
    fn drop(&mut self) {}
}

#[cfg(target_os = "linux")]
fn watch_loop(
    root: PathBuf,
    shutdown_read_fd: std::os::fd::OwnedFd,
    tx: mpsc::Sender<PolicyInfraResult<PolicyWatchEvent>>,
    ready_tx: mpsc::Sender<PolicyInfraResult<()>>,
) -> PolicyInfraResult<()> {
    let mut state = match LinuxWatcherState::new(root.clone()) {
        Ok(state) => {
            let _ = ready_tx.send(Ok(()));
            state
        }
        Err(error) => {
            let _ = ready_tx.send(Err(PolicyInfraError::WatchBackend {
                message: error.to_string(),
            }));
            return Err(error);
        }
    };
    loop {
        let Some(paths) = state.wait_for_paths(&shutdown_read_fd)? else {
            return Ok(());
        };
        if paths.is_empty() {
            continue;
        }
        if tx
            .send(Ok(PolicyWatchEvent {
                root: root.clone(),
                paths,
            }))
            .is_err()
        {
            return Ok(());
        }
    }
}

#[cfg(target_os = "linux")]
struct LinuxWatcherState {
    root: PathBuf,
    inotify_fd: std::os::fd::OwnedFd,
    watch_by_descriptor: std::collections::HashMap<i32, PathBuf>,
    descriptor_by_path: std::collections::BTreeMap<PathBuf, i32>,
}

#[cfg(target_os = "linux")]
impl LinuxWatcherState {
    fn new(root: PathBuf) -> PolicyInfraResult<Self> {
        let inotify_fd = new_inotify_fd()?;
        let mut state = Self {
            root,
            inotify_fd,
            watch_by_descriptor: std::collections::HashMap::new(),
            descriptor_by_path: std::collections::BTreeMap::new(),
        };
        state.refresh_watches()?;
        Ok(state)
    }

    fn wait_for_paths(
        &mut self,
        shutdown_read_fd: &std::os::fd::OwnedFd,
    ) -> PolicyInfraResult<Option<Vec<PathBuf>>> {
        use std::os::fd::AsRawFd;

        loop {
            wait_for_readable(self.inotify_fd.as_raw_fd(), shutdown_read_fd.as_raw_fd())?;
            if shutdown_requested(shutdown_read_fd)? {
                return Ok(None);
            }

            let mut buffer = vec![0u8; 64 * 1024];
            let read_len = read_into(self.inotify_fd.as_raw_fd(), &mut buffer)?;
            if read_len == 0 {
                continue;
            }

            let mut paths = Vec::new();
            let mut refresh_watches = false;
            let mut offset = 0usize;
            let header_len = std::mem::size_of::<libc::inotify_event>();
            while offset < read_len {
                if read_len - offset < header_len {
                    return Err(PolicyInfraError::WatchBackend {
                        message: format!(
                            "malformed inotify payload: trailing bytes at offset {offset}"
                        ),
                    });
                }

                let event = read_inotify_event(&buffer, offset);
                let next_offset = offset
                    .checked_add(header_len)
                    .and_then(|value| value.checked_add(event.len as usize))
                    .ok_or_else(|| PolicyInfraError::WatchBackend {
                        message: format!(
                            "malformed inotify payload: event size overflow at offset {offset}"
                        ),
                    })?;
                if next_offset > read_len {
                    return Err(PolicyInfraError::WatchBackend {
                        message: format!(
                            "malformed inotify payload: event at offset {offset} exceeds read size {read_len}"
                        ),
                    });
                }

                if event.mask & libc::IN_Q_OVERFLOW != 0 {
                    paths.push(self.root.clone());
                    refresh_watches = true;
                    offset = next_offset;
                    continue;
                }

                let Some(path) = self.path_for_event(&buffer, offset, &event) else {
                    offset = next_offset;
                    continue;
                };

                if affects_policy_root(&self.root, &path) && is_mutating_event(event.mask) {
                    paths.push(path.clone());
                    refresh_watches = true;
                }

                offset = next_offset;
            }

            if refresh_watches {
                self.refresh_watches()?;
            }

            if !paths.is_empty() {
                return Ok(Some(paths));
            }
        }
    }

    fn refresh_watches(&mut self) -> PolicyInfraResult<()> {
        use std::os::fd::AsRawFd;

        let expected_paths = collect_watched_directories(&self.root)?
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();

        let current_paths = self
            .descriptor_by_path
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();

        for path in current_paths.difference(&expected_paths) {
            if let Some(descriptor) = self.descriptor_by_path.remove(path) {
                self.watch_by_descriptor.remove(&descriptor);
                remove_watch(self.inotify_fd.as_raw_fd(), descriptor);
            }
        }

        for path in expected_paths.difference(&current_paths) {
            let descriptor = add_watch(self.inotify_fd.as_raw_fd(), path)?;
            self.watch_by_descriptor.insert(descriptor, path.clone());
            self.descriptor_by_path.insert(path.clone(), descriptor);
        }

        Ok(())
    }

    fn path_for_event(
        &self,
        buffer: &[u8],
        offset: usize,
        event: &libc::inotify_event,
    ) -> Option<PathBuf> {
        let base = self.watch_by_descriptor.get(&event.wd)?.clone();
        if event.len == 0 {
            return Some(base);
        }

        let name_offset = offset + std::mem::size_of::<libc::inotify_event>();
        let name_end = name_offset.checked_add(event.len as usize)?;
        let name_bytes = buffer.get(name_offset..name_end)?;
        let name_len = name_bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name_bytes.len());
        if name_len == 0 {
            return Some(base);
        }

        use std::os::unix::ffi::OsStrExt;

        Some(base.join(Path::new(std::ffi::OsStr::from_bytes(
            &name_bytes[..name_len],
        ))))
    }
}

#[cfg(target_os = "linux")]
fn affects_policy_root(root: &Path, path: &Path) -> bool {
    path == root || path.starts_with(root)
}

#[cfg(target_os = "linux")]
fn is_mutating_event(mask: u32) -> bool {
    mask & (libc::IN_CREATE
        | libc::IN_DELETE
        | libc::IN_MODIFY
        | libc::IN_CLOSE_WRITE
        | libc::IN_ATTRIB
        | libc::IN_MOVED_FROM
        | libc::IN_MOVED_TO
        | libc::IN_DELETE_SELF
        | libc::IN_MOVE_SELF)
        != 0
}

#[cfg(target_os = "linux")]
fn new_shutdown_pipe() -> PolicyInfraResult<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    use std::os::fd::FromRawFd;

    let mut fds = [0; 2];
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
    if rc != 0 {
        return Err(last_os_error().into());
    }

    let read_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) };
    let write_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[1]) };
    Ok((read_fd, write_fd))
}

#[cfg(target_os = "linux")]
fn signal_shutdown(write_fd: &std::os::fd::OwnedFd) -> PolicyInfraResult<()> {
    use std::os::fd::AsRawFd;

    let value = [1u8];
    let rc = unsafe { libc::write(write_fd.as_raw_fd(), value.as_ptr().cast(), value.len()) };
    if rc < 0 {
        let error = last_os_error();
        if error.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(());
        }
        return Err(error.into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn shutdown_requested(read_fd: &std::os::fd::OwnedFd) -> PolicyInfraResult<bool> {
    use std::os::fd::AsRawFd;

    let mut buffer = [0u8; 8];
    let rc = unsafe {
        libc::read(
            read_fd.as_raw_fd(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
        )
    };
    if rc < 0 {
        let error = last_os_error();
        if error.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(false);
        }
        return Err(error.into());
    }
    Ok(rc > 0)
}

#[cfg(target_os = "linux")]
fn new_inotify_fd() -> PolicyInfraResult<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;

    let raw_fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    if raw_fd < 0 {
        return Err(last_os_error().into());
    }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw_fd) })
}

#[cfg(target_os = "linux")]
fn add_watch(inotify_fd: i32, path: &Path) -> PolicyInfraResult<i32> {
    use std::os::unix::ffi::OsStrExt;

    let raw_path = std::ffi::CString::new(path.as_os_str().as_bytes().to_vec()).map_err(|_| {
        PolicyInfraError::WatchBackend {
            message: format!("policy watch path contains NUL byte: {}", path.display()),
        }
    })?;

    let descriptor = unsafe {
        libc::inotify_add_watch(
            inotify_fd,
            raw_path.as_ptr(),
            libc::IN_CREATE
                | libc::IN_DELETE
                | libc::IN_MODIFY
                | libc::IN_CLOSE_WRITE
                | libc::IN_ATTRIB
                | libc::IN_MOVED_FROM
                | libc::IN_MOVED_TO
                | libc::IN_DELETE_SELF
                | libc::IN_MOVE_SELF,
        )
    };
    if descriptor < 0 {
        return Err(last_os_error().into());
    }
    Ok(descriptor)
}

#[cfg(target_os = "linux")]
fn remove_watch(inotify_fd: i32, descriptor: i32) {
    let _ = unsafe { libc::inotify_rm_watch(inotify_fd, descriptor) };
}

#[cfg(target_os = "linux")]
fn wait_for_readable(inotify_fd: i32, shutdown_fd: i32) -> PolicyInfraResult<()> {
    loop {
        let mut fds = [
            libc::pollfd {
                fd: inotify_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: shutdown_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if rc > 0 {
            return Ok(());
        }
        if rc == 0 {
            continue;
        }

        let error = last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(error.into());
    }
}

#[cfg(target_os = "linux")]
fn read_into(fd: i32, buffer: &mut [u8]) -> PolicyInfraResult<usize> {
    loop {
        let rc = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if rc >= 0 {
            return Ok(rc as usize);
        }

        let error = last_os_error();
        match error.kind() {
            std::io::ErrorKind::Interrupted => continue,
            std::io::ErrorKind::WouldBlock => return Ok(0),
            _ => return Err(error.into()),
        }
    }
}

#[cfg(target_os = "linux")]
fn read_inotify_event(buffer: &[u8], offset: usize) -> libc::inotify_event {
    unsafe { std::ptr::read_unaligned(buffer.as_ptr().add(offset).cast::<libc::inotify_event>()) }
}

#[cfg(target_os = "linux")]
fn last_os_error() -> std::io::Error {
    std::io::Error::last_os_error()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::Duration;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn emits_event_when_policy_file_changes() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path().join("policies");
        fs::create_dir_all(&root).expect("create policy dir");
        fs::write(root.join("base.yaml"), "version: 1").expect("write policy file");

        let watcher = PolicyDirectoryWatcher::start(&root).expect("start watcher");
        fs::write(root.join("base.yaml"), "version: 2").expect("rewrite policy file");

        let event = watcher
            .recv_timeout(Duration::from_secs(2))
            .expect("wait for watch event")
            .expect("watch event should arrive");
        assert_eq!(event.root, root);
        assert!(event.paths.iter().any(|path| path.ends_with("base.yaml")));
    }
}

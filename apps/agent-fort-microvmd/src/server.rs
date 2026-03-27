use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use af_microvm::control::{
    ExecuteResponse, HealthResponse, Request, Response, Runtime, WarmupResponse,
};
use anyhow::{Context, Result};
use tracing::{error, info, warn};

use crate::config::Config;

const CONNECTION_IO_TIMEOUT: Duration = Duration::from_secs(5);
const PRIVATE_DIR_MODE: u32 = 0o700;
const PRIVATE_SOCKET_MODE: u32 = 0o600;

pub struct Server<R> {
    config: Config,
    runtime: Arc<R>,
}

impl<R> Server<R>
where
    R: Runtime + 'static,
{
    pub fn new(config: Config, runtime: R) -> Self {
        Self {
            config,
            runtime: Arc::new(runtime),
        }
    }

    pub fn run(&self) -> Result<()> {
        cleanup_socket(&self.config.socket_path)?;
        if let Some(parent) = self.config.socket_path.parent() {
            let parent_exists = parent.exists();
            fs::create_dir_all(parent)
                .with_context(|| format!("create socket parent directory {}", parent.display()))?;
            if !parent_exists {
                fs::set_permissions(parent, fs::Permissions::from_mode(PRIVATE_DIR_MODE))
                    .with_context(|| format!("set socket directory mode {}", parent.display()))?;
            }
        }

        let listener = bind_listener(&self.config.socket_path)?;
        info!(socket = %self.config.socket_path.display(), "microvmd listening");

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let runtime = Arc::clone(&self.runtime);
                    thread::spawn(move || {
                        if let Err(error) = handle_connection(stream, runtime) {
                            warn!(error = %error, "connection closed with error");
                        }
                    });
                }
                Err(error) => {
                    error!(error = %error, "accept failed");
                }
            }
        }

        Ok(())
    }
}

fn handle_connection<R>(mut stream: UnixStream, runtime: Arc<R>) -> Result<()>
where
    R: Runtime,
{
    configure_stream(&stream, CONNECTION_IO_TIMEOUT)?;
    serve_stream(&mut stream, runtime)
}

fn serve_stream<R>(stream: &mut (impl Read + Write), runtime: Arc<R>) -> Result<()>
where
    R: Runtime,
{
    loop {
        let request = match Request::read_from(stream) {
            Ok(request) => request,
            Err(error) if should_close_connection(&error) => return Ok(()),
            Err(error) => return Err(error.into()),
        };

        let response = dispatch(runtime.as_ref(), request);
        response.write_to(stream)?;
    }
}

fn dispatch(runtime: &impl Runtime, request: Request) -> Response {
    match request {
        Request::Execute(request) => match request.validate() {
            Ok(()) => match runtime.execute(request) {
                Ok(response) => Response::Execute(response),
                Err(error) => Response::Execute(ExecuteResponse::err(exec_error(error))),
            },
            Err(error) => Response::Execute(ExecuteResponse::err(exec_error(error))),
        },
        Request::Warmup(request) => match request.validate() {
            Ok(()) => match runtime.warmup(request) {
                Ok(response) => Response::Warmup(response),
                Err(error) => Response::Warmup(WarmupResponse::err(exec_error(error))),
            },
            Err(error) => Response::Warmup(WarmupResponse::err(exec_error(error))),
        },
        Request::Health => match runtime.health() {
            Ok(response) => Response::Health(response),
            Err(error) => {
                Response::Health(HealthResponse::err("internal_error", error.to_string()))
            }
        },
    }
}

fn exec_error(error: af_microvm::Error) -> af_microvm::control::ExecError {
    af_microvm::control::ExecError {
        code: af_microvm::control::ErrorCode::BackendUnavailable,
        message: error.to_string(),
    }
}

fn bind_listener(path: &Path) -> Result<UnixListener> {
    // Apply a restrictive umask during bind so the socket is private from creation.
    let previous_umask = unsafe { libc::umask(0o177) };
    let listener = UnixListener::bind(path);
    unsafe {
        libc::umask(previous_umask);
    }

    let listener = listener.with_context(|| format!("bind {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_SOCKET_MODE))
        .with_context(|| format!("set socket mode {}", path.display()))?;
    Ok(listener)
}

fn configure_stream(stream: &UnixStream, timeout: Duration) -> Result<()> {
    stream
        .set_read_timeout(Some(timeout))
        .context("set read timeout")?;
    stream
        .set_write_timeout(Some(timeout))
        .context("set write timeout")?;
    Ok(())
}

fn should_close_connection(error: &af_microvm::Error) -> bool {
    match error {
        af_microvm::Error::Io(error) => matches!(
            error.kind(),
            ErrorKind::UnexpectedEof
                | ErrorKind::ConnectionReset
                | ErrorKind::TimedOut
                | ErrorKind::WouldBlock
        ),
        _ => false,
    }
}

fn cleanup_socket(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_socket() {
                fs::remove_file(path)
                    .with_context(|| format!("remove stale socket {}", path.display()))?;
                Ok(())
            } else {
                anyhow::bail!("socket path is not a socket: {}", path.display())
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect socket path {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use af_microvm::control::{
        ExecuteRequest, ExecuteResponse, HealthResponse, Limits, Request, Response, Runtime, Trace,
        WarmupRequest, WarmupResponse,
    };

    use super::*;

    #[derive(Debug)]
    struct TestRuntime;

    impl Runtime for TestRuntime {
        fn execute(&self, request: ExecuteRequest) -> af_microvm::Result<ExecuteResponse> {
            Ok(ExecuteResponse::err(af_microvm::control::ExecError {
                code: af_microvm::control::ErrorCode::ExecFailed,
                message: format!("{} {}", request.profile_id, request.command[0]),
            }))
        }

        fn warmup(&self, _request: WarmupRequest) -> af_microvm::Result<WarmupResponse> {
            Ok(WarmupResponse::ok())
        }

        fn health(&self) -> af_microvm::Result<HealthResponse> {
            Ok(HealthResponse::ok())
        }
    }

    #[test]
    fn dispatch_health() {
        let response = dispatch(&TestRuntime, Request::Health);
        assert_eq!(response, Response::Health(HealthResponse::ok()));
    }

    #[test]
    fn dispatch_execute_invalid_request() {
        let response = dispatch(
            &TestRuntime,
            Request::Execute(ExecuteRequest {
                request_id: String::new(),
                profile_id: "default".to_string(),
                command: vec!["python".to_string()],
                cwd: PathBuf::from("/workspace"),
                env: BTreeMap::new(),
                stdin: None,
                limits: Limits {
                    timeout_ms: 1_000,
                    ..Limits::default()
                },
                trace: Trace::default(),
            }),
        );

        match response {
            Response::Execute(response) => {
                assert!(!response.ok);
                assert!(response.error.is_some());
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn serve_stream_closes_timed_out_client() {
        let mut stream = TimeoutStream;
        serve_stream(&mut stream, Arc::new(TestRuntime))
            .expect("timeout should close stalled connection");
    }

    struct TimeoutStream;

    impl Read for TimeoutStream {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(ErrorKind::TimedOut, "timed out"))
        }
    }

    impl Write for TimeoutStream {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            panic!("write should not be called");
        }

        fn flush(&mut self) -> std::io::Result<()> {
            panic!("flush should not be called");
        }
    }
}

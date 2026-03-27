use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::thread;

use af_microvm::control::{
    ExecuteResponse, HealthResponse, Request, Response, Runtime, WarmupResponse,
};
use anyhow::{Context, Result};
use tracing::{error, info, warn};

use crate::config::Config;

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
            fs::create_dir_all(parent)
                .with_context(|| format!("create socket parent directory {}", parent.display()))?;
        }

        let listener = UnixListener::bind(&self.config.socket_path)
            .with_context(|| format!("bind {}", self.config.socket_path.display()))?;
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
    loop {
        let request = match Request::read_from(&mut stream) {
            Ok(request) => request,
            Err(af_microvm::Error::Io(error)) if error.kind() == ErrorKind::UnexpectedEof => {
                return Ok(());
            }
            Err(af_microvm::Error::Io(error)) if error.kind() == ErrorKind::ConnectionReset => {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };

        let response = dispatch(runtime.as_ref(), request);
        response.write_to(&mut stream)?;
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
}

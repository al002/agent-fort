#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io::ErrorKind;
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
#[cfg(unix)]
use std::path::Path;

#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

use crate::endpoint::Endpoint;
use crate::error::TransportError;

#[cfg(unix)]
pub fn bind(endpoint: &Endpoint) -> Result<UnixListener, TransportError> {
    let path = unix_path(endpoint)?;
    prepare_socket_path(path)?;
    Ok(UnixListener::bind(path)?)
}

#[cfg(unix)]
pub async fn connect(endpoint: &Endpoint) -> Result<UnixStream, TransportError> {
    let path = unix_path(endpoint)?;
    let stream = UnixStream::connect(path).await?;
    Ok(stream)
}

#[cfg(unix)]
pub async fn accept(listener: &UnixListener) -> Result<UnixStream, TransportError> {
    let (stream, _) = listener.accept().await?;
    Ok(stream)
}

#[cfg(unix)]
pub fn cleanup(endpoint: &Endpoint) -> Result<(), TransportError> {
    let path = unix_path(endpoint)?;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(TransportError::Io(err)),
    };

    if metadata.file_type().is_socket() {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            Err(err) => Err(TransportError::Io(err)),
        }
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn unix_path(endpoint: &Endpoint) -> Result<&Path, TransportError> {
    match endpoint {
        Endpoint::Unix(path) => Ok(path.as_path()),
        Endpoint::NamedPipe(pipe) => Err(TransportError::UnsupportedEndpoint(format!(
            "named pipe `{pipe}` is not available on unix"
        ))),
    }
}

#[cfg(unix)]
fn prepare_socket_path(path: &Path) -> Result<(), TransportError> {
    let parent = path.parent().ok_or_else(|| {
        TransportError::InvalidEndpoint(format!(
            "unix socket path `{}` has no parent directory",
            path.display()
        ))
    })?;
    fs::create_dir_all(parent)?;

    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(TransportError::Io(err)),
    };

    if !metadata.file_type().is_socket() {
        return Err(TransportError::InvalidEndpoint(format!(
            "path `{}` exists and is not a socket",
            path.display()
        )));
    }

    fs::remove_file(path)?;
    Ok(())
}

#[cfg(not(unix))]
mod stubs {
    use crate::{endpoint::Endpoint, error::TransportError};

    #[derive(Debug)]
    pub struct UnixListener;

    #[derive(Debug)]
    pub struct UnixStream;

    pub fn bind(_endpoint: &Endpoint) -> Result<UnixListener, TransportError> {
        Err(TransportError::UnsupportedEndpoint(
            "unix socket transport is not available on this platform".to_string(),
        ))
    }

    pub async fn connect(_endpoint: &Endpoint) -> Result<UnixStream, TransportError> {
        Err(TransportError::UnsupportedEndpoint(
            "unix socket transport is not available on this platform".to_string(),
        ))
    }

    pub async fn accept(_listener: &UnixListener) -> Result<UnixStream, TransportError> {
        Err(TransportError::UnsupportedEndpoint(
            "unix socket transport is not available on this platform".to_string(),
        ))
    }

    pub fn cleanup(_endpoint: &Endpoint) -> Result<(), TransportError> {
        Ok(())
    }
}

#[cfg(not(unix))]
pub use stubs::*;

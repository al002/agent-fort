use crate::{endpoint::Endpoint, error::TransportError};

#[derive(Debug)]
pub struct WindowsListener;

#[derive(Debug)]
pub struct WindowsStream;

pub fn bind_named_pipe(_endpoint: &Endpoint) -> Result<WindowsListener, TransportError> {
    Err(TransportError::UnsupportedEndpoint(
        "windows named pipe transport is reserved but not implemented yet".to_string(),
    ))
}

pub async fn connect_named_pipe(_endpoint: &Endpoint) -> Result<WindowsStream, TransportError> {
    Err(TransportError::UnsupportedEndpoint(
        "windows named pipe transport is reserved but not implemented yet".to_string(),
    ))
}

pub async fn accept_named_pipe(
    _listener: &WindowsListener,
) -> Result<WindowsStream, TransportError> {
    Err(TransportError::UnsupportedEndpoint(
        "windows named pipe transport is reserved but not implemented yet".to_string(),
    ))
}

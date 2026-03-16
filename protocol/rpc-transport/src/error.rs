use std::io;

use prost::DecodeError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("unsupported endpoint: {0}")]
    UnsupportedEndpoint(String),
    #[error("frame too large: {size} bytes exceeds max {max} bytes")]
    FrameTooLarge { size: usize, max: usize },
    #[error("invalid frame: {0}")]
    InvalidFrame(String),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("protobuf decode error: {0}")]
    Decode(#[from] DecodeError),
}

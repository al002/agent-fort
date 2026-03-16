use std::path::PathBuf;

use crate::error::TransportError;

const UNIX_SCHEME: &str = "unix://";
const NPIPE_SCHEME: &str = "npipe://";
const WINDOWS_PIPE_PREFIX: &str = r"\\.\pipe\";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    Unix,
    NamedPipe,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Unix(PathBuf),
    NamedPipe(String),
}

impl Endpoint {
    pub fn parse(raw: &str) -> Result<Self, TransportError> {
        let value = raw.trim();
        if value.is_empty() {
            return Err(TransportError::InvalidEndpoint(
                "endpoint cannot be empty".to_string(),
            ));
        }

        if let Some(path) = value.strip_prefix(UNIX_SCHEME) {
            if path.is_empty() {
                return Err(TransportError::InvalidEndpoint(
                    "unix endpoint path cannot be empty".to_string(),
                ));
            }
            return Ok(Self::Unix(PathBuf::from(path)));
        }

        if let Some(pipe) = value.strip_prefix(NPIPE_SCHEME) {
            return Ok(Self::NamedPipe(normalize_pipe_name(pipe)?));
        }

        if value.contains("://") {
            return Err(TransportError::InvalidEndpoint(format!(
                "unsupported endpoint scheme in `{value}`"
            )));
        }

        if value.starts_with(WINDOWS_PIPE_PREFIX) {
            return Ok(Self::NamedPipe(value.to_string()));
        }

        #[cfg(windows)]
        {
            Ok(Self::NamedPipe(normalize_pipe_name(value)?))
        }
        #[cfg(not(windows))]
        {
            Ok(Self::Unix(PathBuf::from(value)))
        }
    }

    pub fn kind(&self) -> EndpointKind {
        match self {
            Self::Unix(_) => EndpointKind::Unix,
            Self::NamedPipe(_) => EndpointKind::NamedPipe,
        }
    }

    pub fn as_uri(&self) -> String {
        match self {
            Self::Unix(path) => format!("{UNIX_SCHEME}{}", path.display()),
            Self::NamedPipe(name) => format!("{NPIPE_SCHEME}{name}"),
        }
    }
}

fn normalize_pipe_name(value: &str) -> Result<String, TransportError> {
    let name = value.trim();
    if name.is_empty() {
        return Err(TransportError::InvalidEndpoint(
            "named pipe cannot be empty".to_string(),
        ));
    }

    if name.starts_with(WINDOWS_PIPE_PREFIX) {
        return Ok(name.to_string());
    }
    if name.contains('\\') {
        return Err(TransportError::InvalidEndpoint(format!(
            "invalid named pipe `{name}`"
        )));
    }

    Ok(format!("{WINDOWS_PIPE_PREFIX}{name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unix_scheme() {
        let endpoint = Endpoint::parse("unix:///tmp/agent-fortd.sock").expect("parse should work");
        assert_eq!(
            endpoint,
            Endpoint::Unix(PathBuf::from("/tmp/agent-fortd.sock"))
        );
    }

    #[test]
    fn parses_npipe_scheme() {
        let endpoint = Endpoint::parse("npipe://agent-fortd").expect("parse should work");
        assert_eq!(
            endpoint,
            Endpoint::NamedPipe(String::from(r"\\.\pipe\agent-fortd"))
        );
    }

    #[test]
    fn rejects_unknown_scheme() {
        let error = Endpoint::parse("tcp://127.0.0.1:1234").expect_err("must reject");
        assert!(matches!(error, TransportError::InvalidEndpoint(_)));
    }
}

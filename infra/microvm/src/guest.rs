use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::PathBuf;

use af_microvm_proto::codec::{decode_message, encode_message};
use af_microvm_proto::{GuestExecRequest, GuestExecResponse};

use crate::{Error, Result, read_frame, write_frame};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    Succeeded,
    Failed,
    TimedOut,
    Cancelled,
}

impl TryFrom<i32> for ExitStatus {
    type Error = Error;

    fn try_from(value: i32) -> Result<Self> {
        match af_microvm_proto::GuestExitStatus::try_from(value) {
            Ok(af_microvm_proto::GuestExitStatus::Succeeded) => Ok(Self::Succeeded),
            Ok(af_microvm_proto::GuestExitStatus::Failed) => Ok(Self::Failed),
            Ok(af_microvm_proto::GuestExitStatus::TimedOut) => Ok(Self::TimedOut),
            Ok(af_microvm_proto::GuestExitStatus::Cancelled) => Ok(Self::Cancelled),
            Ok(af_microvm_proto::GuestExitStatus::Unspecified) | Err(_) => {
                Err(Error::Invalid("invalid guest exit status".into()))
            }
        }
    }
}

impl From<ExitStatus> for i32 {
    fn from(value: ExitStatus) -> Self {
        match value {
            ExitStatus::Succeeded => af_microvm_proto::GuestExitStatus::Succeeded as i32,
            ExitStatus::Failed => af_microvm_proto::GuestExitStatus::Failed as i32,
            ExitStatus::TimedOut => af_microvm_proto::GuestExitStatus::TimedOut as i32,
            ExitStatus::Cancelled => af_microvm_proto::GuestExitStatus::Cancelled as i32,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
    pub stdin: Option<String>,
    pub timeout_ms: u64,
    pub stdout_max_bytes: u64,
    pub stderr_max_bytes: u64,
}

impl Request {
    pub fn validate(&self) -> Result<()> {
        if self.command.is_empty() {
            return Err(Error::Invalid("command is empty".into()));
        }
        if self.command[0].is_empty() {
            return Err(Error::Invalid("command[0] is empty".into()));
        }
        if !self.cwd.is_absolute() {
            return Err(Error::Invalid("cwd is not absolute".into()));
        }
        if self.timeout_ms == 0 {
            return Err(Error::Invalid("timeout_ms is 0".into()));
        }
        if self.stdout_max_bytes == 0 {
            return Err(Error::Invalid("stdout_max_bytes is 0".into()));
        }
        if self.stderr_max_bytes == 0 {
            return Err(Error::Invalid("stderr_max_bytes is 0".into()));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_message(&GuestExecRequest::from(self.clone()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let request = decode_message::<GuestExecRequest>(bytes)?;
        request.try_into()
    }

    pub fn write_to(&self, writer: &mut impl Write) -> Result<()> {
        self.validate()?;
        write_frame(writer, &self.encode())
    }

    pub fn read_from(reader: &mut impl Read) -> Result<Self> {
        let bytes = read_frame(reader)?;
        Self::decode(&bytes)
    }
}

impl TryFrom<GuestExecRequest> for Request {
    type Error = Error;

    fn try_from(value: GuestExecRequest) -> Result<Self> {
        Ok(Self {
            command: value.command,
            cwd: PathBuf::from(value.cwd),
            env: value.env.into_iter().collect(),
            stdin: value.stdin,
            timeout_ms: value.timeout_ms,
            stdout_max_bytes: value.stdout_max_bytes,
            stderr_max_bytes: value.stderr_max_bytes,
        })
    }
}

impl From<Request> for GuestExecRequest {
    fn from(value: Request) -> Self {
        Self {
            command: value.command,
            cwd: value.cwd.display().to_string(),
            env: value.env.into_iter().collect(),
            stdin: value.stdin,
            timeout_ms: value.timeout_ms,
            stdout_max_bytes: value.stdout_max_bytes,
            stderr_max_bytes: value.stderr_max_bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: ExitStatus,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

impl Response {
    pub fn encode(&self) -> Vec<u8> {
        encode_message(&GuestExecResponse::from(self.clone()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let response = decode_message::<GuestExecResponse>(bytes)?;
        response.try_into()
    }

    pub fn write_to(&self, writer: &mut impl Write) -> Result<()> {
        write_frame(writer, &self.encode())
    }

    pub fn read_from(reader: &mut impl Read) -> Result<Self> {
        let bytes = read_frame(reader)?;
        Self::decode(&bytes)
    }
}

impl TryFrom<GuestExecResponse> for Response {
    type Error = Error;

    fn try_from(value: GuestExecResponse) -> Result<Self> {
        Ok(Self {
            status: value.status.try_into()?,
            exit_code: value.exit_code,
            timed_out: value.timed_out,
            stdout: value.stdout,
            stderr: value.stderr,
            stdout_truncated: value.stdout_truncated,
            stderr_truncated: value.stderr_truncated,
        })
    }
}

impl From<Response> for GuestExecResponse {
    fn from(value: Response) -> Self {
        Self {
            status: value.status.into(),
            exit_code: value.exit_code,
            timed_out: value.timed_out,
            stdout: value.stdout,
            stderr: value.stderr,
            stdout_truncated: value.stdout_truncated,
            stderr_truncated: value.stderr_truncated,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip() {
        let request = Request {
            command: vec!["node".to_string(), "index.js".to_string()],
            cwd: PathBuf::from("/workspace"),
            env: BTreeMap::from([(String::from("NODE_ENV"), String::from("test"))]),
            stdin: Some("data".to_string()),
            timeout_ms: 5_000,
            stdout_max_bytes: 1024,
            stderr_max_bytes: 2048,
        };
        let bytes = request.encode();
        let decoded = Request::decode(&bytes).expect("decode request");
        assert_eq!(decoded, request);
    }

    #[test]
    fn response_round_trip() {
        let response = Response {
            status: ExitStatus::Succeeded,
            exit_code: Some(0),
            timed_out: false,
            stdout: "ok".to_string(),
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        };
        let bytes = response.encode();
        let decoded = Response::decode(&bytes).expect("decode response");
        assert_eq!(decoded, response);
    }

    #[test]
    fn request_needs_timeout() {
        let error = Request {
            command: vec!["python".to_string()],
            cwd: PathBuf::from("/workspace"),
            env: BTreeMap::new(),
            stdin: None,
            timeout_ms: 0,
            stdout_max_bytes: 1024,
            stderr_max_bytes: 1024,
        }
        .validate()
        .expect_err("request should reject zero timeout");
        assert!(matches!(error, Error::Invalid(_)));
    }
}

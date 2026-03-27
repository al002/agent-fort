use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::PathBuf;

use af_microvm_proto::codec::{decode_message, encode_message};
use af_microvm_proto::{
    MicrovmControlRequest, MicrovmControlResponse, MicrovmExecError, MicrovmExecResult,
    MicrovmExecuteRequest, MicrovmExecuteResponse, MicrovmHealthRequest, MicrovmHealthResponse,
    MicrovmLimits, MicrovmMetrics, MicrovmWarmupRequest, MicrovmWarmupResponse, TraceMeta,
    microvm_control_request, microvm_control_response,
};

use crate::{Error, Result, read_frame, write_frame};

pub trait Runtime: Send + Sync {
    fn execute(&self, request: ExecuteRequest) -> Result<ExecuteResponse>;
    fn warmup(&self, request: WarmupRequest) -> Result<WarmupResponse>;
    fn health(&self) -> Result<HealthResponse>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Execute(ExecuteRequest),
    Warmup(WarmupRequest),
    Health,
}

impl Request {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Execute(request) => request.validate(),
            Self::Warmup(request) => request.validate(),
            Self::Health => Ok(()),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let kind = match self {
            Self::Execute(request) => {
                microvm_control_request::Kind::Execute(request.clone().into())
            }
            Self::Warmup(request) => microvm_control_request::Kind::Warmup(request.clone().into()),
            Self::Health => microvm_control_request::Kind::Health(MicrovmHealthRequest {}),
        };
        encode_message(&MicrovmControlRequest { kind: Some(kind) })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let request = decode_message::<MicrovmControlRequest>(bytes)?;
        Self::try_from(request)
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

impl TryFrom<MicrovmControlRequest> for Request {
    type Error = Error;

    fn try_from(value: MicrovmControlRequest) -> Result<Self> {
        match value.kind {
            Some(microvm_control_request::Kind::Execute(request)) => {
                Ok(Self::Execute(request.try_into()?))
            }
            Some(microvm_control_request::Kind::Warmup(request)) => {
                Ok(Self::Warmup(request.into()))
            }
            Some(microvm_control_request::Kind::Health(_)) => Ok(Self::Health),
            None => Err(Error::Invalid("control request kind is missing".into())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Execute(ExecuteResponse),
    Warmup(WarmupResponse),
    Health(HealthResponse),
}

impl Response {
    pub fn encode(&self) -> Vec<u8> {
        let kind = match self {
            Self::Execute(response) => {
                microvm_control_response::Kind::Execute(response.clone().into())
            }
            Self::Warmup(response) => {
                microvm_control_response::Kind::Warmup(response.clone().into())
            }
            Self::Health(response) => {
                microvm_control_response::Kind::Health(response.clone().into())
            }
        };
        encode_message(&MicrovmControlResponse { kind: Some(kind) })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let response = decode_message::<MicrovmControlResponse>(bytes)?;
        Self::try_from(response)
    }

    pub fn write_to(&self, writer: &mut impl Write) -> Result<()> {
        write_frame(writer, &self.encode())
    }

    pub fn read_from(reader: &mut impl Read) -> Result<Self> {
        let bytes = read_frame(reader)?;
        Self::decode(&bytes)
    }
}

impl TryFrom<MicrovmControlResponse> for Response {
    type Error = Error;

    fn try_from(value: MicrovmControlResponse) -> Result<Self> {
        match value.kind {
            Some(microvm_control_response::Kind::Execute(response)) => {
                Ok(Self::Execute(response.try_into()?))
            }
            Some(microvm_control_response::Kind::Warmup(response)) => {
                Ok(Self::Warmup(response.try_into()?))
            }
            Some(microvm_control_response::Kind::Health(response)) => {
                Ok(Self::Health(response.into()))
            }
            None => Err(Error::Invalid("control response kind is missing".into())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Limits {
    pub cpu_ms: u64,
    pub memory_mb: u64,
    pub pids: u32,
    pub disk_mb: u64,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Trace {
    pub trace_id: Option<String>,
    pub client_instance_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecuteRequest {
    pub request_id: String,
    pub profile_id: String,
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
    pub stdin: Option<String>,
    pub limits: Limits,
    pub trace: Trace,
}

impl ExecuteRequest {
    pub fn validate(&self) -> Result<()> {
        if self.request_id.is_empty() {
            return Err(Error::Invalid("request_id is empty".into()));
        }
        if self.profile_id.is_empty() {
            return Err(Error::Invalid("profile_id is empty".into()));
        }
        if self.command.is_empty() {
            return Err(Error::Invalid("command is empty".into()));
        }
        if self.command[0].is_empty() {
            return Err(Error::Invalid("command[0] is empty".into()));
        }
        if !self.cwd.is_absolute() {
            return Err(Error::Invalid("cwd is not absolute".into()));
        }
        if self.limits.timeout_ms == 0 {
            return Err(Error::Invalid("timeout_ms is 0".into()));
        }
        Ok(())
    }
}

impl TryFrom<MicrovmExecuteRequest> for ExecuteRequest {
    type Error = Error;

    fn try_from(value: MicrovmExecuteRequest) -> Result<Self> {
        Ok(Self {
            request_id: value.request_id,
            profile_id: value.profile_id,
            command: value.command,
            cwd: PathBuf::from(value.cwd),
            env: value.env.into_iter().collect(),
            stdin: value.stdin,
            limits: value.limits.map(Into::into).unwrap_or_default(),
            trace: value.trace.map(Into::into).unwrap_or_default(),
        })
    }
}

impl From<ExecuteRequest> for MicrovmExecuteRequest {
    fn from(value: ExecuteRequest) -> Self {
        Self {
            request_id: value.request_id,
            profile_id: value.profile_id,
            command: value.command,
            cwd: value.cwd.display().to_string(),
            env: value.env.into_iter().collect(),
            stdin: value.stdin,
            limits: Some(value.limits.into()),
            trace: Some(value.trace.into()),
        }
    }
}

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
        match af_microvm_proto::MicrovmExitStatus::try_from(value) {
            Ok(af_microvm_proto::MicrovmExitStatus::Succeeded) => Ok(Self::Succeeded),
            Ok(af_microvm_proto::MicrovmExitStatus::Failed) => Ok(Self::Failed),
            Ok(af_microvm_proto::MicrovmExitStatus::TimedOut) => Ok(Self::TimedOut),
            Ok(af_microvm_proto::MicrovmExitStatus::Cancelled) => Ok(Self::Cancelled),
            Ok(af_microvm_proto::MicrovmExitStatus::Unspecified) | Err(_) => {
                Err(Error::Invalid("invalid exit status".into()))
            }
        }
    }
}

impl From<ExitStatus> for i32 {
    fn from(value: ExitStatus) -> Self {
        match value {
            ExitStatus::Succeeded => af_microvm_proto::MicrovmExitStatus::Succeeded as i32,
            ExitStatus::Failed => af_microvm_proto::MicrovmExitStatus::Failed as i32,
            ExitStatus::TimedOut => af_microvm_proto::MicrovmExitStatus::TimedOut as i32,
            ExitStatus::Cancelled => af_microvm_proto::MicrovmExitStatus::Cancelled as i32,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Metrics {
    pub queue_wait_ms: u64,
    pub boot_ms: u64,
    pub exec_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResult {
    pub status: ExitStatus,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub vm_id: String,
    pub lease_source: String,
    pub metrics: Metrics,
}

impl TryFrom<MicrovmExecResult> for ExecResult {
    type Error = Error;

    fn try_from(value: MicrovmExecResult) -> Result<Self> {
        Ok(Self {
            status: value.status.try_into()?,
            exit_code: value.exit_code,
            timed_out: value.timed_out,
            stdout: value.stdout,
            stderr: value.stderr,
            stdout_truncated: value.stdout_truncated,
            stderr_truncated: value.stderr_truncated,
            vm_id: value.vm_id,
            lease_source: value.lease_source,
            metrics: value.metrics.map(Into::into).unwrap_or_default(),
        })
    }
}

impl From<ExecResult> for MicrovmExecResult {
    fn from(value: ExecResult) -> Self {
        Self {
            status: value.status.into(),
            exit_code: value.exit_code,
            timed_out: value.timed_out,
            stdout: value.stdout,
            stderr: value.stderr,
            stdout_truncated: value.stdout_truncated,
            stderr_truncated: value.stderr_truncated,
            vm_id: value.vm_id,
            lease_source: value.lease_source,
            metrics: Some(value.metrics.into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    QueueTimeout,
    PoolExhausted,
    VmBootFailed,
    VmRestoreFailed,
    GuestChannelFailed,
    ExecTimeout,
    ExecFailed,
    BackendUnavailable,
}

impl TryFrom<i32> for ErrorCode {
    type Error = Error;

    fn try_from(value: i32) -> Result<Self> {
        match af_microvm_proto::MicrovmErrorCode::try_from(value) {
            Ok(af_microvm_proto::MicrovmErrorCode::QueueTimeout) => Ok(Self::QueueTimeout),
            Ok(af_microvm_proto::MicrovmErrorCode::PoolExhausted) => Ok(Self::PoolExhausted),
            Ok(af_microvm_proto::MicrovmErrorCode::VmBootFailed) => Ok(Self::VmBootFailed),
            Ok(af_microvm_proto::MicrovmErrorCode::VmRestoreFailed) => Ok(Self::VmRestoreFailed),
            Ok(af_microvm_proto::MicrovmErrorCode::GuestChannelFailed) => {
                Ok(Self::GuestChannelFailed)
            }
            Ok(af_microvm_proto::MicrovmErrorCode::ExecTimeout) => Ok(Self::ExecTimeout),
            Ok(af_microvm_proto::MicrovmErrorCode::ExecFailed) => Ok(Self::ExecFailed),
            Ok(af_microvm_proto::MicrovmErrorCode::BackendUnavailable) => {
                Ok(Self::BackendUnavailable)
            }
            Ok(af_microvm_proto::MicrovmErrorCode::Unspecified) | Err(_) => {
                Err(Error::Invalid("invalid error code".into()))
            }
        }
    }
}

impl From<ErrorCode> for i32 {
    fn from(value: ErrorCode) -> Self {
        match value {
            ErrorCode::QueueTimeout => af_microvm_proto::MicrovmErrorCode::QueueTimeout as i32,
            ErrorCode::PoolExhausted => af_microvm_proto::MicrovmErrorCode::PoolExhausted as i32,
            ErrorCode::VmBootFailed => af_microvm_proto::MicrovmErrorCode::VmBootFailed as i32,
            ErrorCode::VmRestoreFailed => {
                af_microvm_proto::MicrovmErrorCode::VmRestoreFailed as i32
            }
            ErrorCode::GuestChannelFailed => {
                af_microvm_proto::MicrovmErrorCode::GuestChannelFailed as i32
            }
            ErrorCode::ExecTimeout => af_microvm_proto::MicrovmErrorCode::ExecTimeout as i32,
            ErrorCode::ExecFailed => af_microvm_proto::MicrovmErrorCode::ExecFailed as i32,
            ErrorCode::BackendUnavailable => {
                af_microvm_proto::MicrovmErrorCode::BackendUnavailable as i32
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecError {
    pub code: ErrorCode,
    pub message: String,
}

impl TryFrom<MicrovmExecError> for ExecError {
    type Error = Error;

    fn try_from(value: MicrovmExecError) -> Result<Self> {
        Ok(Self {
            code: value.code.try_into()?,
            message: value.message,
        })
    }
}

impl From<ExecError> for MicrovmExecError {
    fn from(value: ExecError) -> Self {
        Self {
            code: value.code.into(),
            message: value.message,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecuteResponse {
    pub ok: bool,
    pub result: Option<ExecResult>,
    pub error: Option<ExecError>,
}

impl ExecuteResponse {
    pub fn ok(result: ExecResult) -> Self {
        Self {
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(error: ExecError) -> Self {
        Self {
            ok: false,
            result: None,
            error: Some(error),
        }
    }
}

impl TryFrom<MicrovmExecuteResponse> for ExecuteResponse {
    type Error = Error;

    fn try_from(value: MicrovmExecuteResponse) -> Result<Self> {
        Ok(Self {
            ok: value.ok,
            result: value.result.map(TryInto::try_into).transpose()?,
            error: value.error.map(TryInto::try_into).transpose()?,
        })
    }
}

impl From<ExecuteResponse> for MicrovmExecuteResponse {
    fn from(value: ExecuteResponse) -> Self {
        Self {
            ok: value.ok,
            result: value.result.map(Into::into),
            error: value.error.map(Into::into),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarmupRequest {
    pub profile_id: String,
}

impl WarmupRequest {
    pub fn validate(&self) -> Result<()> {
        if self.profile_id.is_empty() {
            return Err(Error::Invalid("profile_id is empty".into()));
        }
        Ok(())
    }
}

impl From<MicrovmWarmupRequest> for WarmupRequest {
    fn from(value: MicrovmWarmupRequest) -> Self {
        Self {
            profile_id: value.profile_id,
        }
    }
}

impl From<WarmupRequest> for MicrovmWarmupRequest {
    fn from(value: WarmupRequest) -> Self {
        Self {
            profile_id: value.profile_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarmupResponse {
    pub ok: bool,
    pub error: Option<ExecError>,
}

impl WarmupResponse {
    pub fn ok() -> Self {
        Self {
            ok: true,
            error: None,
        }
    }

    pub fn err(error: ExecError) -> Self {
        Self {
            ok: false,
            error: Some(error),
        }
    }
}

impl TryFrom<MicrovmWarmupResponse> for WarmupResponse {
    type Error = Error;

    fn try_from(value: MicrovmWarmupResponse) -> Result<Self> {
        Ok(Self {
            ok: value.ok,
            error: value.error.map(TryInto::try_into).transpose()?,
        })
    }
}

impl From<WarmupResponse> for MicrovmWarmupResponse {
    fn from(value: WarmupResponse) -> Self {
        Self {
            ok: value.ok,
            error: value.error.map(Into::into),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthResponse {
    pub ok: bool,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

impl HealthResponse {
    pub fn ok() -> Self {
        Self {
            ok: true,
            error_code: None,
            error_message: None,
        }
    }

    pub fn err(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            error_code: Some(code.into()),
            error_message: Some(message.into()),
        }
    }
}

impl From<MicrovmHealthResponse> for HealthResponse {
    fn from(value: MicrovmHealthResponse) -> Self {
        Self {
            ok: value.ok,
            error_code: value.error_code,
            error_message: value.error_message,
        }
    }
}

impl From<HealthResponse> for MicrovmHealthResponse {
    fn from(value: HealthResponse) -> Self {
        Self {
            ok: value.ok,
            error_code: value.error_code,
            error_message: value.error_message,
        }
    }
}

impl From<MicrovmLimits> for Limits {
    fn from(value: MicrovmLimits) -> Self {
        Self {
            cpu_ms: value.cpu_ms,
            memory_mb: value.memory_mb,
            pids: value.pids,
            disk_mb: value.disk_mb,
            timeout_ms: value.timeout_ms,
        }
    }
}

impl From<Limits> for MicrovmLimits {
    fn from(value: Limits) -> Self {
        Self {
            cpu_ms: value.cpu_ms,
            memory_mb: value.memory_mb,
            pids: value.pids,
            disk_mb: value.disk_mb,
            timeout_ms: value.timeout_ms,
        }
    }
}

impl From<TraceMeta> for Trace {
    fn from(value: TraceMeta) -> Self {
        Self {
            trace_id: value.trace_id,
            client_instance_id: value.client_instance_id,
        }
    }
}

impl From<Trace> for TraceMeta {
    fn from(value: Trace) -> Self {
        Self {
            trace_id: value.trace_id,
            client_instance_id: value.client_instance_id,
        }
    }
}

impl From<MicrovmMetrics> for Metrics {
    fn from(value: MicrovmMetrics) -> Self {
        Self {
            queue_wait_ms: value.queue_wait_ms,
            boot_ms: value.boot_ms,
            exec_ms: value.exec_ms,
        }
    }
}

impl From<Metrics> for MicrovmMetrics {
    fn from(value: Metrics) -> Self {
        Self {
            queue_wait_ms: value.queue_wait_ms,
            boot_ms: value.boot_ms,
            exec_ms: value.exec_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_request_round_trip() {
        let request = Request::Execute(ExecuteRequest {
            request_id: "req-1".to_string(),
            profile_id: "default".to_string(),
            command: vec!["python".to_string(), "main.py".to_string()],
            cwd: PathBuf::from("/workspace"),
            env: BTreeMap::from([(String::from("A"), String::from("1"))]),
            stdin: Some("input".to_string()),
            limits: Limits {
                cpu_ms: 2_000,
                memory_mb: 64,
                pids: 32,
                disk_mb: 8,
                timeout_ms: 5_000,
            },
            trace: Trace {
                trace_id: Some("trace-1".to_string()),
                client_instance_id: Some("client-1".to_string()),
            },
        });

        let bytes = request.encode();
        let decoded = Request::decode(&bytes).expect("decode request");
        assert_eq!(decoded, request);
    }

    #[test]
    fn execute_response_round_trip() {
        let response = Response::Execute(ExecuteResponse::ok(ExecResult {
            status: ExitStatus::Succeeded,
            exit_code: Some(0),
            timed_out: false,
            stdout: "ok".to_string(),
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            vm_id: "vm-1".to_string(),
            lease_source: "cold_boot".to_string(),
            metrics: Metrics {
                queue_wait_ms: 1,
                boot_ms: 2,
                exec_ms: 3,
            },
        }));

        let bytes = response.encode();
        let decoded = Response::decode(&bytes).expect("decode response");
        assert_eq!(decoded, response);
    }

    #[test]
    fn warmup_request_needs_profile_id() {
        let error = WarmupRequest {
            profile_id: String::new(),
        }
        .validate()
        .expect_err("warmup should reject empty profile_id");
        assert!(matches!(error, Error::Invalid(_)));
    }

    #[test]
    fn execute_response_error_constructor() {
        let response = ExecuteResponse::err(ExecError {
            code: ErrorCode::BackendUnavailable,
            message: "down".to_string(),
        });
        assert!(!response.ok);
        assert!(response.result.is_none());
        assert_eq!(response.error.expect("error").message, "down");
    }
}

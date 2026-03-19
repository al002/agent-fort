use af_rpc_proto::{CreateTaskResponse, PingResponse, TaskOperation};

use crate::error::Result;
use crate::runtime::RuntimeClient;

/// Task-focused API surface.
///
/// This client is created from [`crate::AgentFortClient::tasks`] and borrows
/// the underlying runtime connection mutably.
#[derive(Debug)]
pub struct TaskClient<'a> {
    runtime: &'a mut RuntimeClient,
}

impl<'a> TaskClient<'a> {
    pub(crate) fn new(runtime: &'a mut RuntimeClient) -> Self {
        Self { runtime }
    }

    /// Pings the daemon through the shared runtime connection.
    ///
    /// # Errors
    /// Returns transport, RPC, or protocol decode errors.
    pub async fn ping_daemon(&mut self) -> Result<PingResponse> {
        self.runtime.ping().await
    }

    /// Creates a task for a previously created session.
    ///
    /// `rebind_token` must match the current session lease for the given `session_id`.
    /// For `exec` tasks, use [`crate::exec_operation`] to build a valid operation payload.
    ///
    /// # Errors
    /// Returns transport, RPC, or protocol decode errors.
    ///
    /// # Example
    /// ```no_run
    /// use af_sdk::{AgentFortClient, Result, SdkConfig, SdkError, exec_operation};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     let config = SdkConfig::new("my-agent", None);
    ///     let _sync = AgentFortClient::initialize(config.clone()).await?;
    ///     let mut client = AgentFortClient::connect(config).await?;
    ///
    ///     let session = {
    ///         let mut sessions = client.sessions().await?;
    ///         sessions.create_session().await?
    ///     };
    ///     let session_id = session.session_id.clone();
    ///     let rebind_token = session
    ///         .lease
    ///         .ok_or_else(|| SdkError::Protocol("CreateSessionResponse missing lease".to_string()))?
    ///         .rebind_token;
    ///
    ///     let mut tasks = client.tasks().await?;
    ///     let _resp = tasks
    ///         .create(
    ///             session_id,
    ///             rebind_token,
    ///             exec_operation("ls"),
    ///             Some("exec: ls".to_string()),
    ///             None,
    ///         )
    ///         .await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn create(
        &mut self,
        session_id: String,
        rebind_token: String,
        operation: TaskOperation,
        goal: Option<String>,
        limits_json: Option<String>,
    ) -> Result<CreateTaskResponse> {
        self.runtime
            .create_task(session_id, rebind_token, operation, goal, limits_json)
            .await
    }
}

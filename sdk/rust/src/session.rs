use af_rpc_proto::{PingResponse, Session};

use crate::error::{Result, SdkError};
use crate::runtime::{CreateSessionOptions, RuntimeClient};

/// Session-focused API surface.
///
/// This client is created from [`crate::AgentFortClient::sessions`] and borrows
/// the underlying runtime connection mutably.
#[derive(Debug)]
pub struct SessionClient<'a> {
    runtime: &'a mut RuntimeClient,
}

impl<'a> SessionClient<'a> {
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

    /// Creates a session with default [`CreateSessionOptions`].
    ///
    /// # Errors
    /// Returns transport, RPC, or protocol decode errors.
    pub async fn create_session(&mut self) -> Result<Session> {
        self.create_session_with_options(CreateSessionOptions::default())
            .await
    }

    /// Creates a session using explicit options.
    ///
    /// Returns [`SdkError::Protocol`] if the RPC response does not contain a
    /// `session` payload.
    ///
    /// # Errors
    /// Returns transport, RPC, or protocol decode errors.
    ///
    /// # Example
    /// ```no_run
    /// use af_sdk::{AgentFortClient, CreateSessionOptions, Result, SdkConfig};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     let config = SdkConfig::new("my-agent", None);
    ///     let _sync = AgentFortClient::initialize(config.clone()).await?;
    ///     let mut client = AgentFortClient::connect(config).await?;
    ///     let mut sessions = client.sessions().await?;
    ///     let options = CreateSessionOptions::with_agent_name("override-agent");
    ///     let _session = sessions.create_session_with_options(options).await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn create_session_with_options(
        &mut self,
        options: CreateSessionOptions,
    ) -> Result<Session> {
        let response = self.runtime.create_session(options).await?;
        response
            .session
            .ok_or_else(|| SdkError::Protocol("CreateSessionResponse missing session".to_string()))
    }
}

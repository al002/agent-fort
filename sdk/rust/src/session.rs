use af_rpc_proto::{PingResponse, Session};

use crate::error::{Result, SdkError};
use crate::runtime::{CreateSessionOptions, RuntimeClient};

#[derive(Debug)]
pub struct SessionClient<'a> {
    runtime: &'a mut RuntimeClient,
}

impl<'a> SessionClient<'a> {
    pub(crate) fn new(runtime: &'a mut RuntimeClient) -> Self {
        Self { runtime }
    }

    pub async fn ping_daemon(&mut self) -> Result<PingResponse> {
        self.runtime.ping().await
    }

    pub async fn create_session(&mut self) -> Result<Session> {
        self.create_session_with_options(CreateSessionOptions::default())
            .await
    }

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

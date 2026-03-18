use af_rpc_proto::{CreateTaskResponse, PingResponse, TaskOperation};

use crate::error::Result;
use crate::runtime::RuntimeClient;

#[derive(Debug)]
pub struct TaskClient<'a> {
    runtime: &'a mut RuntimeClient,
}

impl<'a> TaskClient<'a> {
    pub(crate) fn new(runtime: &'a mut RuntimeClient) -> Self {
        Self { runtime }
    }

    pub async fn ping_daemon(&mut self) -> Result<PingResponse> {
        self.runtime.ping().await
    }

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

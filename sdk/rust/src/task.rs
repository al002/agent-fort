use af_rpc_proto::PingResponse;

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
}

use std::sync::{Arc, Mutex};

use crate::{
    ActivePolicy, PolicyInfraError, PolicyInfraResult, PolicyRuntime, PolicyRuntimeConfig,
    PolicyStatus,
};

#[derive(Debug, Clone)]
pub struct SharedPolicyRuntime {
    inner: Arc<Mutex<PolicyRuntime>>,
}

impl SharedPolicyRuntime {
    pub fn start(config: PolicyRuntimeConfig) -> PolicyInfraResult<Self> {
        let runtime = PolicyRuntime::start(config)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(runtime)),
        })
    }

    pub fn active_policy(&self) -> PolicyInfraResult<ActivePolicy> {
        self.with_runtime(|runtime| runtime.active_policy())
    }

    pub fn status(&self) -> PolicyInfraResult<PolicyStatus> {
        self.with_runtime(|runtime| runtime.status())
    }

    fn with_runtime<T>(
        &self,
        operation: impl FnOnce(&PolicyRuntime) -> PolicyInfraResult<T>,
    ) -> PolicyInfraResult<T> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| PolicyInfraError::RuntimeStatePoisoned)?;
        operation(&guard)
    }
}

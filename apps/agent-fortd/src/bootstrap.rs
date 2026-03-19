use std::sync::Arc;
use std::sync::Mutex;

use af_policy_infra::{PolicyRuntime, PolicyRuntimeConfig};
use af_store::Store;
use anyhow::Result;
use tracing::info;

use crate::config::DaemonConfig;
use crate::helper_client::HelperClient;
use crate::rpc_controller::RpcController;
use crate::server::DaemonServer;

#[derive(Debug)]
pub struct BootstrappedDaemon {
    config: DaemonConfig,
    server: DaemonServer,
}

impl BootstrappedDaemon {
    pub fn new(config: DaemonConfig) -> Result<Self> {
        let store = Store::open_path(&config.store_path)?;
        let migration_report = *store.startup_migration_report();
        info!(
            store_path = %config.store_path.display(),
            schema_version = migration_report.current_version,
            applied_migrations = migration_report.applied_count,
            skipped_migrations = migration_report.skipped_count,
            "sqlite store ready"
        );

        let policy_runtime = Arc::new(Mutex::new(PolicyRuntime::start(PolicyRuntimeConfig::new(
            config.policy_dir.clone(),
        ))?));
        let policy_status = policy_runtime
            .lock()
            .expect("policy runtime lock should not be poisoned")
            .status()?;
        info!(
            policy_dir = %config.policy_dir.display(),
            policy_revision = policy_status.revision,
            policy_files = policy_status.file_count,
            static_policy_revision = policy_status.static_policy_revision,
            "policy directory runtime ready"
        );

        let helper_client = HelperClient::new(
            config.helper_path.clone(),
            config.bwrap_path.clone(),
            config.cgroup_root.clone(),
        );
        let workspace_root = std::env::current_dir().ok();
        let controller = RpcController::new_with_execution(
            config.daemon_instance_id.clone(),
            Arc::new(store),
            helper_client,
            policy_runtime,
            config.policy_dir.clone(),
            workspace_root,
            config.resource_governance_mode,
        );
        let daemon_info = controller.daemon_info();
        info!(
            daemon_instance_id = %config.daemon_instance_id,
            routes = ?daemon_info.info.map(|info| info.routes).unwrap_or_default(),
            "rpc controller ready"
        );

        let server = DaemonServer::bind(config.endpoint.clone(), controller)?;
        Ok(Self { config, server })
    }

    pub async fn run(self) -> Result<()> {
        info!(
            daemon_instance_id = %self.config.daemon_instance_id,
            endpoint = %self.config.endpoint.as_uri(),
            store_path = %self.config.store_path.display(),
            helper_path = %self.config.helper_path.display(),
            bwrap_path = %self.config.bwrap_path.display(),
            resource_governance_mode = ?self.config.resource_governance_mode,
            policy_dir = %self.config.policy_dir.display(),
            "agent-fortd started"
        );
        self.server.run().await
    }
}

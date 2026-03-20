use std::ffi::OsString;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use wait_timeout::ChildExt;

use super::{
    BootstrapErrorOutput, BootstrapStartOutput, BootstrapSyncOutput, CommandOutput,
    DEFAULT_COMMAND_TIMEOUT_MS, DEFAULT_PING_INTERVAL_MS, DEFAULT_STARTUP_TIMEOUT_MS,
    ResolvedBootstrapConfig,
};
use crate::bootstrap::paths::install_root_manifest_path;
use crate::error::{Result, SdkError};

pub(super) fn run_sync_if_needed(
    bootstrap_path: &Path,
    config: &ResolvedBootstrapConfig,
) -> Result<Option<BootstrapSyncOutput>> {
    ensure_sync_bundle_manifest(config)?;
    let sync_args = build_sync_args(config);
    let sync_raw = run_bootstrap(
        bootstrap_path,
        &sync_args,
        DEFAULT_COMMAND_TIMEOUT_MS,
        "sync",
    )?;
    Ok(Some(parse_bootstrap_output::<BootstrapSyncOutput>(
        "sync", &sync_raw,
    )?))
}

pub(super) fn run_start(
    bootstrap_path: &Path,
    config: &ResolvedBootstrapConfig,
) -> Result<BootstrapStartOutput> {
    let start_args = build_start_args(config);
    let start_raw = run_bootstrap(
        bootstrap_path,
        &start_args,
        DEFAULT_COMMAND_TIMEOUT_MS,
        "start",
    )?;
    parse_bootstrap_output::<BootstrapStartOutput>("start", &start_raw)
}

fn ensure_sync_bundle_manifest(config: &ResolvedBootstrapConfig) -> Result<()> {
    if config.bundle_manifest.is_some()
        || install_root_manifest_path(&config.install_root).is_file()
    {
        return Ok(());
    }
    Err(SdkError::BundleManifestRequired)
}

fn build_sync_args(config: &ResolvedBootstrapConfig) -> Vec<OsString> {
    let mut args = Vec::new();
    args.push(OsString::from("sync"));
    args.push(OsString::from("--install-root"));
    args.push(config.install_root.as_os_str().to_owned());

    if let Some(bundle_manifest) = &config.bundle_manifest {
        args.push(OsString::from("--manifest-source"));
        args.push(OsString::from(bundle_manifest));
    }

    args.push(OsString::from("--endpoint"));
    args.push(OsString::from(&config.endpoint));
    args
}

fn build_start_args(config: &ResolvedBootstrapConfig) -> Vec<OsString> {
    let mut args = Vec::new();
    args.push(OsString::from("start"));
    args.push(OsString::from("--install-root"));
    args.push(config.install_root.as_os_str().to_owned());

    args.push(OsString::from("--endpoint"));
    args.push(OsString::from(&config.endpoint));

    args.push(OsString::from("--startup-timeout-ms"));
    args.push(OsString::from(DEFAULT_STARTUP_TIMEOUT_MS.to_string()));

    args.push(OsString::from("--ping-interval-ms"));
    args.push(OsString::from(DEFAULT_PING_INTERVAL_MS.to_string()));

    args.push(OsString::from("--policy-dir"));
    args.push(config.policy_dir.as_os_str().to_owned());

    args.push(OsString::from("--command-rules-dir"));
    args.push(config.command_rules_dir.as_os_str().to_owned());
    if let Some(command_rules_strict) = config.command_rules_strict {
        args.push(OsString::from("--command-rules-strict"));
        args.push(OsString::from(if command_rules_strict {
            "true"
        } else {
            "false"
        }));
    }

    if let Some(store_path) = &config.store_path {
        args.push(OsString::from("--store-path"));
        args.push(store_path.as_os_str().to_owned());
    }
    args
}

fn run_bootstrap(
    bootstrap_path: &Path,
    args: &[OsString],
    timeout_ms: u64,
    command_name: &str,
) -> Result<CommandOutput> {
    let mut child = Command::new(bootstrap_path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| super::source::map_bootstrap_spawn_error(bootstrap_path, error))?;

    let mut stdout = child
        .stdout
        .take()
        .ok_or(SdkError::Unsupported("failed to capture bootstrap stdout"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or(SdkError::Unsupported("failed to capture bootstrap stderr"))?;
    let stdout_reader = thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let mut buffer = Vec::new();
        stdout.read_to_end(&mut buffer)?;
        Ok(buffer)
    });
    let stderr_reader = thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let mut buffer = Vec::new();
        stderr.read_to_end(&mut buffer)?;
        Ok(buffer)
    });

    let status = child.wait_timeout(Duration::from_millis(timeout_ms.max(1)))?;
    let timed_out = status.is_none();
    if timed_out {
        let _ = child.kill();
        let _ = child.wait();
    }

    let stdout_buf = stdout_reader
        .join()
        .map_err(|_| SdkError::Unsupported("bootstrap stdout reader thread panicked"))??;
    let stderr_buf = stderr_reader
        .join()
        .map_err(|_| SdkError::Unsupported("bootstrap stderr reader thread panicked"))??;

    if timed_out {
        return Err(SdkError::BootstrapCommandTimeout {
            command: command_name.to_string(),
            timeout_ms,
        });
    }

    Ok(CommandOutput {
        status: status.expect("status exists when not timed out"),
        stdout: String::from_utf8_lossy(&stdout_buf).trim().to_string(),
        stderr: String::from_utf8_lossy(&stderr_buf).trim().to_string(),
    })
}

fn parse_bootstrap_output<T>(command_name: &str, output: &CommandOutput) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    if output.stdout.is_empty() {
        return Err(SdkError::BootstrapInvalidOutput {
            command: command_name.to_string(),
            message: format!(
                "stdout is empty{}",
                if output.stderr.is_empty() {
                    String::new()
                } else {
                    format!(", stderr: {}", output.stderr)
                }
            ),
        });
    }

    let value: Value =
        serde_json::from_str(&output.stdout).map_err(|error| SdkError::BootstrapInvalidOutput {
            command: command_name.to_string(),
            message: format!("failed to parse JSON: {error}; stdout: {}", output.stdout),
        })?;

    if !output.status.success() {
        if let Ok(error_payload) = serde_json::from_value::<BootstrapErrorOutput>(value.clone())
            && !error_payload.ok
        {
            return Err(SdkError::BootstrapReportedError {
                command: command_name.to_string(),
                error: error_payload.error,
            });
        }

        let message = if output.stderr.is_empty() {
            output.stdout.clone()
        } else {
            format!("stdout: {}; stderr: {}", output.stdout, output.stderr)
        };
        return Err(SdkError::BootstrapCommandFailed {
            command: command_name.to_string(),
            message,
        });
    }

    if let Some(false) = value.get("ok").and_then(Value::as_bool) {
        let error = value
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("bootstrap returned ok=false without error field")
            .to_string();
        return Err(SdkError::BootstrapReportedError {
            command: command_name.to_string(),
            error,
        });
    }

    serde_json::from_value(value).map_err(|error| SdkError::BootstrapInvalidOutput {
        command: command_name.to_string(),
        message: format!(
            "failed to decode typed output: {error}; stdout: {}",
            output.stdout
        ),
    })
}

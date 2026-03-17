use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;

use af_rpc_transport::Endpoint;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;
use wait_timeout::ChildExt;

use crate::error::{Result, SdkError};

const DEFAULT_COMMAND_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_STARTUP_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_PING_INTERVAL_MS: u64 = 200;
const DEFAULT_LOCAL_DEV_BOOTSTRAP_DIR: &str = "target/debug";
const EXPECTED_BOOTSTRAP_SHA256_LINUX_X86_64: &str =
    "e935437defc54009b8cddbd8b946f9b1f5a20feb71cef5c0fdac32c4f6e3e0c3";

#[cfg(windows)]
const DEFAULT_ENDPOINT: &str = "npipe://agent-fortd";
#[cfg(not(windows))]
const DEFAULT_ENDPOINT: &str = "unix:///tmp/agent-fortd.sock";

#[derive(Debug, Clone, Default)]
pub struct BootstrapConfig {
    pub bootstrap_binary_url: Option<String>,
    pub install_root: Option<PathBuf>,
    pub bundle_manifest: Option<String>,
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BootstrapRunResult {
    pub bootstrap_path: PathBuf,
    pub sync: Option<BootstrapSyncOutput>,
    pub start: BootstrapStartOutput,
}

#[derive(Debug, Clone)]
pub struct BootstrapSyncResult {
    pub bootstrap_path: PathBuf,
    pub sync: Option<BootstrapSyncOutput>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapSyncOutput {
    pub ok: bool,
    pub version: String,
    pub daemon_path: String,
    pub bwrap_path: String,
    pub helper_path: String,
    pub endpoint: String,
    pub install_state_path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapStartOutput {
    pub ok: bool,
    pub endpoint: String,
    pub started: bool,
    pub daemon_pid: Option<u32>,
    pub daemon_instance_id: String,
}

#[derive(Debug, Clone)]
pub struct BootstrapRunner {
    config: BootstrapConfig,
}

#[derive(Debug)]
struct CommandOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Deserialize)]
struct BootstrapErrorOutput {
    ok: bool,
    error: String,
}

#[derive(Debug, Clone)]
struct ResolvedBootstrapConfig {
    bootstrap_binary_url: String,
    install_root: PathBuf,
    bundle_manifest: Option<String>,
    endpoint: String,
}

#[derive(Debug, Clone)]
enum Source {
    Local(PathBuf),
    Http(Url),
}

impl BootstrapRunner {
    pub fn new(config: BootstrapConfig) -> Self {
        Self { config }
    }

    pub fn prepare_and_start(&self) -> Result<BootstrapRunResult> {
        let resolved = self.resolve_config()?;
        let bootstrap_path = resolve_bootstrap_path(&resolved, true)?;
        let sync_output = run_sync_if_needed(&bootstrap_path, &resolved)?;
        let start = run_start(&bootstrap_path, &resolved)?;

        Ok(BootstrapRunResult {
            bootstrap_path,
            sync: sync_output,
            start,
        })
    }

    pub fn sync_only(&self) -> Result<BootstrapSyncResult> {
        let resolved = self.resolve_config()?;
        let bootstrap_path = resolve_bootstrap_path(&resolved, true)?;
        let sync = run_sync_if_needed(&bootstrap_path, &resolved)?;
        Ok(BootstrapSyncResult {
            bootstrap_path,
            sync,
        })
    }

    pub fn start_only(&self) -> Result<BootstrapStartOutput> {
        let resolved = self.resolve_config()?;
        let bootstrap_path = resolve_bootstrap_path(&resolved, false)?;
        run_start(&bootstrap_path, &resolved)
    }

    fn resolve_config(&self) -> Result<ResolvedBootstrapConfig> {
        let install_root = self
            .config
            .install_root
            .clone()
            .unwrap_or_else(default_install_root);

        let endpoint = self
            .config
            .endpoint
            .clone()
            .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
        let _ = Endpoint::parse(&endpoint)?;

        let bootstrap_binary_url = self
            .config
            .bootstrap_binary_url
            .clone()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(default_local_bin);

        Ok(ResolvedBootstrapConfig {
            bootstrap_binary_url,
            install_root,
            bundle_manifest: self.config.bundle_manifest.clone(),
            endpoint,
        })
    }
}

fn run_sync_if_needed(
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

fn run_start(
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

fn resolve_bootstrap_path(
    config: &ResolvedBootstrapConfig,
    allow_download: bool,
) -> Result<PathBuf> {
    if let Some(path) = find_bootstrap_under_install_root(&config.install_root) {
        return Ok(path);
    }

    if allow_download {
        return init_bootstrap_binary(&config.bootstrap_binary_url, &config.install_root);
    }

    Err(SdkError::BootstrapNotFound)
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
        .map_err(|error| map_bootstrap_spawn_error(bootstrap_path, error))?;

    let mut stdout = child
        .stdout
        .take()
        .ok_or(SdkError::Unsupported("failed to capture bootstrap stdout"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or(SdkError::Unsupported("failed to capture bootstrap stderr"))?;

    let status = child.wait_timeout(Duration::from_millis(timeout_ms.max(1)))?;
    let timed_out = status.is_none();
    if timed_out {
        let _ = child.kill();
        let _ = child.wait();
    }

    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();
    stdout.read_to_end(&mut stdout_buf)?;
    stderr.read_to_end(&mut stderr_buf)?;

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
        if let Ok(error_payload) = serde_json::from_value::<BootstrapErrorOutput>(value.clone()) {
            if !error_payload.ok {
                return Err(SdkError::BootstrapReportedError {
                    command: command_name.to_string(),
                    error: error_payload.error,
                });
            }
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

fn init_bootstrap_binary(url_text: &str, install_root: &Path) -> Result<PathBuf> {
    let source = Source::parse(url_text)?;
    let binary_bytes = source.fetch_bytes()?;
    let target_dir = install_root.join("bin");
    fs::create_dir_all(&target_dir)?;
    let target_path = target_dir.join(default_bootstrap_file_name());

    if !source.is_local() {
        let expected_sha256 = expected_bootstrap_sha256()?;
        let actual_sha256 = sha256_bytes(&binary_bytes);
        if actual_sha256 != expected_sha256 {
            return Err(SdkError::BootstrapChecksumMismatch {
                path: target_path.clone(),
                expected: expected_sha256.to_string(),
                actual: actual_sha256,
            });
        }
    }

    let mut file = fs::File::create(&target_path)?;
    file.write_all(&binary_bytes)?;
    file.flush()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&target_path, fs::Permissions::from_mode(0o755))?;
    }
    #[cfg(windows)]
    {
        clear_windows_zone_identifier(&target_path);
    }

    Ok(target_path)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn expected_bootstrap_sha256() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok(EXPECTED_BOOTSTRAP_SHA256_LINUX_X86_64),
        (os, arch) => Err(SdkError::Unsupported(match (os, arch) {
            ("windows", "x86_64") => "missing hardcoded bootstrap sha256 for windows-x86_64 target",
            _ => "missing hardcoded bootstrap sha256 for current target",
        })),
    }
}

fn default_local_bin_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir
        .parent()
        .and_then(|path| path.parent())
        .map(Path::to_path_buf)
        .unwrap_or(manifest_dir);
    root.join(DEFAULT_LOCAL_DEV_BOOTSTRAP_DIR)
        .join(default_bootstrap_file_name())
}

fn default_local_bin() -> String {
    let path = default_local_bin_path();
    Url::from_file_path(&path)
        .map(|url| url.to_string())
        .unwrap_or_else(|_| path.to_string_lossy().to_string())
}

fn map_bootstrap_spawn_error(_path: &Path, error: std::io::Error) -> SdkError {
    #[cfg(windows)]
    {
        use std::io::ErrorKind::{NotFound, PermissionDenied};
        if matches!(error.kind(), PermissionDenied | NotFound) {
            return SdkError::BootstrapExecutionBlocked {
                path: _path.to_path_buf(),
                message: format!(
                    "failed to execute bootstrap; Windows Defender/SmartScreen may block or quarantine downloaded exe: {error}"
                ),
            };
        }
    }

    SdkError::Io(error)
}

impl Source {
    fn parse(raw: &str) -> Result<Self> {
        if raw.starts_with("http://") || raw.starts_with("https://") {
            let url = Url::parse(raw).map_err(|error| SdkError::BootstrapDownloadFailed {
                url: raw.to_string(),
                message: error.to_string(),
            })?;
            return Ok(Self::Http(url));
        }

        if raw.starts_with("file://") {
            let url = Url::parse(raw).map_err(|error| SdkError::BootstrapDownloadFailed {
                url: raw.to_string(),
                message: error.to_string(),
            })?;
            let path = url
                .to_file_path()
                .map_err(|_| SdkError::BootstrapDownloadFailed {
                    url: raw.to_string(),
                    message: "invalid file:// URL".to_string(),
                })?;
            return Ok(Self::Local(path));
        }

        if raw.contains("://") {
            return Err(SdkError::BootstrapDownloadFailed {
                url: raw.to_string(),
                message: "unsupported URL scheme".to_string(),
            });
        }

        Ok(Self::Local(PathBuf::from(raw)))
    }

    fn fetch_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::Local(path) => {
                fs::read(path).map_err(|error| SdkError::BootstrapDownloadFailed {
                    url: path.display().to_string(),
                    message: error.to_string(),
                })
            }
            Self::Http(url) => {
                let config = ureq::Agent::config_builder()
                    .timeout_global(Some(Duration::from_secs(60)))
                    .build();
                let agent: ureq::Agent = config.into();

                let mut response = agent.get(url.as_str()).call().map_err(|error| {
                    SdkError::BootstrapDownloadFailed {
                        url: url.to_string(),
                        message: error.to_string(),
                    }
                })?;

                response.body_mut().read_to_vec().map_err(|error| {
                    SdkError::BootstrapDownloadFailed {
                        url: url.to_string(),
                        message: error.to_string(),
                    }
                })
            }
        }
    }

    fn is_local(&self) -> bool {
        matches!(self, Self::Local(_))
    }
}

#[cfg(windows)]
fn clear_windows_zone_identifier(path: &Path) {
    if let Some(path_str) = path.to_str() {
        let zone_identifier = format!("{path_str}:Zone.Identifier");
        let _ = fs::remove_file(zone_identifier);
    }
}

fn find_bootstrap_under_install_root(install_root: &Path) -> Option<PathBuf> {
    for name in bootstrap_binary_names() {
        let in_bin = install_root.join("bin").join(name);
        if in_bin.is_file() {
            return Some(in_bin);
        }

        let in_root = install_root.join(name);
        if in_root.is_file() {
            return Some(in_root);
        }
    }
    None
}

#[cfg(windows)]
fn bootstrap_binary_names() -> &'static [&'static str] {
    &["af-bootstrap.exe", "af-bootstrap"]
}

#[cfg(not(windows))]
fn bootstrap_binary_names() -> &'static [&'static str] {
    &["af-bootstrap"]
}

#[cfg(windows)]
fn default_bootstrap_file_name() -> String {
    "af-bootstrap.exe".to_string()
}

#[cfg(not(windows))]
fn default_bootstrap_file_name() -> String {
    "af-bootstrap".to_string()
}

fn install_root_manifest_path(install_root: &Path) -> PathBuf {
    install_root.join("manifest.json")
}

fn default_install_root() -> PathBuf {
    #[cfg(windows)]
    {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("USERPROFILE")
                    .map(PathBuf::from)
                    .map(|home| home.join("AppData").join("Local"))
            })
            .unwrap_or_else(|| PathBuf::from("."));
        return base.join("AgentFort");
    }

    #[cfg(not(windows))]
    {
        if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
            return PathBuf::from(xdg).join("agent-fort");
        }
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        home.join(".local").join("share").join("agent-fort")
    }
}

pub fn default_install_root_path() -> PathBuf {
    default_install_root()
}

pub fn default_manifest_path(install_root: &Path) -> PathBuf {
    install_root_manifest_path(install_root)
}

pub fn default_endpoint_uri() -> &'static str {
    DEFAULT_ENDPOINT
}

pub fn bootstrap_path_lookup_order_hint(install_root: &Path) -> Vec<PathBuf> {
    let mut order = Vec::new();
    for name in bootstrap_binary_names() {
        order.push(install_root.join("bin").join(name));
        order.push(install_root.join(name));
    }
    order
}

pub fn install_root_has_manifest(install_root: &Path) -> bool {
    fs::metadata(install_root_manifest_path(install_root))
        .map(|meta| meta.is_file())
        .unwrap_or(false)
}

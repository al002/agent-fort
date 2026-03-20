use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use url::Url;

use super::{DEFAULT_LOCAL_DEV_BOOTSTRAP_DIR, EXPECTED_BOOTSTRAP_SHA256_LINUX_X86_64};
use crate::error::{Result, SdkError};

#[derive(Debug, Clone)]
enum Source {
    Local(PathBuf),
    Http(Url),
}

pub(super) fn init_bootstrap_binary(url_text: &str, install_root: &Path) -> Result<PathBuf> {
    let source = Source::parse(url_text)?;
    let binary_bytes = source.fetch_bytes()?;
    let target_dir = install_root.join("bin");
    fs::create_dir_all(&target_dir)?;
    let target_path = target_dir.join(super::paths::default_bootstrap_file_name());

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

pub(super) fn default_local_bin() -> String {
    let path = default_local_bin_path();
    Url::from_file_path(&path)
        .map(|url| url.to_string())
        .unwrap_or_else(|_| path.to_string_lossy().to_string())
}

pub(super) fn map_bootstrap_spawn_error(_path: &Path, error: std::io::Error) -> SdkError {
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
        .join(super::paths::default_bootstrap_file_name())
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

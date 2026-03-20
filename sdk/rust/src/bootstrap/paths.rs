use std::fs;
use std::path::{Path, PathBuf};

use super::{DEFAULT_ENDPOINT, ResolvedBootstrapConfig};
use crate::error::{Result, SdkError};

pub(super) fn resolve_bootstrap_path(
    config: &ResolvedBootstrapConfig,
    allow_download: bool,
) -> Result<PathBuf> {
    if let Some(path) = find_bootstrap_under_install_root(&config.install_root) {
        return Ok(path);
    }

    if allow_download {
        return super::source::init_bootstrap_binary(
            &config.bootstrap_binary_url,
            &config.install_root,
        );
    }

    Err(SdkError::BootstrapNotFound)
}

pub(super) fn find_bootstrap_under_install_root(install_root: &Path) -> Option<PathBuf> {
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

pub(super) fn install_root_manifest_path(install_root: &Path) -> PathBuf {
    install_root.join("manifest.json")
}

pub(super) fn default_install_root() -> PathBuf {
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

/// Returns default install root path used by bootstrap when not explicitly configured.
///
/// # Example
/// ```
/// use af_sdk::default_install_root_path;
///
/// let install_root = default_install_root_path();
/// assert!(!install_root.as_os_str().is_empty());
/// ```
pub fn default_install_root_path() -> PathBuf {
    default_install_root()
}

/// Returns default policy directory path (`<current_dir>/policies`).
///
/// # Example
/// ```
/// use af_sdk::default_policy_dir_path;
///
/// let policy_dir = default_policy_dir_path();
/// assert!(!policy_dir.as_os_str().is_empty());
/// ```
pub fn default_policy_dir_path() -> PathBuf {
    default_policy_dir()
}

/// Returns default local manifest path (`<install_root>/manifest.json`).
///
/// This is the SDK's fallback manifest source when
/// [`super::BootstrapConfig::bundle_manifest`] is not provided.
/// It is a filesystem path, not an online URL.
///
/// # Example
/// ```
/// use af_sdk::{default_install_root_path, default_manifest_path};
///
/// let install_root = default_install_root_path();
/// let manifest = default_manifest_path(&install_root);
/// assert!(manifest.ends_with("manifest.json"));
/// ```
pub fn default_manifest_path(install_root: &Path) -> PathBuf {
    install_root_manifest_path(install_root)
}

/// Returns SDK default daemon endpoint URI.
///
/// # Example
/// ```
/// use af_sdk::default_endpoint_uri;
///
/// let endpoint = default_endpoint_uri();
/// assert!(!endpoint.is_empty());
/// ```
pub fn default_endpoint_uri() -> &'static str {
    DEFAULT_ENDPOINT
}

/// Returns bootstrap binary lookup order under a given install root.
///
/// This can be used for diagnostics when `BootstrapNotFound` is returned.
///
/// # Example
/// ```
/// use af_sdk::{bootstrap_path_lookup_order_hint, default_install_root_path};
///
/// let order = bootstrap_path_lookup_order_hint(&default_install_root_path());
/// assert!(!order.is_empty());
/// ```
pub fn bootstrap_path_lookup_order_hint(install_root: &Path) -> Vec<PathBuf> {
    let mut order = Vec::new();
    for name in bootstrap_binary_names() {
        order.push(install_root.join("bin").join(name));
        order.push(install_root.join(name));
    }
    order
}

/// Returns `true` if install root contains `manifest.json`.
///
/// # Example
/// ```
/// use af_sdk::{default_install_root_path, install_root_has_manifest};
///
/// let has_manifest = install_root_has_manifest(&default_install_root_path());
/// let _ = has_manifest;
/// ```
pub fn install_root_has_manifest(install_root: &Path) -> bool {
    fs::metadata(install_root_manifest_path(install_root))
        .map(|meta| meta.is_file())
        .unwrap_or(false)
}

pub(super) fn default_policy_dir() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("policies")
}

pub(super) fn resolve_policy_dir(path: PathBuf) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };

    match absolute.canonicalize() {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(absolute),
        Err(error) => Err(error.into()),
    }
}

#[cfg(windows)]
pub(super) fn bootstrap_binary_names() -> &'static [&'static str] {
    &["af-bootstrap.exe", "af-bootstrap"]
}

#[cfg(not(windows))]
pub(super) fn bootstrap_binary_names() -> &'static [&'static str] {
    &["af-bootstrap"]
}

#[cfg(windows)]
pub(super) fn default_bootstrap_file_name() -> String {
    "af-bootstrap.exe".to_string()
}

#[cfg(not(windows))]
pub(super) fn default_bootstrap_file_name() -> String {
    "af-bootstrap".to_string()
}

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tar::Archive;
use url::Url;

use crate::command::{
    InstallState, SyncArgs, resolve_endpoint, resolve_install_root, resolve_manifest_source,
    unix_now_s,
};

#[derive(Debug, Deserialize)]
struct SyncManifest {
    version: String,
    bundle: BundleSpec,
}

#[derive(Debug, Deserialize)]
struct BundleSpec {
    source: String,
    sha256: String,
    #[serde(default = "default_bundle_format")]
    format: String,
    daemon_rel_path: String,
    bwrap_rel_path: String,
    helper_rel_path: String,
}

#[derive(Debug, Serialize)]
pub struct SyncOutput {
    pub ok: bool,
    pub version: String,
    pub daemon_path: String,
    pub bwrap_path: String,
    pub helper_path: String,
    pub endpoint: String,
    pub install_state_path: String,
}

pub fn run(args: SyncArgs) -> Result<SyncOutput> {
    let install_root = resolve_install_root(args.install_root);
    fs::create_dir_all(&install_root)
        .with_context(|| format!("create install root {}", install_root.display()))?;

    let manifest_source_text = resolve_manifest_source(args.manifest_source, &install_root)
        .ok_or_else(|| anyhow::anyhow!("manifest source is required"))?;
    let manifest_source = Source::parse(&manifest_source_text)?;
    let manifest = read_manifest(&manifest_source)?;

    if manifest.bundle.format != "tar.gz" {
        bail!(
            "unsupported bundle format `{}`; expected `tar.gz`",
            manifest.bundle.format
        );
    }

    let bundle_source = manifest_source.resolve_relative(&manifest.bundle.source)?;
    let bundle_file = fetch_bundle(&bundle_source, &manifest.bundle.sha256, &install_root)?;
    let actual_sha256 = sha256_hex(&bundle_file)?;
    if actual_sha256 != manifest.bundle.sha256 {
        bail!(
            "bundle sha256 mismatch: expected {}, got {}",
            manifest.bundle.sha256,
            actual_sha256
        );
    }

    let extracted_root = install_root.join("bundles").join(&manifest.bundle.sha256);
    if extracted_root.exists() {
        fs::remove_dir_all(&extracted_root)
            .with_context(|| format!("remove {}", extracted_root.display()))?;
    }
    fs::create_dir_all(&extracted_root)
        .with_context(|| format!("create {}", extracted_root.display()))?;
    extract_bundle_tar_gz(&bundle_file, &extracted_root)?;

    let daemon_path = extracted_root.join(&manifest.bundle.daemon_rel_path);
    let bwrap_path = extracted_root.join(&manifest.bundle.bwrap_rel_path);
    let helper_path = extracted_root.join(&manifest.bundle.helper_rel_path);
    ensure_file(&daemon_path, "daemon binary")?;
    ensure_file(&bwrap_path, "bwrap binary")?;
    ensure_file(&helper_path, "helper binary")?;

    let endpoint = resolve_endpoint(args.endpoint, None);
    let state = InstallState {
        version: manifest.version.clone(),
        endpoint: endpoint.clone(),
        daemon_path: daemon_path.clone(),
        bwrap_path: bwrap_path.clone(),
        helper_path: helper_path.clone(),
        bundle_sha256: manifest.bundle.sha256,
        manifest_source: manifest_source_text,
        synced_at_unix_s: unix_now_s()?,
    };
    state.save(&install_root)?;

    Ok(SyncOutput {
        ok: true,
        version: state.version,
        daemon_path: daemon_path.display().to_string(),
        bwrap_path: bwrap_path.display().to_string(),
        helper_path: helper_path.display().to_string(),
        endpoint: state.endpoint,
        install_state_path: InstallState::file_path(&install_root).display().to_string(),
    })
}

fn read_manifest(source: &Source) -> Result<SyncManifest> {
    let raw = source.read_to_string()?;
    serde_json::from_str(&raw).context("parse manifest JSON")
}

fn fetch_bundle(source: &Source, sha256: &str, install_root: &Path) -> Result<PathBuf> {
    let downloads_dir = install_root.join("downloads");
    fs::create_dir_all(&downloads_dir)
        .with_context(|| format!("create {}", downloads_dir.display()))?;
    let destination = downloads_dir.join(format!("{sha256}.tar.gz"));
    source.copy_to(&destination)?;
    Ok(destination)
}

fn sha256_hex(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("read {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn extract_bundle_tar_gz(bundle_path: &Path, destination: &Path) -> Result<()> {
    let file =
        fs::File::open(bundle_path).with_context(|| format!("open {}", bundle_path.display()))?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);
    archive.unpack(destination).with_context(|| {
        format!(
            "extract {} into {}",
            bundle_path.display(),
            destination.display()
        )
    })
}

fn ensure_file(path: &Path, label: &str) -> Result<()> {
    if !path.is_file() {
        bail!("{label} not found at {}", path.display());
    }
    Ok(())
}

fn default_bundle_format() -> String {
    "tar.gz".to_string()
}

#[derive(Debug, Clone)]
enum Source {
    Local(PathBuf),
    Http(Url),
}

impl Source {
    fn parse(raw: &str) -> Result<Self> {
        if raw.starts_with("http://") || raw.starts_with("https://") {
            let url = Url::parse(raw).with_context(|| format!("parse URL `{raw}`"))?;
            return Ok(Self::Http(url));
        }

        if raw.starts_with("file://") {
            let url = Url::parse(raw).with_context(|| format!("parse file URL `{raw}`"))?;
            let path = url
                .to_file_path()
                .map_err(|_| anyhow::anyhow!("invalid file URL `{raw}`"))?;
            return Ok(Self::Local(path));
        }

        if raw.contains("://") {
            bail!("unsupported source URI `{raw}`");
        }

        Ok(Self::Local(PathBuf::from(raw)))
    }

    fn resolve_relative(&self, reference: &str) -> Result<Self> {
        if reference.starts_with("http://")
            || reference.starts_with("https://")
            || reference.starts_with("file://")
            || reference.contains("://")
        {
            return Self::parse(reference);
        }

        match self {
            Self::Local(path) => {
                let base_dir = if path.is_dir() {
                    path.clone()
                } else {
                    path.parent()
                        .unwrap_or_else(|| Path::new("."))
                        .to_path_buf()
                };
                Ok(Self::Local(base_dir.join(reference)))
            }
            Self::Http(url) => {
                let resolved = url
                    .join(reference)
                    .with_context(|| format!("resolve `{reference}` against `{url}`"))?;
                Ok(Self::Http(resolved))
            }
        }
    }

    fn read_to_string(&self) -> Result<String> {
        match self {
            Self::Local(path) => fs::read_to_string(path)
                .with_context(|| format!("read manifest {}", path.display())),
            Self::Http(url) => {
                let bytes = http_get_bytes(url)?;
                String::from_utf8(bytes)
                    .with_context(|| format!("manifest response is not utf-8: {url}"))
            }
        }
    }

    fn copy_to(&self, destination: &Path) -> Result<()> {
        match self {
            Self::Local(path) => {
                if !path.is_file() {
                    bail!("bundle file not found at {}", path.display());
                }
                fs::copy(path, destination).with_context(|| {
                    format!(
                        "copy bundle from {} to {}",
                        path.display(),
                        destination.display()
                    )
                })?;
                Ok(())
            }
            Self::Http(url) => {
                let bytes = http_get_bytes(url)?;
                fs::write(destination, &bytes)
                    .with_context(|| format!("write {}", destination.display()))?;
                Ok(())
            }
        }
    }
}

fn http_get_bytes(url: &Url) -> Result<Vec<u8>> {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .build();
    let agent: ureq::Agent = config.into();
    let mut response = agent
        .get(url.as_str())
        .call()
        .map_err(|error| anyhow::anyhow!("http GET {} failed: {error}", url))?;
    response
        .body_mut()
        .read_to_vec()
        .map_err(|error| anyhow::anyhow!("read response body from {} failed: {error}", url))
}

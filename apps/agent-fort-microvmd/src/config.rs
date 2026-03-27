use std::path::PathBuf;

use anyhow::{Context, Result, bail};

#[cfg(not(windows))]
const DEFAULT_SOCKET_PATH: &str = "/tmp/agent-fort-microvmd.sock";
const DEFAULT_VCPU_COUNT: u8 = 1;
const DEFAULT_MEMORY_MIB: u32 = 512;
const DEFAULT_GUEST_VSOCK_PORT: u32 = 10_000;

#[derive(Debug, Clone)]
pub struct Config {
    pub socket_path: PathBuf,
    pub firecracker_path: PathBuf,
    pub kernel_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub state_root: PathBuf,
    pub vcpu_count: u8,
    pub memory_mib: u32,
    pub guest_vsock_port: u32,
}

impl Config {
    pub fn load() -> Result<Self> {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        Self::load_from_args(&args)
    }

    fn load_from_args(args: &[String]) -> Result<Self> {
        let mut raw = Parsed::default();

        let mut i = 0usize;
        while i < args.len() {
            match args[i].as_str() {
                "--socket" => {
                    let (value, next) = parse_value(args, i, "--socket")?;
                    raw.socket_path = Some(PathBuf::from(value));
                    i = next;
                }
                "--firecracker-path" => {
                    let (value, next) = parse_value(args, i, "--firecracker-path")?;
                    raw.firecracker_path = Some(PathBuf::from(value));
                    i = next;
                }
                "--kernel-path" => {
                    let (value, next) = parse_value(args, i, "--kernel-path")?;
                    raw.kernel_path = Some(PathBuf::from(value));
                    i = next;
                }
                "--rootfs-path" => {
                    let (value, next) = parse_value(args, i, "--rootfs-path")?;
                    raw.rootfs_path = Some(PathBuf::from(value));
                    i = next;
                }
                "--state-root" => {
                    let (value, next) = parse_value(args, i, "--state-root")?;
                    raw.state_root = Some(PathBuf::from(value));
                    i = next;
                }
                "--vcpu-count" => {
                    let (value, next) = parse_value(args, i, "--vcpu-count")?;
                    raw.vcpu_count = Some(parse_u8_flag(&value, "--vcpu-count")?);
                    i = next;
                }
                "--memory-mib" => {
                    let (value, next) = parse_value(args, i, "--memory-mib")?;
                    raw.memory_mib = Some(parse_u32_flag(&value, "--memory-mib")?);
                    i = next;
                }
                "--guest-vsock-port" => {
                    let (value, next) = parse_value(args, i, "--guest-vsock-port")?;
                    raw.guest_vsock_port = Some(parse_u32_flag(&value, "--guest-vsock-port")?);
                    i = next;
                }
                "--help" | "-h" => {
                    println!("{}", help_text());
                    std::process::exit(0);
                }
                other => bail!("unknown option for `af-microvmd`: `{other}`"),
            }
        }

        Ok(Self {
            socket_path: raw
                .socket_path
                .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_PATH)),
            firecracker_path: required_path(raw.firecracker_path, "--firecracker-path")?,
            kernel_path: required_path(raw.kernel_path, "--kernel-path")?,
            rootfs_path: required_path(raw.rootfs_path, "--rootfs-path")?,
            state_root: optional_path(raw.state_root, default_state_root)?,
            vcpu_count: required_non_zero(
                raw.vcpu_count.unwrap_or(DEFAULT_VCPU_COUNT),
                "--vcpu-count",
            )?,
            memory_mib: required_non_zero(
                raw.memory_mib.unwrap_or(DEFAULT_MEMORY_MIB),
                "--memory-mib",
            )?,
            guest_vsock_port: required_non_zero(
                raw.guest_vsock_port.unwrap_or(DEFAULT_GUEST_VSOCK_PORT),
                "--guest-vsock-port",
            )?,
        })
    }
}

#[derive(Debug, Default)]
struct Parsed {
    socket_path: Option<PathBuf>,
    firecracker_path: Option<PathBuf>,
    kernel_path: Option<PathBuf>,
    rootfs_path: Option<PathBuf>,
    state_root: Option<PathBuf>,
    vcpu_count: Option<u8>,
    memory_mib: Option<u32>,
    guest_vsock_port: Option<u32>,
}

fn parse_value(args: &[String], index: usize, flag: &str) -> Result<(String, usize)> {
    let value = args
        .get(index + 1)
        .ok_or_else(|| anyhow::anyhow!("missing value for `{flag}`"))?;
    Ok((value.clone(), index + 2))
}

fn required_path(path: Option<PathBuf>, flag: &str) -> Result<PathBuf> {
    path.ok_or_else(|| anyhow::anyhow!("missing required option `{flag}`"))
        .and_then(resolve_path)
}

fn optional_path(path: Option<PathBuf>, default: impl FnOnce() -> PathBuf) -> Result<PathBuf> {
    resolve_path(path.unwrap_or_else(default))
}

fn resolve_path(path: PathBuf) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path);
    }

    std::env::current_dir()
        .map(|current| current.join(path))
        .context("resolve relative path")
}

fn parse_u8_flag(value: &str, flag: &str) -> Result<u8> {
    value
        .parse::<u8>()
        .with_context(|| format!("parse `{flag}` as u8"))
}

fn parse_u32_flag(value: &str, flag: &str) -> Result<u32> {
    value
        .parse::<u32>()
        .with_context(|| format!("parse `{flag}` as u32"))
}

fn required_non_zero<T>(value: T, flag: &str) -> Result<T>
where
    T: PartialEq + From<u8> + Copy,
{
    if value == T::from(0) {
        bail!("`{flag}` must be greater than 0");
    }
    Ok(value)
}

#[cfg(windows)]
fn default_state_root() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .map(PathBuf::from)
                .map(|home| home.join("AppData").join("Local"))
        })
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("AgentFort").join("microvmd")
}

#[cfg(not(windows))]
fn default_state_root() -> PathBuf {
    if is_root() {
        return PathBuf::from("/var/lib/agent-fort/microvmd");
    }
    if let Some(xdg) = std::env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(xdg).join("agent-fort").join("microvmd");
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".local")
        .join("state")
        .join("agent-fort")
        .join("microvmd")
}

#[cfg(not(windows))]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn help_text() -> String {
    "Usage: af-microvmd [OPTIONS]\n\n\
Options:\n  \
--socket <PATH>\n  \
--firecracker-path <PATH>\n  \
--kernel-path <PATH>\n  \
--rootfs-path <PATH>\n  \
--state-root <PATH>\n  \
--vcpu-count <COUNT>\n  \
--memory-mib <MIB>\n  \
--guest-vsock-port <PORT>\n  \
-h, --help"
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_required_flags() {
        let args = vec![
            "--firecracker-path".to_string(),
            "/usr/bin/firecracker".to_string(),
            "--kernel-path".to_string(),
            "/opt/guest/vmlinux".to_string(),
            "--rootfs-path".to_string(),
            "/opt/guest/rootfs.ext4".to_string(),
        ];

        let config = Config::load_from_args(&args).expect("parse config");
        assert_eq!(config.socket_path, PathBuf::from(DEFAULT_SOCKET_PATH));
        assert_eq!(
            config.firecracker_path,
            PathBuf::from("/usr/bin/firecracker")
        );
        assert_eq!(config.vcpu_count, DEFAULT_VCPU_COUNT);
        assert_eq!(config.memory_mib, DEFAULT_MEMORY_MIB);
        assert_eq!(config.guest_vsock_port, DEFAULT_GUEST_VSOCK_PORT);
    }

    #[test]
    fn parses_machine_flags() {
        let args = vec![
            "--firecracker-path".to_string(),
            "/usr/bin/firecracker".to_string(),
            "--kernel-path".to_string(),
            "/opt/guest/vmlinux".to_string(),
            "--rootfs-path".to_string(),
            "/opt/guest/rootfs.ext4".to_string(),
            "--vcpu-count".to_string(),
            "2".to_string(),
            "--memory-mib".to_string(),
            "1024".to_string(),
            "--guest-vsock-port".to_string(),
            "12000".to_string(),
        ];

        let config = Config::load_from_args(&args).expect("parse config");
        assert_eq!(config.vcpu_count, 2);
        assert_eq!(config.memory_mib, 1024);
        assert_eq!(config.guest_vsock_port, 12_000);
    }

    #[test]
    fn rejects_zero_machine_values() {
        let args = vec![
            "--firecracker-path".to_string(),
            "/usr/bin/firecracker".to_string(),
            "--kernel-path".to_string(),
            "/opt/guest/vmlinux".to_string(),
            "--rootfs-path".to_string(),
            "/opt/guest/rootfs.ext4".to_string(),
            "--memory-mib".to_string(),
            "0".to_string(),
        ];

        let error = Config::load_from_args(&args).expect_err("zero memory_mib should fail");
        assert!(error.to_string().contains("--memory-mib"));
    }
}

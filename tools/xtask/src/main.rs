use anyhow::{Context, Result, bail};
use flate2::Compression;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs::File, io::BufWriter};
use tar::Builder;

fn main() {
    if let Err(err) = run() {
        eprintln!("xtask failed: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        print_usage();
        return Ok(());
    }

    match args[0].as_str() {
        "proto" => run_proto(&args[1..]),
        "dev" => run_dev(&args[1..]),
        "bwrap" => run_bwrap(&args[1..]),
        "package" => run_package(&args[1..]),
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        other => {
            print_usage();
            bail!("unknown command `{other}`")
        }
    }
}

fn run_proto(args: &[String]) -> Result<()> {
    if args.is_empty() {
        print_proto_usage();
        return Ok(());
    }

    let root = repo_root()?;
    match args[0].as_str() {
        "lint" => run_proto_lint(&root),
        "generate" => run_proto_generate(&root),
        "breaking" => {
            let against = parse_flag_value(&args[1..], "--against")
                .unwrap_or_else(|| ".git#branch=main".to_string());
            run_proto_breaking(&root, &against)
        }
        "check-rust" => run_proto_rust_codegen_check(&root),
        "ci" => {
            let against = parse_flag_value(&args[1..], "--against")
                .unwrap_or_else(|| ".git#branch=main".to_string());
            run_proto_ci(&root, &against)
        }
        "help" | "--help" | "-h" => {
            print_proto_usage();
            Ok(())
        }
        other => {
            print_proto_usage();
            bail!("unknown `proto` subcommand `{other}`")
        }
    }
}

fn run_dev(args: &[String]) -> Result<()> {
    if args.is_empty() {
        print_dev_usage();
        return Ok(());
    }

    let root = repo_root()?;
    match args[0].as_str() {
        "fmt" => run_fmt_check(&root),
        "lint" => run_clippy_check(&root),
        "test" => run_workspace_tests(&root),
        "ci" => run_dev_ci(&root),
        "help" | "--help" | "-h" => {
            print_dev_usage();
            Ok(())
        }
        other => {
            print_dev_usage();
            bail!("unknown `dev` subcommand `{other}`")
        }
    }
}

fn run_proto_ci(root: &Path, against: &str) -> Result<()> {
    run_proto_lint(root)?;
    run_proto_breaking(root, against)?;
    run_proto_generate(root)?;
    run_proto_rust_codegen_check(root)
}

fn run_proto_lint(root: &Path) -> Result<()> {
    run_checked(
        Command::new("buf").arg("lint").current_dir(root),
        "run `buf lint`",
    )
}

fn run_proto_breaking(root: &Path, against: &str) -> Result<()> {
    run_checked(
        Command::new("buf")
            .arg("breaking")
            .arg("--against")
            .arg(against)
            .current_dir(root),
        "run `buf breaking`",
    )
}

fn run_proto_generate(root: &Path) -> Result<()> {
    run_checked(
        Command::new("buf").arg("generate").current_dir(root),
        "run `buf generate`",
    )
}

fn run_proto_rust_codegen_check(root: &Path) -> Result<()> {
    run_checked(
        Command::new("cargo")
            .arg("test")
            .arg("-p")
            .arg("af-rpc-proto")
            .current_dir(root),
        "run rust proto generation check (`cargo test -p af-rpc-proto`)",
    )
}

fn run_dev_ci(root: &Path) -> Result<()> {
    run_fmt_check(root)?;
    run_clippy_check(root)?;
    run_workspace_tests(root)
}

fn run_fmt_check(root: &Path) -> Result<()> {
    run_checked(
        Command::new("cargo")
            .arg("fmt")
            .arg("--all")
            .arg("--check")
            .current_dir(root),
        "run format check (`cargo fmt --all --check`)",
    )
}

fn run_clippy_check(root: &Path) -> Result<()> {
    run_checked(
        Command::new("cargo")
            .arg("clippy")
            .arg("--workspace")
            .arg("--all-targets")
            .arg("--")
            .arg("-D")
            .arg("warnings")
            .current_dir(root),
        "run lint (`cargo clippy --workspace --all-targets -- -D warnings`)",
    )
}

fn run_workspace_tests(root: &Path) -> Result<()> {
    run_checked(
        Command::new("cargo")
            .arg("test")
            .arg("--workspace")
            .current_dir(root),
        "run workspace tests (`cargo test --workspace`)",
    )
}

fn run_bwrap(args: &[String]) -> Result<()> {
    if args.is_empty() {
        print_bwrap_usage();
        return Ok(());
    }

    match args[0].as_str() {
        "build" => build_bwrap(&args[1..]),
        "verify" => verify_bwrap(&args[1..]),
        "help" | "--help" | "-h" => {
            print_bwrap_usage();
            Ok(())
        }
        other => {
            print_bwrap_usage();
            bail!("unknown `bwrap` subcommand `{other}`")
        }
    }
}

fn run_package(args: &[String]) -> Result<()> {
    if args.is_empty() {
        print_package_usage();
        return Ok(());
    }

    match args[0].as_str() {
        "bundle" => build_runtime_bundle(&args[1..]),
        "af-bootstrap" => build_sdk_af_bootstrap_binary(&args[1..]),
        "help" | "--help" | "-h" => {
            print_package_usage();
            Ok(())
        }
        other => {
            print_package_usage();
            bail!("unknown `package` subcommand `{other}`")
        }
    }
}

const DEFAULT_RUNTIME_BUNDLE_FILE: &str = "bundle.tar.gz";
const DEFAULT_RUNTIME_MANIFEST_FILE: &str = "manifest.json";
const RUNTIME_DAEMON_ENTRY: &str = "agent-fortd";
const RUNTIME_BWRAP_ENTRY: &str = "bwrap";
const RUNTIME_HELPER_ENTRY: &str = "helper";

#[derive(Debug, Clone, Copy)]
enum BuildProfile {
    Debug,
    Release,
}

impl BuildProfile {
    fn parse(raw: &str) -> Result<Self> {
        match raw {
            "debug" | "dev" => Ok(Self::Debug),
            "release" => Ok(Self::Release),
            other => bail!("unsupported profile `{other}`; expected debug/dev or release"),
        }
    }

    fn output_dir(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Release => "release",
        }
    }

    fn apply_to_command(self, command: &mut Command) {
        if matches!(self, Self::Release) {
            command.arg("--release");
        }
    }
}

#[derive(Debug, Default)]
struct PackageBundleArgs {
    target: Option<String>,
    profile: Option<BuildProfile>,
    version: Option<String>,
    output_dir: Option<PathBuf>,
    bwrap_path: Option<PathBuf>,
    helper_path: Option<PathBuf>,
    bundle_name: Option<String>,
    manifest_name: Option<String>,
    skip_build: bool,
}

impl PackageBundleArgs {
    fn parse(args: &[String]) -> Result<Self> {
        let mut parsed = Self::default();
        let mut i = 0usize;
        while i < args.len() {
            match args[i].as_str() {
                "--target" => {
                    let (value, next) = parse_option_value(args, i, "--target")?;
                    parsed.target = Some(value);
                    i = next;
                }
                "--profile" => {
                    let (value, next) = parse_option_value(args, i, "--profile")?;
                    parsed.profile = Some(BuildProfile::parse(&value)?);
                    i = next;
                }
                "--version" => {
                    let (value, next) = parse_option_value(args, i, "--version")?;
                    parsed.version = Some(value);
                    i = next;
                }
                "--output-dir" => {
                    let (value, next) = parse_option_value(args, i, "--output-dir")?;
                    parsed.output_dir = Some(PathBuf::from(value));
                    i = next;
                }
                "--bwrap-path" => {
                    let (value, next) = parse_option_value(args, i, "--bwrap-path")?;
                    parsed.bwrap_path = Some(PathBuf::from(value));
                    i = next;
                }
                "--helper-path" => {
                    let (value, next) = parse_option_value(args, i, "--helper-path")?;
                    parsed.helper_path = Some(PathBuf::from(value));
                    i = next;
                }
                "--bundle-name" => {
                    let (value, next) = parse_option_value(args, i, "--bundle-name")?;
                    parsed.bundle_name = Some(value);
                    i = next;
                }
                "--manifest-name" => {
                    let (value, next) = parse_option_value(args, i, "--manifest-name")?;
                    parsed.manifest_name = Some(value);
                    i = next;
                }
                "--skip-build" => {
                    parsed.skip_build = true;
                    i += 1;
                }
                other => {
                    bail!("unknown option for `package bundle`: `{other}`");
                }
            }
        }
        Ok(parsed)
    }
}

#[derive(Debug, Default)]
struct PackageAfBootstrapArgs {
    target: Option<String>,
    profile: Option<BuildProfile>,
    output_dir: Option<PathBuf>,
    af_bootstrap_path: Option<PathBuf>,
    skip_build: bool,
}

impl PackageAfBootstrapArgs {
    fn parse(args: &[String]) -> Result<Self> {
        let mut parsed = Self::default();
        let mut i = 0usize;
        while i < args.len() {
            match args[i].as_str() {
                "--target" => {
                    let (value, next) = parse_option_value(args, i, "--target")?;
                    parsed.target = Some(value);
                    i = next;
                }
                "--profile" => {
                    let (value, next) = parse_option_value(args, i, "--profile")?;
                    parsed.profile = Some(BuildProfile::parse(&value)?);
                    i = next;
                }
                "--output-dir" => {
                    let (value, next) = parse_option_value(args, i, "--output-dir")?;
                    parsed.output_dir = Some(PathBuf::from(value));
                    i = next;
                }
                "--af-bootstrap-path" => {
                    let (value, next) = parse_option_value(args, i, "--af-bootstrap-path")?;
                    parsed.af_bootstrap_path = Some(PathBuf::from(value));
                    i = next;
                }
                "--skip-build" => {
                    parsed.skip_build = true;
                    i += 1;
                }
                other => {
                    bail!("unknown option for `package af-bootstrap`: `{other}`");
                }
            }
        }
        Ok(parsed)
    }
}

#[derive(Debug, Serialize)]
struct BootstrapSyncManifest {
    version: String,
    bundle: BootstrapSyncBundle,
}

#[derive(Debug, Serialize)]
struct BootstrapSyncBundle {
    source: String,
    sha256: String,
    format: String,
    daemon_rel_path: String,
    bwrap_rel_path: String,
    helper_rel_path: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SdkBootstrapSha256Manifest {
    bootstrap_sha256: BTreeMap<String, String>,
}

fn build_runtime_bundle(args: &[String]) -> Result<()> {
    if has_flag(args, "--help") || has_flag(args, "-h") {
        print_package_bundle_usage();
        return Ok(());
    }

    let parsed = PackageBundleArgs::parse(args)?;
    let root = repo_root()?;
    let target = parsed.target.unwrap_or_else(machine_target_label);
    let profile = parsed.profile.unwrap_or(BuildProfile::Release);
    let version = parsed.version.unwrap_or_else(default_runtime_version);
    let output_dir = parsed
        .output_dir
        .unwrap_or_else(|| root.join("assets").join("agent-fortd").join(&target));
    let bundle_name = parsed
        .bundle_name
        .unwrap_or_else(|| DEFAULT_RUNTIME_BUNDLE_FILE.to_string());
    let manifest_name = parsed
        .manifest_name
        .unwrap_or_else(|| DEFAULT_RUNTIME_MANIFEST_FILE.to_string());
    let bundle_path = output_dir.join(&bundle_name);
    let manifest_path = output_dir.join(&manifest_name);

    fs::create_dir_all(&output_dir)
        .with_context(|| format!("failed to create {}", output_dir.display()))?;

    if !parsed.skip_build {
        build_runtime_binaries(&root, profile)?;
    }

    let daemon_binary = binary_output_path(&root, profile, "agent-fortd");
    let bwrap_binary = parsed
        .bwrap_path
        .unwrap_or_else(|| bwrap_output_binary(&root, &target));
    let helper_binary = parsed
        .helper_path
        .unwrap_or_else(|| binary_output_path(&root, profile, "af-helper"));

    ensure_packaging_input(&daemon_binary, "agent-fortd binary")?;
    ensure_packaging_input(&bwrap_binary, "bwrap binary")?;
    ensure_packaging_input(&helper_binary, "agent-fort-helper binary")?;

    create_runtime_bundle_archive(&bundle_path, &daemon_binary, &bwrap_binary, &helper_binary)?;
    let bundle_sha256 = sha256_hex_file(&bundle_path)?;

    let manifest = BootstrapSyncManifest {
        version,
        bundle: BootstrapSyncBundle {
            source: bundle_name.clone(),
            sha256: bundle_sha256.clone(),
            format: "tar.gz".to_string(),
            daemon_rel_path: RUNTIME_DAEMON_ENTRY.to_string(),
            bwrap_rel_path: RUNTIME_BWRAP_ENTRY.to_string(),
            helper_rel_path: RUNTIME_HELPER_ENTRY.to_string(),
        },
    };
    write_runtime_manifest(&manifest_path, &manifest)?;

    let checksum_path = output_dir.join("bundle.sha256");
    fs::write(&checksum_path, format!("{bundle_sha256}  {bundle_name}\n"))
        .with_context(|| format!("failed to write {}", checksum_path.display()))?;

    println!("runtime bundle: {}", bundle_path.display());
    println!("manifest: {}", manifest_path.display());
    println!("bundle sha256: {bundle_sha256}");
    Ok(())
}

fn build_sdk_af_bootstrap_binary(args: &[String]) -> Result<()> {
    if has_flag(args, "--help") || has_flag(args, "-h") {
        print_package_af_bootstrap_usage();
        return Ok(());
    }

    let parsed = PackageAfBootstrapArgs::parse(args)?;
    let root = repo_root()?;
    let target = parsed.target.unwrap_or_else(machine_target_label);
    let profile = parsed.profile.unwrap_or(BuildProfile::Release);
    let output_dir = parsed
        .output_dir
        .unwrap_or_else(|| root.join("assets").join("af-bootstrap").join(&target));
    let binary_name = binary_file_name("af-bootstrap");
    let output_binary_path = output_dir.join(&binary_name);

    fs::create_dir_all(&output_dir)
        .with_context(|| format!("failed to create {}", output_dir.display()))?;

    if !parsed.skip_build {
        build_af_bootstrap_binary(&root, profile)?;
    }

    let bootstrap_binary = parsed
        .af_bootstrap_path
        .unwrap_or_else(|| binary_output_path(&root, profile, "af-bootstrap"));
    ensure_packaging_input(&bootstrap_binary, "af-bootstrap binary")?;

    fs::copy(&bootstrap_binary, &output_binary_path).with_context(|| {
        format!(
            "failed to copy bootstrap binary from {} to {}",
            bootstrap_binary.display(),
            output_binary_path.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&output_binary_path, fs::Permissions::from_mode(0o755)).with_context(
            || {
                format!(
                    "failed to set permissions for {}",
                    output_binary_path.display()
                )
            },
        )?;
    }

    let binary_sha256 = sha256_hex_file(&output_binary_path)?;
    let binary_sha_path = output_dir.join(format!("{binary_name}.sha256"));
    fs::write(
        &binary_sha_path,
        format!("{binary_sha256}  {binary_name}\n"),
    )
    .with_context(|| format!("failed to write {}", binary_sha_path.display()))?;
    sync_sdk_bootstrap_expected_sha256(&root, &target, profile, &binary_sha256)?;

    println!("sdk af-bootstrap binary: {}", output_binary_path.display());
    println!("binary sha256: {binary_sha256}");
    Ok(())
}

fn sync_sdk_bootstrap_expected_sha256(
    repo_root: &Path,
    target: &str,
    _profile: BuildProfile,
    binary_sha256: &str,
) -> Result<()> {
    let output_path = repo_root
        .join("sdk")
        .join("rust")
        .join("src")
        .join("generated")
        .join("bootstrap-sha256.toml");

    fs::create_dir_all(
        output_path
            .parent()
            .context("bootstrap checksum target path has no parent directory")?,
    )
    .with_context(|| {
        format!(
            "failed to create parent directory for {}",
            output_path.display()
        )
    })?;

    let next = binary_sha256.trim();
    let mut manifest = read_sdk_bootstrap_sha256_manifest(&output_path)?;
    let current = manifest.bootstrap_sha256.get(target).cloned();
    if current.as_deref() == Some(next) {
        println!(
            "sdk expected bootstrap sha256 unchanged: {}",
            output_path.display()
        );
        return Ok(());
    }

    manifest
        .bootstrap_sha256
        .insert(target.to_string(), next.to_string());
    let rendered = toml::to_string_pretty(&manifest)
        .context("failed to serialize sdk bootstrap checksum manifest")?;
    fs::write(&output_path, rendered)
        .with_context(|| format!("failed to write {}", output_path.display()))?;
    println!(
        "updated sdk expected bootstrap sha256: {} ({target})",
        output_path.display(),
    );
    Ok(())
}

fn read_sdk_bootstrap_sha256_manifest(path: &Path) -> Result<SdkBootstrapSha256Manifest> {
    if !path.exists() {
        return Ok(SdkBootstrapSha256Manifest::default());
    }

    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    toml::from_str(&content).with_context(|| {
        format!(
            "failed to parse sdk bootstrap checksum manifest {}",
            path.display()
        )
    })
}

fn build_af_bootstrap_binary(root: &Path, profile: BuildProfile) -> Result<()> {
    let mut build = Command::new("cargo");
    build
        .arg("build")
        .arg("--package")
        .arg("af-bootstrap")
        .current_dir(root);
    profile.apply_to_command(&mut build);
    run_checked(&mut build, "build af-bootstrap binary")
}

fn parse_option_value(args: &[String], index: usize, option: &str) -> Result<(String, usize)> {
    let value = args
        .get(index + 1)
        .with_context(|| format!("missing value for `{option}`"))?
        .to_string();
    Ok((value, index + 2))
}

fn default_runtime_version() -> String {
    let generated_at_unix_s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    format!("dev-{generated_at_unix_s}")
}

fn build_runtime_binaries(root: &Path, profile: BuildProfile) -> Result<()> {
    let mut build = Command::new("cargo");
    build
        .arg("build")
        .arg("--package")
        .arg("agent-fortd")
        .arg("--package")
        .arg("af-helper")
        .current_dir(root);
    profile.apply_to_command(&mut build);
    run_checked(&mut build, "build agent-fortd and af-helper binaries")
}

fn binary_output_path(root: &Path, profile: BuildProfile, binary: &str) -> PathBuf {
    root.join("target")
        .join(profile.output_dir())
        .join(binary_file_name(binary))
}

fn binary_file_name(binary: &str) -> String {
    if env::consts::EXE_EXTENSION.is_empty() {
        binary.to_string()
    } else {
        format!("{binary}.{}", env::consts::EXE_EXTENSION)
    }
}

fn ensure_packaging_input(path: &Path, label: &str) -> Result<()> {
    if !path.is_file() {
        bail!("{label} not found at {}", path.display());
    }
    Ok(())
}

fn create_runtime_bundle_archive(
    bundle_path: &Path,
    daemon_binary: &Path,
    bwrap_binary: &Path,
    helper_binary: &Path,
) -> Result<()> {
    let file = File::create(bundle_path)
        .with_context(|| format!("failed to create {}", bundle_path.display()))?;
    let writer = BufWriter::new(file);
    let encoder = GzEncoder::new(writer, Compression::default());
    let mut archive = Builder::new(encoder);

    append_bundle_entry(&mut archive, daemon_binary, RUNTIME_DAEMON_ENTRY)?;
    append_bundle_entry(&mut archive, bwrap_binary, RUNTIME_BWRAP_ENTRY)?;
    append_bundle_entry(&mut archive, helper_binary, RUNTIME_HELPER_ENTRY)?;

    archive
        .finish()
        .context("failed to finish runtime bundle archive")?;
    let encoder = archive
        .into_inner()
        .context("failed to finalize runtime bundle archive writer")?;
    let mut writer = encoder
        .finish()
        .context("failed to finalize runtime bundle gzip stream")?;
    std::io::Write::flush(&mut writer).context("failed to flush runtime bundle output")
}

fn append_bundle_entry(
    archive: &mut Builder<GzEncoder<BufWriter<File>>>,
    source: &Path,
    archive_name: &str,
) -> Result<()> {
    archive
        .append_path_with_name(source, archive_name)
        .with_context(|| format!("failed to append {} as {}", source.display(), archive_name))
}

fn sha256_hex_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
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

fn write_runtime_manifest(path: &Path, manifest: &BootstrapSyncManifest) -> Result<()> {
    let content =
        serde_json::to_string_pretty(manifest).context("failed to serialize runtime manifest")?;
    fs::write(path, format!("{content}\n"))
        .with_context(|| format!("failed to write {}", path.display()))
}

fn build_bwrap(args: &[String]) -> Result<()> {
    let target = parse_flag_value(args, "--target").unwrap_or_else(machine_target_label);
    ensure_supported_bwrap_target(&target)?;
    let engine = resolve_engine(parse_flag_value(args, "--engine").as_deref())?;
    let image = parse_flag_value(args, "--image")
        .unwrap_or_else(|| format!("agent-runtime/bwrap-builder:{}", sanitize_tag(&target)));
    let no_cache = has_flag(args, "--no-cache");

    let root = repo_root()?;
    let bubblewrap_src = root.join("vendor/bubblewrap");
    if !bubblewrap_src.is_dir() {
        bail!(
            "bubblewrap source is missing at {}; initialize submodule first",
            bubblewrap_src.display()
        );
    }

    let dockerfile = root.join("tools/xtask/bwrap/Dockerfile");
    if !dockerfile.is_file() {
        bail!("missing Dockerfile at {}", dockerfile.display());
    }

    let mut image_build = Command::new(engine.as_str());
    image_build
        .arg("build")
        .arg("--file")
        .arg(&dockerfile)
        .arg("--tag")
        .arg(&image);
    if no_cache {
        image_build.arg("--no-cache");
    }
    image_build.arg(&root);
    run_checked(&mut image_build, "build bwrap builder container image")?;

    let assets_root = root.join("assets");
    let target_dir = bwrap_output_dir(&root, &target);
    fs::create_dir_all(&target_dir)
        .with_context(|| format!("failed to create {}", target_dir.display()))?;

    let workspace_volume = format!("{}:/workspace:ro", root.display());
    let assets_volume = format!("{}:/assets:rw", assets_root.display());
    let out_dir = format!("/assets/bwrap/{target}");
    let mut build_run = Command::new(engine.as_str());
    build_run
        .arg("run")
        .arg("--rm")
        .arg("--workdir")
        .arg("/workspace")
        .arg("--volume")
        .arg(&workspace_volume)
        .arg("--volume")
        .arg(&assets_volume)
        .arg("--env")
        .arg("BWRAP_SRC=/workspace/vendor/bubblewrap")
        .arg("--env")
        .arg(format!("OUT_DIR={out_dir}"))
        .arg(&image);
    run_checked(&mut build_run, "run bwrap static build in container")?;

    let binary_path = bwrap_output_binary(&root, &target);
    let sha256 = verify_binary_is_static(&binary_path)?;
    write_bwrap_manifest(
        &target_dir,
        &target,
        &binary_path,
        &sha256,
        engine.as_str(),
        &image,
    )?;

    println!("built static bwrap: {}", binary_path.display());
    println!("sha256: {sha256}");
    Ok(())
}

fn verify_bwrap(args: &[String]) -> Result<()> {
    let target = parse_flag_value(args, "--target").unwrap_or_else(machine_target_label);
    ensure_supported_bwrap_target(&target)?;
    let root = repo_root()?;
    let binary_path = bwrap_output_binary(&root, &target);
    let sha256 = verify_binary_is_static(&binary_path)?;
    println!("verified static bwrap: {}", binary_path.display());
    println!("sha256: {sha256}");
    Ok(())
}

#[derive(Debug, Serialize)]
struct BwrapManifest {
    target: String,
    binary_path: String,
    sha256: String,
    builder_engine: String,
    builder_image: String,
    generated_at_unix_s: u64,
}

fn write_bwrap_manifest(
    target_dir: &Path,
    target: &str,
    binary_path: &Path,
    sha256: &str,
    builder_engine: &str,
    builder_image: &str,
) -> Result<()> {
    let generated_at_unix_s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs();
    let manifest = BwrapManifest {
        target: target.to_string(),
        binary_path: binary_path.to_string_lossy().to_string(),
        sha256: sha256.to_string(),
        builder_engine: builder_engine.to_string(),
        builder_image: builder_image.to_string(),
        generated_at_unix_s,
    };
    let manifest_path = target_dir.join("manifest.json");
    let content =
        serde_json::to_string_pretty(&manifest).context("failed to serialize bwrap manifest")?;
    fs::write(&manifest_path, format!("{content}\n"))
        .with_context(|| format!("failed to write {}", manifest_path.display()))?;

    let sha_path = target_dir.join("sha256.txt");
    fs::write(&sha_path, format!("{sha256}  bwrap\n"))
        .with_context(|| format!("failed to write {}", sha_path.display()))?;
    Ok(())
}

fn verify_binary_is_static(binary_path: &Path) -> Result<String> {
    if !binary_path.is_file() {
        bail!("missing bwrap binary at {}", binary_path.display());
    }

    let file_output = run_capture("file", &[binary_path.as_os_str()])?;
    let file_text = String::from_utf8(file_output.stdout)
        .context("`file` output is not valid UTF-8")?
        .to_ascii_lowercase();
    if !file_text.contains("statically linked") {
        bail!(
            "bwrap is not static according to `file`: {}",
            file_text.trim()
        );
    }

    let ldd_output = Command::new("ldd")
        .arg(binary_path)
        .output()
        .with_context(|| format!("failed to execute `ldd {}`", binary_path.display()))?;
    let ldd_text = format!(
        "{}{}",
        String::from_utf8_lossy(&ldd_output.stdout),
        String::from_utf8_lossy(&ldd_output.stderr)
    )
    .to_ascii_lowercase();
    let ok =
        ldd_text.contains("not a dynamic executable") || ldd_text.contains("statically linked");
    if !ok {
        bail!("bwrap failed static check by `ldd`: {}", ldd_text.trim());
    }

    let sha_output = run_capture("sha256sum", &[binary_path.as_os_str()])?;
    let sha_line = String::from_utf8(sha_output.stdout)
        .context("`sha256sum` output is not valid UTF-8")?
        .trim()
        .to_string();
    let sha = sha_line
        .split_whitespace()
        .next()
        .with_context(|| format!("unexpected sha256sum output: `{sha_line}`"))?;
    Ok(sha.to_string())
}

fn resolve_engine(engine: Option<&str>) -> Result<ContainerEngine> {
    if let Some(raw) = engine {
        let parsed = ContainerEngine::from_str(raw)?;
        ensure_command_exists(parsed.as_str())?;
        return Ok(parsed);
    }

    if ensure_command_exists("podman").is_ok() {
        return Ok(ContainerEngine::Podman);
    }
    if ensure_command_exists("docker").is_ok() {
        return Ok(ContainerEngine::Docker);
    }

    bail!("no supported container engine found; install podman or docker")
}

#[derive(Debug, Clone, Copy)]
enum ContainerEngine {
    Docker,
    Podman,
}

impl ContainerEngine {
    fn from_str(raw: &str) -> Result<Self> {
        match raw {
            "docker" => Ok(Self::Docker),
            "podman" => Ok(Self::Podman),
            _ => bail!("unsupported container engine `{raw}`; expected docker or podman"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }
}

fn ensure_command_exists(program: &str) -> Result<()> {
    let status = Command::new(program)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("failed to execute `{program} --version`"))?;
    if !status.success() {
        bail!("`{program} --version` exited with status {status}");
    }
    Ok(())
}

fn ensure_supported_bwrap_target(target_label: &str) -> Result<()> {
    match target_label {
        "linux-x86_64" => Ok(()),
        other => {
            bail!("unsupported bwrap target label `{other}`; currently supported: linux-x86_64")
        }
    }
}

fn parse_flag_value(args: &[String], key: &str) -> Option<String> {
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == key {
            return args.get(i + 1).cloned();
        }
        i += 1;
    }
    None
}

fn has_flag(args: &[String], key: &str) -> bool {
    args.iter().any(|arg| arg == key)
}

fn machine_target_label() -> String {
    format!("{}-{}", env::consts::OS, env::consts::ARCH)
}

fn bwrap_output_dir(repo_root: &Path, target: &str) -> PathBuf {
    repo_root.join("assets").join("bwrap").join(target)
}

fn bwrap_output_binary(repo_root: &Path, target: &str) -> PathBuf {
    bwrap_output_dir(repo_root, target).join("bwrap")
}

fn sanitize_tag(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            output.push(ch);
        } else {
            output.push('-');
        }
    }
    if output.is_empty() {
        "local".to_string()
    } else {
        output
    }
}

fn run_checked(command: &mut Command, action: &str) -> Result<()> {
    eprintln!("+ {:?}", command);
    let status = command
        .status()
        .with_context(|| format!("failed to {action}"))?;
    if !status.success() {
        bail!("failed to {action}: exit status {status}");
    }
    Ok(())
}

fn run_capture(program: &str, args: &[&std::ffi::OsStr]) -> Result<Output> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute `{program}`"))?;
    if !output.status.success() {
        bail!(
            "command `{program}` failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output)
}

fn repo_root() -> Result<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir
        .parent()
        .and_then(|path| path.parent())
        .with_context(|| {
            format!(
                "cannot resolve repository root from xtask manifest dir {}",
                manifest_dir.display()
            )
        })?;
    Ok(root.to_path_buf())
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  cargo xtask proto <lint|breaking|generate|check-rust|ci> [options]");
    eprintln!("  cargo xtask dev <fmt|lint|test|ci>");
    eprintln!("  cargo xtask bwrap <build|verify> [options]");
    eprintln!("  cargo xtask package <bundle|af-bootstrap> [options]");
}

fn print_proto_usage() {
    eprintln!("Usage:");
    eprintln!("  cargo xtask proto lint");
    eprintln!("  cargo xtask proto breaking [--against <source>]");
    eprintln!("  cargo xtask proto generate");
    eprintln!("  cargo xtask proto check-rust");
    eprintln!("  cargo xtask proto ci [--against <source>]");
}

fn print_dev_usage() {
    eprintln!("Usage:");
    eprintln!("  cargo xtask dev fmt");
    eprintln!("  cargo xtask dev lint");
    eprintln!("  cargo xtask dev test");
    eprintln!("  cargo xtask dev ci");
}

fn print_bwrap_usage() {
    eprintln!("Usage:");
    eprintln!(
        "  cargo xtask bwrap build [--target <label>] [--engine <podman|docker>] [--image <name>] [--no-cache]"
    );
    eprintln!("  cargo xtask bwrap verify [--target <label>]");
}

fn print_package_usage() {
    eprintln!("Usage:");
    eprintln!("  cargo xtask package bundle [options]");
    eprintln!("  cargo xtask package af-bootstrap [options]");
    eprintln!();
    print_package_bundle_usage();
    eprintln!();
    print_package_af_bootstrap_usage();
}

fn print_package_bundle_usage() {
    eprintln!("Options for `cargo xtask package bundle`:");
    eprintln!(
        "  (bundle entries: agent-fortd, bwrap, helper; af-bootstrap is distributed separately)"
    );
    eprintln!("  --target <label>         Bundle target label (default: current os-arch)");
    eprintln!("  --profile <debug|release> Cargo build profile (default: release)");
    eprintln!("  --version <version>      Manifest version string (default: dev-<unix_s>)");
    eprintln!("  --output-dir <path>      Output directory (default: assets/agent-fortd/<target>)");
    eprintln!(
        "  --bwrap-path <path>      bwrap binary path (default: assets/bwrap/<target>/bwrap)"
    );
    eprintln!(
        "  --helper-path <path>     helper binary path (default: target/<profile>/af-helper)"
    );
    eprintln!("  --bundle-name <name>     Bundle file name (default: bundle.tar.gz)");
    eprintln!("  --manifest-name <name>   Manifest file name (default: manifest.json)");
    eprintln!("  --skip-build             Skip cargo build and package existing binaries");
    eprintln!("  -h, --help");
}

fn print_package_af_bootstrap_usage() {
    eprintln!("Options for `cargo xtask package af-bootstrap`:");
    eprintln!("  (outputs: af-bootstrap[.exe], af-bootstrap[.exe].sha256)");
    eprintln!("  --target <label>         Output target label (default: current os-arch)");
    eprintln!("  --profile <debug|release> Cargo build profile (default: release)");
    eprintln!(
        "  --output-dir <path>      Output directory (default: assets/af-bootstrap/<target>)"
    );
    eprintln!(
        "  --af-bootstrap-path <path> af-bootstrap binary path (default: target/<profile>/af-bootstrap)"
    );
    eprintln!("  --skip-build             Skip cargo build and package existing binary");
    eprintln!("  -h, --help");
}

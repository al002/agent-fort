use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

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
        "codegen" => run_codegen(&args[1..]),
        "dev" => run_dev(&args[1..]),
        "bwrap" => run_bwrap(&args[1..]),
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
        "lint" => run_checked(
            Command::new("buf").arg("lint").current_dir(&root),
            "run `buf lint`",
        ),
        "generate" => run_checked(
            Command::new("buf").arg("generate").current_dir(&root),
            "run `buf generate`",
        ),
        "breaking" => {
            let against = parse_flag_value(&args[1..], "--against")
                .unwrap_or_else(|| ".git#branch=main".to_string());
            run_checked(
                Command::new("buf")
                    .arg("breaking")
                    .arg("--against")
                    .arg(&against)
                    .current_dir(&root),
                "run `buf breaking`",
            )
        }
        "all" => {
            run_checked(
                Command::new("buf").arg("lint").current_dir(&root),
                "run `buf lint`",
            )?;
            let against = parse_flag_value(&args[1..], "--against")
                .unwrap_or_else(|| ".git#branch=main".to_string());
            run_checked(
                Command::new("buf")
                    .arg("breaking")
                    .arg("--against")
                    .arg(&against)
                    .current_dir(&root),
                "run `buf breaking`",
            )?;
            run_checked(
                Command::new("buf").arg("generate").current_dir(&root),
                "run `buf generate`",
            )
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

fn run_codegen(args: &[String]) -> Result<()> {
    if args.is_empty() {
        print_codegen_usage();
        return Ok(());
    }

    let root = repo_root()?;
    match args[0].as_str() {
        "check-rust-proto" | "check" => run_checked(
            Command::new("cargo")
                .arg("test")
                .arg("-p")
                .arg("af-rpc-proto")
                .current_dir(&root),
            "run rust proto generation check (`cargo test -p af-rpc-proto`)",
        ),
        "help" | "--help" | "-h" => {
            print_codegen_usage();
            Ok(())
        }
        other => {
            print_codegen_usage();
            bail!("unknown `codegen` subcommand `{other}`")
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
        "fmt" => run_checked(
            Command::new("cargo")
                .arg("fmt")
                .arg("--all")
                .arg("--check")
                .current_dir(&root),
            "run format check (`cargo fmt --all --check`)",
        ),
        "lint" => run_checked(
            Command::new("cargo")
                .arg("clippy")
                .arg("--workspace")
                .arg("--all-targets")
                .arg("--")
                .arg("-D")
                .arg("warnings")
                .current_dir(&root),
            "run lint (`cargo clippy --workspace --all-targets -- -D warnings`)",
        ),
        "test" => run_checked(
            Command::new("cargo")
                .arg("test")
                .arg("--workspace")
                .current_dir(&root),
            "run workspace tests (`cargo test --workspace`)",
        ),
        "integration" => run_checked(
            Command::new("cargo")
                .arg("test")
                .arg("--workspace")
                .arg("--tests")
                .current_dir(&root),
            "run integration test orchestration (`cargo test --workspace --tests`)",
        ),
        "all" => {
            run_checked(
                Command::new("cargo")
                    .arg("fmt")
                    .arg("--all")
                    .arg("--check")
                    .current_dir(&root),
                "run format check (`cargo fmt --all --check`)",
            )?;
            run_checked(
                Command::new("cargo")
                    .arg("clippy")
                    .arg("--workspace")
                    .arg("--all-targets")
                    .arg("--")
                    .arg("-D")
                    .arg("warnings")
                    .current_dir(&root),
                "run lint (`cargo clippy --workspace --all-targets -- -D warnings`)",
            )?;
            run_checked(
                Command::new("cargo")
                    .arg("test")
                    .arg("--workspace")
                    .current_dir(&root),
                "run workspace tests (`cargo test --workspace`)",
            )?;
            run_checked(
                Command::new("cargo")
                    .arg("test")
                    .arg("--workspace")
                    .arg("--tests")
                    .current_dir(&root),
                "run integration test orchestration (`cargo test --workspace --tests`)",
            )
        }
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
    eprintln!("  cargo xtask proto <lint|breaking|generate|all> [options]");
    eprintln!("  cargo xtask codegen <check-rust-proto>");
    eprintln!("  cargo xtask dev <fmt|lint|test|integration|all>");
    eprintln!("  cargo xtask bwrap <build|verify> [options]");
}

fn print_proto_usage() {
    eprintln!("Usage:");
    eprintln!("  cargo xtask proto lint");
    eprintln!("  cargo xtask proto breaking [--against <source>]");
    eprintln!("  cargo xtask proto generate");
    eprintln!("  cargo xtask proto all [--against <source>]");
}

fn print_codegen_usage() {
    eprintln!("Usage:");
    eprintln!("  cargo xtask codegen check-rust-proto");
}

fn print_dev_usage() {
    eprintln!("Usage:");
    eprintln!("  cargo xtask dev fmt");
    eprintln!("  cargo xtask dev lint");
    eprintln!("  cargo xtask dev test");
    eprintln!("  cargo xtask dev integration");
    eprintln!("  cargo xtask dev all");
}

fn print_bwrap_usage() {
    eprintln!("Usage:");
    eprintln!(
        "  cargo xtask bwrap build [--target <label>] [--engine <podman|docker>] [--image <name>] [--no-cache]"
    );
    eprintln!("  cargo xtask bwrap verify [--target <label>]");
}

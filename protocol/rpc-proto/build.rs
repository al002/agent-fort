use std::{env, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let workspace_root = manifest_dir.join("../..");
    let proto_root = manifest_dir.join("../../proto");
    let proto_files = [
        proto_root.join("agent/fort/v1/common.proto"),
        proto_root.join("agent/fort/v1/daemon.proto"),
        proto_root.join("agent/fort/v1/session.proto"),
        proto_root.join("agent/fort/v1/task.proto"),
        proto_root.join("agent/fort/v1/approval.proto"),
        proto_root.join("agent/fort/v1/audit.proto"),
    ];

    for file in &proto_files {
        println!("cargo:rerun-if-changed={}", file.display());
    }
    println!(
        "cargo:rerun-if-changed={}",
        proto_root.join("buf.yaml").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("buf.gen.yaml").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("buf.work.yaml").display()
    );

    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    unsafe {
        env::set_var("PROTOC", protoc);
    }

    prost_build::Config::new().compile_protos(&proto_files, &[proto_root])?;
    Ok(())
}

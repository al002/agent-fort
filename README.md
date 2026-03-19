# Agent Fort

**English** | [中文](./README.zh-CN.md)

Agent Fort is a security runtime SDK for AI agents.
It turns high-risk agent operations into auditable decisions (`allow` / `deny` / `ask`), and executes approved tasks in isolated runtime backends.

The runtime backends are:
- sandbox
- container
- microvm

## Quick Start

```bash
cargo build -p af-bootstrap -p af-example-agent-tui
cargo xtask bwrap build
cargo xtask package bundle
cargo run -p af-example-agent-tui
```

Verify behavior in the TUI:
- input `echo hello` (expected direct execution)
- input `curl https://example.com` (expected approval first, then successful request after `yes`)
- high-risk operations such as system-admin/process-control actions should still require approval

If runtime binaries have changed, rebuild local package assets first:

```bash
cargo xtask package bundle
cargo build -p af-bootstrap
```

## Tech Stack

- Rust
- Protobuf (`prost`), managed by [Buf](https://buf.build/)
- Policy engine: static policy with session capability grants
- Execution isolation: Linux sandbox with `bwrap`, seccomp, and cgroups v2
- Storage: SQLite (`rusqlite`)
- SDK: Rust (implemented), Python/Node.js (planned)

## Security Model

- Operations are normalized and converted into requested capabilities before policy evaluation.
- Policy decisions follow capability checks (`allow` / `deny` / `ask`).
- Execution is delegated to an isolated backend (sandbox/container/microvm).
- Default sandbox behavior:
  - filesystem mode is `restricted`
  - network `disabled`
  - command exec timeout is `60s`
  - stdout/stderr capture caps are `1 MiB` each.
  - cgroup governance defaults to `best_effort` (set `AF_RESOURCE_GOVERNANCE_MODE=required` for strict enforcement).

## Usage

```rust
use af_sdk::{AgentFortClient, BootstrapConfig, SdkConfig, exec_operation};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SdkConfig::new(
        "demo-agent",
        Some(BootstrapConfig {
            bootstrap_binary_url: Some("./target/debug/af-bootstrap".into()),
            bundle_manifest: Some("./assets/agent-fortd/linux-x86_64/manifest.json".into()),
            ..Default::default(),
        }),
    );

    AgentFortClient::initialize(config.clone()).await?;
    let mut client = AgentFortClient::connect(config).await?;
    client.ping().await?;

    let session = {
        let mut sessions = client.sessions().await?;
        sessions.create_session().await?
    };
    let lease = session.lease.expect("session lease is required");

    let result = {
        let mut tasks = client.tasks().await?;
        tasks
            .create(
                session.session_id.clone(),
                lease.rebind_token.clone(),
                exec_operation("echo hello"),
                Some("demo task".to_string()),
            )
            .await?
    };

    println!("{result:?}");
    Ok(())
}
```

## Project Layout

```text
.
├── apps      # executable programs (daemon, bootstrap, helper)
├── assets    # runtime bundles, manifests, and packaged binaries
├── core      # application services and orchestration logic
├── docs      # architecture and design specifications
├── domain    # domain models, invariants, and repository interfaces
├── examples  # end-to-end and developer-oriented sample applications
├── infra     # infrastructure implementations (policy, sandbox, store, audit sink)
├── proto     # protobuf API definitions
├── protocol  # transport and protobuf codec crates
├── sdk       # SDK implementations (current: Rust; planned: Python/Node)
├── tools     # engineering automation (`xtask`)
└── vendor    # third-party vendored source dependencies
```

## Policy Example

Create `policies/static_policy.yaml`:

```yaml
version: 1
revision: 1
default_action: deny
capabilities:
  fs_read: ["/home/**", "/tmp/**", "/etc/ssl/**"]
  fs_write: ["/home/**", "/tmp/**"]
  fs_delete: ["/home/**", "/tmp/**"]
  net_connect:
    - host: "example.com"
      port: 443
      protocol: "https"
  allow_host_exec: false
  allow_process_control: false
  allow_privilege: false
  allow_credential_access: false
backends:
  backend_order: ["sandbox"]
  capability_matrix:
    sandbox:
      fs_read: ["/home/**", "/tmp/**", "/etc/ssl/**"]
      fs_write: ["/home/**", "/tmp/**"]
      fs_delete: ["/home/**", "/tmp/**"]
      net_connect:
        - host: "example.com"
          port: 443
          protocol: "https"
      allow_host_exec: false
      allow_process_control: false
      allow_privilege: false
      allow_credential_access: false
  profiles:
    sandbox:
      type: sandbox
      profile_id: "sandbox-default"
      network_default: "deny"
      writable_roots: ["/home/**", "/tmp/**"]
      readonly_roots: ["/etc/ssl/**"]
      syscall_policy: "baseline"
      limits: { cpu_ms: 120000, memory_mb: 1024, pids: 128, disk_mb: 1024, timeout_ms: 60000 }
```

Valid task operation kinds are: `exec`, `fs.read`, `fs.write`, `net`, `tool`.

## Testing

```bash
cargo xtask dev all
cargo xtask dev test
cargo xtask dev integration
cargo xtask proto all
```

## Development Workflow

```bash
git clone --recurse-submodules <repo-url>
```

- If the repo is already cloned, pull submodules with:

```bash
git submodule update --init --recursive
```

- Install Buf for proto workflow: <https://buf.build/>

```bash
# Homebrew
brew install bufbuild/buf/buf
# Go toolchain
go install github.com/bufbuild/buf/cmd/buf@latest
```

- If protobuf schema changes:

```bash
cargo xtask proto all
cargo xtask codegen check-rust-proto
```

- Implement by layers: `domain` -> `core` -> `infra` -> `apps/sdk`.
- Run quality gates before submission:

```bash
cargo xtask dev all
```

- Use `af-example-agent-tui` for end-to-end smoke validation.
- If runtime binaries change, rebuild local package assets:

```bash
cargo xtask package bundle --profile debug
cargo xtask package af-bootstrap --profile debug
```

## Project Status

Completed:
- [x] Rust SDK (`af-sdk`)
- [x] Local daemon lifecycle bootstrap (`af-bootstrap`)
- [x] Capability-first static policy loading + hot reload
- [x] Approval workflow for human-in-the-loop decisions
- [x] Sandboxed command execution on Linux-first runtime path
- [x] End-to-end sample app (`af-example-agent-tui`)

Planned:
- [ ] Python SDK
- [ ] Node.js SDK
- [ ] Container execution backend
- [ ] MicroVM execution backend
- [ ] Cross platform support (Linux/Windows/macOS)

# Agent Fort

**English** | [中文](./README.zh-CN.md)

Agent Fort is a security runtime SDK for AI agents.
It turns high-risk agent operations into auditable decisions (`allow` / `deny` / `ask`), and executes approved tasks in isolated runtime backends.

The runtime backends are:
- sandbox
- container
- microvm

## Quick Start

Install [buf](https://buf.build/) 

```bash
# Homebrew
brew install bufbuild/buf/buf
# Go toolchain
go install github.com/bufbuild/buf/cmd/buf@latest
```

```bash
cargo xtask proto generate
cargo xtask package af-bootstrap
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
cargo xtask package af-bootstrap
cargo xtask package bundle
```

## Tech Stack

- Rust
- Protobuf (`prost`), managed by [buf](https://buf.build/)
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
  - cgroup governance defaults to `best_effort`.

## Usage

```rust
use af_sdk::{AgentFortClient, BootstrapConfig, SdkConfig, parse_action_json};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SdkConfig::new(
        "demo-agent",
        Some(BootstrapConfig {
            bootstrap_binary_url: Some("./target/debug/af-bootstrap".into()),
            bundle_manifest: Some("./assets/agent-fortd/linux-x86_64/manifest.json".into()),
            command_rules_dir: Some("./examples/agent-tui/command-rules".into()),
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

    let action_json = json!({
        "schema": "af.action.v1",
        "request_id": "demo-req-1",
        "session": {
            "mode": "create"
        },
        "task": {
            "goal": "demo task",
            "operation": {
                "kind": "exec",
                "payload": {
                    "command": "echo hello"
                },
                "options": {
                    "cwd": ".",
                    "env": {},
                    "stdin": "",
                    "shell": "/bin/sh"
                }
            }
        }
    })
    .to_string();
    let action = parse_action_json(&action_json)?;

    let result = {
        let mut tasks = client.tasks().await?;
        tasks
            .create(
                session.session_id.clone(),
                lease.rebind_token.clone(),
                action.operation,
                action.goal,
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

`policy` defines the system safety limits.

- default policy directory:
  - Linux: `~/.config/agent-fort/policies`
  - Windows: `%APPDATA%\\AgentFort\\policies`
- policy is required: runtime startup fails when `static_policy.yaml` / `static_policy.yml` is missing.

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
  capability_limits:
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

## Command Rules

Policy runtime supports command-rule files in Starlark syntax and hot reload.

`command rule` maps command patterns into capability, augmenting built-in `capability/extractor`.

- default rules directory:
  - Linux: `~/.config/agent-fort/command-rules`
  - Windows: `%APPDATA%\\AgentFort\\command-rules`

Example `command-rules/00-base.rules`:

```python
command_rule(
    pattern = ["curl"],
    capabilities = cap(
        net_connect = [net(host = url_host_from_arg(0), port = 443, protocol = "https")],
    ),
    reason = "curl connects to url host",
    match = ["curl https://example.com"],
)

command_rule(
    pattern = ["curl"],
    when = has_any(["-o", "--output"]),
    capabilities = cap(
        fs_write = [resolve_path(arg_after_any(["-o", "--output"]))],
    ),
    reason = "curl output writes destination file",
    match = ["curl https://example.com -o result.json"],
)
```

## Testing

```bash
cargo xtask dev test
cargo xtask dev ci
cargo xtask proto ci
```

## Development Workflow

```bash
git clone --recurse-submodules <repo-url>
```

- If the repo is already cloned, pull submodules with:

```bash
git submodule update --init --recursive
```

- Install [buf](https://buf.build/) 

```bash
# Homebrew
brew install bufbuild/buf/buf
# Go toolchain
go install github.com/bufbuild/buf/cmd/buf@latest
```

- proto generate and build dependencies

```bash
cargo xtask proto generate
cargo xtask bwrap build
cargo xtask package af-bootstrap
```

- If protobuf schema changes:

```bash
cargo xtask proto ci
```

- Run quality check before submission:

```bash
cargo xtask dev ci
```

- Use `af-example-agent-tui` for end-to-end smoke validation.
- If runtime binaries change, rebuild local package assets:

```bash
cargo xtask package af-bootstrap
cargo xtask package bundle
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

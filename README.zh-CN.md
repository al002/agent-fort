# Agent Fort

**中文** | [English](./README.md)

Agent Fort 是给 AI Agent 使用的 security runtime SDK。
它将高风险操作转换为可审计的决策（`allow` / `deny` / `ask`），并在审批通过后交由隔离执行后端完成执行。

运行时后端包括：
- sandbox
- microvm

## 快速开始

安装 [buf](https://buf.build/) 

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

在 TUI 中验证行为：
- 输入 `echo hello`，应直接执行
- 输入 `curl https://example.com`，应先进入审批，回复 `yes` 后请求成功
- 涉及系统管理、进程控制等高风险操作时，仍应进入审批流程

如果运行时二进制有变更，请先更新本地打包产物：

```bash
cargo xtask package af-bootstrap
cargo xtask package bundle
```

## 技术栈

- Rust
- Protobuf（`prost`），由 [buf](https://buf.build/) 管理
- 策略引擎：static policy 和会话级的动态 capability 权限
- 执行隔离：基于 `bwrap`、seccomp、cgroups v2 的 Linux sandbox
- 存储：SQLite（`rusqlite`）
- SDK：Rust（已实现），Python/Node.js（规划中）

## 安全模型

- 请求会先被统一化并提取为 capabilities，再进入策略求值。
- 策略结果由 capability 决定（`allow` / `deny` / `ask`）。
- 实际执行由隔离后端承载（sandbox/microvm）。
- Sandbox 默认行为：
  - 文件系统为 `restricted`（启用平台默认挂载并挂载 `/proc`），挂载当前目录为可读写；
  - 网络禁用
  - 命令超时默认 `60s`
  - stdout/stderr 捕获上限各 `1 MiB`。
  - cgroup 资源治理默认 `best_effort`。

## 使用

以下是完整的 SDK 内置 bootstrap 流程（与 `af-example-agent-tui` 一致）：

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


## 目录结构

```text
.
├── apps      # 可执行程序（daemon、bootstrap、helper）
├── assets    # 运行时 bundle、manifest 与打包产物
├── core      # 应用服务与业务编排逻辑
├── docs      # 架构与设计规范文档
├── domain    # 领域模型、约束与仓储接口
├── examples  # 端到端与开发者示例程序
├── infra     # 基础设施实现（policy、sandbox、store、audit sink）
├── proto     # Protobuf API 定义
├── protocol  # 传输层与 protobuf 编解码 crate
├── sdk       # SDK 实现（当前 Rust，规划 Python/Node）
├── tools     # 工程自动化工具（`xtask`）
└── vendor    # 第三方 vendored 依赖源码
```

## Policy 配置示例

`policy`（`static_policy.yaml`）定义基本的安全限制。

- 默认 policy 目录：
  - Linux：`~/.config/agent-fort/policies`
  - Windows：`%APPDATA%\\AgentFort\\policies`
- policy 是必需项：缺少 `static_policy.yaml` / `static_policy.yml` 时运行时启动会失败。

创建 `policies/static_policy.yaml`：

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

Task operation kind 仅支持：`exec`、`fs.read`、`fs.write`、`net`、`tool`。

## Command Rule 规则

Policy runtime 支持 Starlark 语法的命令规则文件，并支持热更新。

`command rule` 用于把命令映射成 capability，补充内置的 `capability/extractor`。

- 默认规则目录：
  - Linux：`~/.config/agent-fort/command-rules`
  - Windows：`%APPDATA%\\AgentFort\\command-rules`

示例 `command-rules/00-base.rules`：

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

## 测试

```bash
cargo xtask dev test
cargo xtask dev ci
cargo xtask proto ci
```

## 开发流程

```bash
git clone --recurse-submodules <repo-url>
```

- 若仓库已克隆，再拉 submodule：

```bash
git submodule update --init --recursive
```

- 安装 [buf](https://buf.build/)

```bash
# Homebrew
brew install bufbuild/buf/buf
# Go toolchain
go install github.com/bufbuild/buf/cmd/buf@latest
```

- 生成 proto 和构建依赖：

```bash
cargo xtask proto generate
cargo xtask bwrap build
cargo xtask package af-bootstrap
```

- 若 protobuf 发生变更：

```bash
cargo xtask proto ci
```

- 提交前执行检查：

```bash
cargo xtask dev ci
```

- 使用 `af-example-agent-tui` 进行端到端冒烟验证。
- 若运行时二进制发生变更，更新本地打包产物：

```bash
cargo xtask package af-bootstrap
cargo xtask package bundle
```

## 项目状态

已完成:
- [x] Rust SDK（`af-sdk`）
- [x] 本地 daemon 启动与资产准备（`af-bootstrap`）
- [x] capability-first 静态策略加载（`static_policy.yaml`）+ 热更新
- [x] 人工审批闭环（approval workflow）
- [x] Linux 优先路径下的 sandbox 命令执行
- [x] 端到端示例应用（`af-example-agent-tui`）

开发中:
- [ ] Python SDK
- [ ] Node.js SDK
- [ ] MicroVM runtime
- [ ] 跨平台支持（Linux/Windows/macOS）

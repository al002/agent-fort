# Agent Fort

**中文** | [English](./README.md)

Agent Fort 是给 AI Agent 使用的 security runtime SDK。
它将高风险操作转换为可审计的决策（`allow` / `deny` / `ask`），并在审批通过后交由隔离执行后端完成执行。

运行时后端包括：
- sandbox
- container
- microvm

## 快速开始

```bash
cargo build -p af-bootstrap -p af-example-agent-tui
cargo run -p af-example-agent-tui
```

在 TUI 中验证行为：
- 输入 `echo hello`，应直接执行
- 输入 `curl https://example.com`，应先进入审批，回复 `yes` 后请求成功
- 涉及系统管理、进程控制等高风险操作时，仍应进入审批流程

如果运行时二进制有变更，请先更新本地打包产物：

```bash
cargo xtask package bundle --profile debug
cargo xtask package af-bootstrap --profile debug
```

## 技术栈

- Rust
- Protobuf（`prost`），由 [Buf](https://buf.build/) 管理
- 策略引擎：YAML 策略文件 + [cel](https://cel.dev/)
- 执行隔离：基于 `bwrap`、seccomp、cgroups v2 的 Linux sandbox
- 存储：SQLite（`rusqlite`）
- SDK：Rust（已实现），Python/Node.js（规划中）

## 安全模型

- 请求会先被统一化为结构化数据，再进入策略求值。
- 策略结果决定允许、拒绝或进入审批流程。
- 实际执行由隔离后端承载（sandbox/container/microvm）。
- Sandbox 默认行为：
  - 文件系统为 `restricted`（启用平台默认挂载并挂载 `/proc`），挂载当前目录为可读写；
  - 网络禁用
  - 命令超时默认 `60s`
  - stdout/stderr 捕获上限各 `1 MiB`。

## 使用

以下是完整的 SDK 内置 bootstrap 流程（与 `af-example-agent-tui` 一致）：

```rust
use std::collections::{BTreeMap, HashMap};

use af_sdk::{AgentFortClient, BootstrapConfig, SdkConfig, TaskOperation};
use prost_types::{value::Kind as ProstValueKind, Struct as ProstStruct, Value as ProstValue};

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

    // TaskOperation 可让 AI 生成，再提交至运行时。
    let mut payload = BTreeMap::new();
    payload.insert(
        "command".to_string(),
        ProstValue {
            kind: Some(ProstValueKind::StringValue("echo hello".to_string())),
        },
    );
    let operation = TaskOperation {
        kind: "exec".to_string(),
        payload: Some(ProstStruct { fields: payload }),
        options: None,
        labels: HashMap::new(),
    };

    let result = {
        let mut tasks = client.tasks().await?;
        tasks
            .create(
                session.session_id.clone(),
                lease.rebind_token.clone(),
                operation,
                Some("demo task".to_string()),
                // 保持网络可用，并挂载 /etc 与 /mnt 以提供 DNS 相关配置文件。
                Some(r#"{"sandbox":{"network":"full","mounts":[{"source":"/etc","target":"/etc","read_only":true},{"source":"/mnt","target":"/mnt","read_only":true}]}}"#.to_string()),
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

创建 `policies/default.yaml`：

```yaml
version: 1
rules:
  - id: deny-system-file-write
    kind: deny
    priority: 1000
    enabled: true
    match:
      operation_kinds: ["exec"]
    when: "facts.system_file_write == true"
    effect:
      decision: deny
      reason: system file writes are denied
      runtime_backend: sandbox
      requirements: []

  - id: ask-network-access
    kind: approval
    priority: 900
    enabled: true
    match:
      operation_kinds: ["exec"]
    when: "facts.network_access == true"
    effect:
      decision: ask
      reason: network access requires approval
      runtime_backend: sandbox
      requirements: []
      approval:
        summary: network access requires approval
        details: reply yes/no in the agent-tui to continue
        items:
          - kind: network
            summary: outbound network access

  - id: allow-default-exec
    kind: allow
    priority: 100
    enabled: true
    match:
      operation_kinds: ["exec"]
    when: "true"
    effect:
      decision: allow
      reason: allow default command execution
      runtime_backend: sandbox
      requirements: []
```

## 测试

```bash
cargo xtask dev all
cargo xtask dev test
cargo xtask dev integration
cargo xtask proto all
```

## 开发流程

```bash
git clone --recurse-submodules <repo-url>
```

- 若仓库已克隆，再补拉 submodule：

```bash
git submodule update --init --recursive
```

- Proto 工作流依赖 Buf：<https://buf.build/>

```bash
# Homebrew
brew install bufbuild/buf/buf
# Go toolchain
go install github.com/bufbuild/buf/cmd/buf@latest
```

- 若 protobuf 发生变更：

```bash
cargo xtask proto all
cargo xtask codegen check-rust-proto
```

- 按分层推进实现：`domain` -> `core` -> `infra` -> `apps/sdk`。
- 提交前执行统一质量检查：

```bash
cargo xtask dev all
```

- 使用 `af-example-agent-tui` 进行端到端冒烟验证。
- 若运行时二进制发生变更，更新本地打包产物：

```bash
cargo xtask package bundle --profile debug
cargo xtask package af-bootstrap --profile debug
```

## 项目状态

已完成:
- [x] Rust SDK（`af-sdk`）
- [x] 本地 daemon 启动与资产准备（`af-bootstrap`）
- [x] 基于目录的策略加载（`YAML`）+ CEL 求值 + 热更新
- [x] 人工审批闭环（approval workflow）
- [x] Linux 优先路径下的 sandbox 命令执行
- [x] 端到端示例应用（`af-example-agent-tui`）

开发中:
- [ ] Python SDK
- [ ] Node.js SDK
- [ ] Container runtime
- [ ] MicroVM runtime
- [ ] 跨平台支持（Linux/Windows/macOS）

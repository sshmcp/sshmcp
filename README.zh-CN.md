# SSHMCP

为 AI 智能体提供安全的远程访问。

赋予智能体能力，而不是 SSH 凭据。


<p align="center">
  <a href="README.md">English</a>
</p>

<p align="center">
  <img src="docs/readme/hero.svg" alt="SSHMCP for Agents" width="100%">
</p>

<p align="center">
  <a href="https://github.com/sshmcp/sshmcp/releases">
    <img src="https://img.shields.io/github/v/release/sshmcp/sshmcp?display_name=tag&sort=semver" alt="Latest release">
  </a>
  <a href="https://github.com/sshmcp/sshmcp/actions/workflows/release.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/sshmcp/sshmcp/release.yml?label=release" alt="Release workflow">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-Apache%202.0-0f766e.svg" alt="Apache 2.0 license">
  </a>
  <img src="https://img.shields.io/badge/platforms-Windows%20x64%20%7C%20Linux%20x64-0f172a.svg" alt="Supported platforms">
</p>

`sshmcp` 是一个面向 Agent 的远程主机网关。它为 Codex、ChatGPT、Claude Code、Cursor 和自研 Agent 提供可复用的 embedded SSH session、profile 密钥隔离、跳板路由和策略控制。

它刻意**不是**通用 SSH 客户端替代品；项目的重点是 agent 工作流、profile 驱动的安全边界，以及可重复的远程操作接口。

## 工作方式

```text
ChatGPT · Claude · Codex · Cursor · OpenCode · 自定义智能体
                         | MCP
                         v
                      SSHMCP
         身份 · 策略 · 人工审批 · 审计 · 会话管理
                         | SSH
                         v
                       服务器
```

智能体先映射为已认证的 Principal，再由策略作出 Allow、Confirm 或 Deny 决策。需要确认的请求必须经人工审批，允许的 SSH 操作会被审计。这不是 `LLM -> unrestricted ssh command`。本仓库是开源 Core 和自托管实现；SSHMCP Cloud 是未来单独提供的托管产品。

## 为什么需要 sshmcp

- 智能体如果频繁起一次性 `ssh` / `scp`，很容易把连接打碎，最终遇到节流、拒绝连接或登录失败。
- 带跳板机、多跳认证、委托登录这类链路，用 prompt 临时描述既脆弱又不安全。
- 密码和私钥应该留在 gateway 自己的配置和 daemon 边界里，而不是出现在 agent 可见的命令行或对话历史中。

## 特性

- **在 gateway API 边界做 secret isolation**：daemon 从配置文件读取密码、密钥路径和可选的私钥口令；调用方只传 `profile` 和操作参数。
- **脱敏的 profile / session 输出**：`profile show`、`session inspect`、错误结果都不会回显原始密码或口令。
- **面向 agent 的 profile-first 工作流**：agent 用 profile 名称工作，而不是拼带密码的 `ssh` 命令。
- **受控的 profile 管理**：MCP 可查询策略；显式开启后可请求新增或删除 profile。自托管模式使用 MCP 客户端确认；Cloud 运行模式需要 Human CLI 审批。
- **嵌入式 SSH + 会话复用**：direct / bastion 模式不依赖本地反复起 `ssh.exe` 或 `scp`。
- **direct / bastion 模式下本地不依赖 OpenSSH**：Windows 和 Linux 的直连传输都走内置 SSH 客户端栈。
- **逐跳认证**：target 和每个 bastion 都可以各自配置 password 或 key。
- **`via_profile` 委托模式**：当最终目标只能从上游主机访问时，复用上游主机已有的远端 SSH 能力。
- **托管远端 agent 生命周期**：连接时自动做版本检查、安装和复用。
- **JSON-only CLI**：统一覆盖 `daemon`、`profile`、`exec`、`read`、`write`、`upload`、`download`、`tunnel`、`session`。
- **两类 Agent 接口**：本地 Agent 使用 CLI + Skill，远程 Agent 使用支持静态 Bearer 或 OAuth JWT 认证的 Streamable HTTP MCP。
- **MCP OAuth 多租户隔离**：可接入外部 OIDC/JWT 提供方，并按 audience/resource 路由到不同的 profile 文件、本地文件根、审批存储和 session 命名空间。
- **Agent Policy**：`--agent` CLI 和所有 MCP 调用统一执行 capability、精确命令白名单和远端真实路径限制，旧版 Human CLI 默认行为不变。

Codex 本地接入见 [docs/codex.md](docs/codex.md)，ChatGPT MCP 与 NAS 部署见 [docs/chatgpt.md](docs/chatgpt.md)。

## 安全模型

### 运行模式与主机密钥

默认的 `self_hosted` 模式兼容现有 YAML。默认的 `runtime.host_key_mode: insecure_compatibility` 会接受未固定的 SSH 主机密钥，这种方式无法防止服务器冒充。建议设置 `runtime.host_key_mode: strict`，并在目标与每个 bastion 的配置中填写经独立渠道核实的 `host_key_sha256: "SHA256:..."`。即使处于兼容模式，已配置的指纹也会被强制检查。

`runtime.mode: cloud` 是面向未来托管环境的核心安全模式，并非现成的云服务。它强制使用严格主机密钥校验，禁止 SSH tunnel，拒绝不安全的目标地址；经 bastion 转发的后续跳点须使用 IP 字面量，`via_profile` 暂不支持。参见[架构](docs/architecture.md)和[安全模型](docs/security-model.md)。

MCP 与 CLI 调用会映射为 `Principal`。OAuth JWT 的 `sub` 标识调用者，`mcp.tenants[].tenant_id` 可单独标识租户；会话和授权记录使用由身份派生的内部命名空间。审计通过可替换的 sink 记录脱敏事件。

<p align="center">
  <img src="docs/readme/security.svg" alt="Security boundary for profile-driven secrets and redacted outputs" width="100%">
</p>

### 已经隔离的部分

- 密码、私钥路径和可选的私钥口令保存在 `profiles.yaml`、`profiles.yml` 或兼容的 `profiles.toml` 中，由本地 gateway daemon 读取和使用。
- CLI / RPC 请求只携带 `profile` 名称和操作参数，不携带裸密码、口令或私钥内容。
- `profile show`、`session inspect` 和错误结果会在返回 JSON 之前做脱敏。

### 不是在承诺什么

- 这**不是**对“同一 OS 用户下其他恶意本地进程”的强隔离承诺。
- 这**不是**对操作系统权限、secret manager、主机加固或 bastion 策略的替代。
- `via_profile` 委托模式仍然依赖上游主机自身可用的 SSH 能力来打到最终 target。

### 运维建议

- 真正的配置文件放在仓库之外。
- 只给预期的本地用户或服务账号配置文件读取权限。
- 不要把线上 profile、密码或私钥提交到仓库。

## 快速开始

<p align="center">
  <img src="docs/readme/architecture.svg" alt="Agent to daemon to embedded SSH to bastion and target flow" width="100%">
</p>

1. 从 [GitHub Releases](https://github.com/sshmcp/sshmcp/releases) 下载二进制，并把 `sshmcp` 放进 `PATH`。
2. 准备 profile 配置。推荐 YAML，起点是 [examples/profiles.yaml](examples/profiles.yaml)。
3. 首次使用前先校验 profile。
4. 显式或隐式启动 daemon，然后通过 `profile` 执行远端操作。

PowerShell：

```powershell
$env:SSHMCP_CONFIG_PATH = (Resolve-Path .\examples\profiles.yaml)
sshmcp profile validate
sshmcp daemon start
sshmcp exec --profile direct-with-bastion -- hostname
sshmcp session list
sshmcp daemon stop
```

Bash：

```bash
export SSHMCP_CONFIG_PATH="$PWD/examples/profiles.yaml"
sshmcp profile validate
sshmcp daemon start
sshmcp exec --profile direct-with-bastion -- hostname
sshmcp session list
sshmcp daemon stop
```

配置优先读取 `SSHMCP_CONFIG_PATH`，然后兼容旧变量 `SSH_GATEWAY_CONFIG_PATH`、`ARRT_CONFIG_PATH`。未指定路径时，先在新 SSHMCP 目录中查找 `profiles.yaml`、`profiles.yml`、`profiles.toml`，再查找旧目录。Linux 新目录是 `$XDG_CONFIG_HOME/sshmcp`（通常为 `~/.config/sshmcp`），Windows 为 `%APPDATA%\sshmcp\config`。旧数据目录仍可回退使用，文件不会被自动迁移。详见[迁移指南](docs/migration-from-ssh-gateway.md)。

## 配置示例

仓库中的公开示例放在 [examples/profiles.yaml](examples/profiles.yaml)。

### 带 bastion 的 direct SSH

```yaml
profiles:
  - name: direct-with-bastion
    target:
      host: target.internal
      user: root
      port: 22
      auth:
        type: password
        password: target-password
    bastions:
      - host: bastion.example.com
        user: root
        port: 22
        auth:
          type: key
          key_path: ~/.ssh/id_ed25519

### 带口令的私钥

```yaml
profiles:
  - name: encrypted-key-target
    target:
      host: secure.internal
      user: ops
      port: 22
      auth:
        type: key
        key_path: ~/.ssh/id_rsa_2048
        passphrase: local-key-passphrase
```

这个口令只会被本地 gateway daemon 用来解密私钥，不会通过 `profile show`、`session inspect` 或普通 CLI 错误结果返回给调用方。
```

### 委托模式 `via_profile`

```yaml
profiles:
  - name: upstream-bastion
    target:
      host: bastion.example.com
      user: root
      port: 22
      auth:
        type: key
        key_path: ~/.ssh/id_ed25519

  - name: delegated-target
    via_profile: upstream-bastion
    target:
      host: target.internal
      user: root
      port: 22
```

如果上游主机已经知道如何执行 `ssh target.internal ...`，而本地机器又不应该额外持有 target 的凭据，就适合用委托模式。这个模式下：

- delegated profile 不能再定义 `auth`
- delegated profile 不能再定义 `bastions`
- 支持 `exec`、`read`、`write`、`upload`、`download`
- `tunnel open` 会被拒绝

### 兼容旧版 TOML

旧版 TOML 仍然支持：

```toml
[[profiles]]
name = "legacy"

[profiles.target]
host = "target.internal"
user = "root"

[profiles.auth]
key_path = "~/.ssh/id_ed25519"
passphrase = "local-key-passphrase"
```

## 命令

业务命令输出 JSON；标准 `--help` 和 `--version` 输出纯文本。

| 范围 | 命令 |
| --- | --- |
| `daemon` | `daemon start`、`daemon status`、`daemon stop` |
| `profile` | `profile list`、`profile show <name>`、`profile validate [name]` |
| 远端操作 | `exec`、`read`、`write`、`upload`、`download` |
| `tunnel` | `tunnel open --profile <name> --local <port> --remote <host:port>`、`tunnel close --id <tunnel-id>` |
| `session` | `session list`、`session inspect --id <session-id>`、`session close --id <session-id>` |

常见示例：

```text
sshmcp exec --profile delegated-target -- hostname
sshmcp read --profile delegated-target --path /etc/hostname
sshmcp write --profile delegated-target --path /tmp/demo.txt --input hello
sshmcp upload --profile delegated-target --src ./local.txt --dst /tmp/local.txt
sshmcp download --profile delegated-target --src /tmp/local.txt --dst ./local-copy.txt
sshmcp tunnel open --profile direct-with-bastion --local 8080 --remote 127.0.0.1:11434
```

## MCP OAuth 与多配置隔离

MCP server 保留原有静态 Bearer 模式，同时支持 `oauth_jwt`，用于对接官方 OAuth 风格的 MCP 客户端。OAuth 模式下，`sshmcp` 作为 resource server 工作：外部 OIDC 提供方负责登录和签发 token，gateway 负责校验 JWT 签名、issuer、过期时间、audience/resource 和必需 scope。

```yaml
mcp:
  listen: 127.0.0.1:8765
  auth:
    type: oauth_jwt
    resource: https://gateway.example.com
    issuer: https://idp.example.com
    jwks_url: https://idp.example.com/.well-known/jwks.json
    scopes: [sshmcp]
  tenants:
    - resource: https://gateway.example.com
      config_path: tenants/main/profiles.yaml
      local_file_root: /srv/sshmcp/main/files
      profile_management:
        enabled: false
```

每个 tenant 指向自己的 `profiles.yaml`。认证后的 token audience 会选择 tenant，匹配到的 tenant 决定可见 profiles、Agent Policy、profile 管理、审批、grants、本地文件传输根目录和可复用 SSH session。部署细节见 [ChatGPT MCP setup](docs/chatgpt.md)。

本地相对路径以调用 CLI 时的当前工作目录为基准。该规则适用于 `upload --src` 和 `download --dst`；daemon 会在 RPC 边界拒绝相对本地路径，不会按自身工作目录解析。相对本地路径中的 `.` 和 `..` 会在发送请求前规范化；Windows 盘符绝对路径和 UNC 路径保持不变。

上传会创建远端父目录并覆盖已有远端目标；下载会创建本地父目录，完整接收并同步内容后再原子替换已有本地目标。传输 JSON 会返回实际路径对：上传为 `local_src`/`remote_dst`，下载为 `remote_src`/`local_dst`；下载还会返回 `overwritten`。

在 MSYS2 下执行传输命令时应设置 `MSYS2_ARG_CONV_EXCL="*"`，避免 MSYS2 在 `sshmcp` 接收参数前错误转换远端 POSIX 路径：

```bash
MSYS2_ARG_CONV_EXCL="*" sshmcp download --profile delegated-target --src /tmp/local.txt --dst ./local-copy.txt
```

`daemon stop` 在成功通知一个正在运行的 daemon 时返回 `{"status":"stopping"}`；如果当前没有 daemon 在监听，则返回 `{"status":"not_running"}`。

## 从 Release 安装

每次推送 `v*` tag 都会自动发布 release 产物。

- Windows x64：`sshmcp-<version>-x86_64-pc-windows-msvc.zip`
- Linux x64：`sshmcp-<version>-x86_64-unknown-linux-gnu.tar.gz`
- 校验和：`SHA256SUMS`

典型安装步骤：

1. 从 [Releases](https://github.com/sshmcp/sshmcp/releases) 下载适合自己平台的压缩包。
2. 解压出 `sshmcp` 或 `sshmcp.exe`。
3. 把二进制放进 `PATH`。
4. 基于 [examples/profiles.yaml](examples/profiles.yaml) 准备配置文件。

仓库内置的 Windows skill 安装脚本默认把二进制放到 `%LOCALAPPDATA%\sshmcp\bin\sshmcp.exe`。`skills/sshmcp/scripts/install.ps1` 现在还会默认把这个目录写入用户级 `PATH`，这样新开的 shell 可以直接解析 `sshmcp`。

## 作为 Skill 安装给智能体

仓库内置了一个可移植的 `SKILL.md` 风格 skill，目录在 [skills/sshmcp](skills/sshmcp)。它面向支持开放 skills 生态的智能体，职责不是替代 CLI，而是指导 agent 优先走 profile 驱动的 `sshmcp` 命令，而不是回退到原始 `ssh`。

这个 skill 还支持在首次使用时自动自举 `sshmcp` 二进制：如果本地没有 CLI，可以按当前平台从 GitHub Releases 下载最新版本。agent 侧应优先尝试 `PATH` 中的 `sshmcp`，其次尝试安装脚本的默认落盘路径，最后才重新下载安装。

### 开放 skills 生态安装

如果目标 agent 支持 [`npx skills add`](https://github.com/vercel-labs/skills)，更推荐直接指向 skill 目录对应的 GitHub 路径安装。这样可以避开部分 agent 或 CLI 版本在“从仓库根发现嵌套 skill”时的不稳定行为：

```bash
npx skills add https://github.com/sshmcp/sshmcp/tree/main/skills/sshmcp -g
```

如果 CLI 对嵌套 skill 的发现正常，仓库简写也可以用：

```bash
npx skills add sshmcp/sshmcp --skill sshmcp -g
```

常见 agent 示例：

```bash
npx skills add https://github.com/sshmcp/sshmcp/tree/main/skills/sshmcp -a codex -g
npx skills add https://github.com/sshmcp/sshmcp/tree/main/skills/sshmcp -a claude-code -g
npx skills add https://github.com/sshmcp/sshmcp/tree/main/skills/sshmcp -a cursor -g
```

如果你想先确认 CLI 实际看到了哪些 skill：

```bash
npx skills add sshmcp/sshmcp --list
```

如果这份 skill 最初就是通过 `npx skills add` 安装的，后续更新可以直接走：

```bash
npx skills update sshmcp -g
```

`npx skills update` 不会接管通过 Codex 原生 `install-skill-from-github.py` 装出来的副本。如果你之前是那条路径安装的，又想以后走标准的 `skills` CLI 更新流程，做法是先删掉旧副本，再改用 `npx skills add` 重新安装。

安装并不依赖某个强制的统一中心仓库。这个 GitHub 仓库本身就可以直接作为分发源；[skills.sh](https://skills.sh/docs) 更像发现入口和公开排行榜，而不是必须先注册才能安装的中心仓库。

### Codex 原生安装方式

如果你更想走 Codex 自带的 skill 安装器，也可以直接从 GitHub 安装：

Windows PowerShell：

```powershell
py -3 "$env:USERPROFILE\.codex\skills\.system\skill-installer\scripts\install-skill-from-github.py" `
  --repo sshmcp/sshmcp `
  --path skills/sshmcp
```

Linux / macOS shell：

```bash
python ~/.codex/skills/.system/skill-installer/scripts/install-skill-from-github.py \
  --repo sshmcp/sshmcp \
  --path skills/sshmcp
```

说明：

- 安装完成后需要重启对应的 agent。
- 如果本地还没有 `sshmcp`，skill 自带的脚本可以在首次使用时下载最新 release 二进制。
- 这个 skill 仍然预期本地已经有可用配置文件。
- skill 很薄，只负责规范 agent 应该如何调用本项目 CLI。
- 如果你希望跨 agent 统一安装和更新流程，优先用 `npx skills add`。
- 如果 profile 使用了带口令私钥，把口令留在 gateway 配置里，不要粘贴到对话或命令行参数里。

## Release 自动化概览

仓库自带一个 tag 驱动的 GitHub Actions workflow：[.github/workflows/release.yml](.github/workflows/release.yml)。

工作流产物使用不可变的 commit SHA 命名，例如 `sshmcp-<commit SHA>-x86_64-unknown-linux-gnu`，并附带该压缩包的 SHA256 文件。创建版本标签时仍会发布各平台压缩包及汇总的 `SHA256SUMS`。

- 触发条件：推送匹配 `v*` 的 tag
- 构建矩阵：Windows x64 和 Linux x64
- 固定步骤：checkout、安装 Rust stable、`cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`、`cargo test --locked`、`cargo build --release --locked`、打包产物、创建 GitHub Release、上传二进制和 `SHA256SUMS`
- Release Notes：交给 GitHub 自动生成

示例：

```bash
git tag v0.2.0
git push origin v0.2.0
```

## 许可证

项目采用 [Apache License 2.0](LICENSE)。

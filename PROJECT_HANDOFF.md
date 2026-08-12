# Agent Firewall 项目总览与跨机器接续手册

> 最后更新：2026-08-12  
> 当前版本：`0.1.0-dev`  
> 当前阶段：本地可运行、核心测试通过的安全型 MVP；尚未完成真实宿主认证和公开发布  
> 目标团队与周期：2–4 人，8–12 周完成可公开发布的 v0.1

这份文件是项目的单一接续入口。换机器或开启新的开发对话时，先完整读取本文，再按“新机器启动清单”和“下一步开发顺序”继续。详细设计仍保留在 `docs/`，但不读其他文件也能从本文了解项目定位、当前状态和下一步。

## 1. 一句话介绍

Agent Firewall 是一个面向 Codex、Claude Code、OpenClaw 和通用 MCP 的本地优先行为防火墙：它在 Shell、文件写入、网络请求、敏感数据访问及高风险工具调用执行前，把不同宿主的调用转换成统一 action，使用确定性 YAML 策略作出 `allow / ask / deny` 判断，必要时要求人工批准，并留下脱敏、可验证、可重播的证据。

公开承诺应保持克制：

> One policy and one replayable evidence trail across coding agents and MCP.

它不是内核沙箱、EDR、系统级网络防火墙，也不保证拦截任意子进程的所有副作用。

## 2. 产品目标与用户

### 首要目标

- 全球开发者优先，先争取 GitHub Star 和安全社区信任。
- 一个小型 Go 二进制即可离线运行，不要求账号、守护进程、模型调用或云服务。
- 同一份策略对 Codex、Claude Code、OpenClaw 和 MCP 的语义等价动作产生一致决策。
- 对危险行为进行执行前阻断，而不是只做事后告警。
- 审批必须可解释、限时、不可无限重放。
- 证据默认脱敏，可校验完整性，并能用候选策略重播。
- 保留未来托管版可能性，但本地引擎必须始终独立可用。

### 目标用户

1. 在本地使用 coding agent 的个人开发者。
2. 希望为贡献者统一最低安全策略的开源维护者。
3. 在部署 agent 前做行为治理评估的平台与安全团队。

### 未来托管版可增加

- 团队策略分发和版本控制；
- 集中审批路由；
- 多设备证据汇总；
- 外部时间戳或不可变存储锚定；
- 兼容性与攻击语料持续服务。

这些能力不能反向要求本地引擎联网。

## 3. 当前仓库状态：换机器前必须知道

截至 2026-08-12：

- 这是独立 Git 仓库，分支名为 `main`。
- GitHub 目标仓库为 `https://github.com/YuYigeng/agent-firewall`。
- Go module path 已统一为 `github.com/YuYigeng/agent-firewall`。
- 没有与 `research-grid` 或相邻项目共用代码、数据库、产物或 Git 历史。
- 当前机器验证工具链为 Go `1.26.5 darwin/arm64`；项目声明最低 Go `1.25`。
- 临时 smoke 目录和本地编译二进制已经清理，仓库内没有需要迁移的运行时数据。

### 推荐：从 GitHub 在新机器继续

```bash
git clone https://github.com/YuYigeng/agent-firewall.git
cd agent-firewall
git switch main
go test ./...
```

### 也可以继续使用 iCloud/文件复制

必须复制整个 `agent-firewall` 目录，包括隐藏的 `.git`。到新机器后先检查：

```bash
git rev-parse --show-toplevel
git branch --show-current
git status --short
```

不要只复制可见源文件后重新在相邻项目内初始化，否则容易破坏“独立 Git 历史”的边界。

## 4. 已完成的系统

### 4.1 Canonical action 与决策契约

所有宿主动作都会进入 `afw.action/v1alpha1`，核心字段包括：

- `source`：`codex`、`claude`、`openclaw`、`mcp` 或 JSON API 调用方；
- `workspace`：动作所属工作区；
- `kind`：`shell`、`file_read`、`file_write`、`network`、`secret`、`tool`；
- `operation`、`subject`、结构化 `attributes`；
- 分析器产生的 `signals` 和 `risk`；
- 调用 id、session id 和时间戳。

决策使用 `afw.decision/v1alpha1`，包含：

- `decision`：`allow`、`ask`、`deny`；
- `risk`、命中的 `rule_id` 和安全原因；
- action fingerprint；
- policy digest；
- 可选 approval id 和匹配 trace。

JSON CLI 会重新分析 action，不信任调用方自己填写的 `risk` 或 `signals`。本地 smoke 已证明，即使输入把 `rm -rf /` 标成 `low`，最终仍会变为 `critical` 并被拒绝。

### 4.2 行为分析

当前分析器识别：

- 根目录/设备破坏、一般破坏性命令；
- reverse shell；
- 提权与权限放宽；
- shell profile、Git hook、cron/system service 等持久化；
- 网络访问和网络写入；
- 包安装；
- force push 等受保护 Git 写入；
- 动态 shell、编码后执行；
- `.env`、SSH、云凭据及常见 token 环境变量引用；
- 敏感路径、工作区外写入、agent 配置写入；
- private network 与 cloud metadata endpoint；
- secret reference 与 outbound network 组合形成的潜在外传；
- MCP/通用工具的读取型、状态变更型及未知工具。

Shell 使用 `mvdan.cc/sh` 做语法级命令抽取，再叠加保守信号规则。当前不是完整 shell 数据流分析器。

### 4.3 YAML 策略引擎

策略 schema 为 `afw.policy/v1alpha1`。支持按以下属性匹配：

- source、kind、operation；
- tool/path/host glob；
- signal；
- 最低 risk；
- workspace 或 outside-workspace path scope；
- command/argument regex。

规则先按较高 `priority` 选择；同优先级冲突时：

```text
deny > ask > allow
```

默认风险决策为：

```yaml
defaults:
  low: allow
  medium: ask
  high: ask
  critical: deny
  on_error: deny
```

内置 balanced policy 有 16 条规则，覆盖 root destruction、reverse shell、cloud metadata、潜在外传、工作区外动作、敏感路径、持久化、agent 配置、提权、网络写、破坏性命令、受保护 Git 写、状态变更工具、包安装、动态 shell 与工作区写入。

解析器会拒绝未知字段、重复 id、非法 enum、非法 regex/glob、多份 YAML document。政策语义内容会生成稳定 SHA-256 digest，注释和空白不改变 digest。

### 4.4 人工审批

- Claude Code：原生 `ask`，由 Claude permission UI 展示。
- OpenClaw：使用原生 `requireApproval`。
- Codex：当前 `PreToolUse` 不支持原生 `ask`，第一次调用会 fail closed，并返回单次 approval id；用户批准后，完全相同的动作可以重试一次。
- MCP stdio：`ask` 返回本地 JSON-RPC error，不会先发送上游；批准后由客户端重试相同调用。

本地 one-shot approval 绑定：

- action fingerprint；
- workspace；
- policy digest；
- 10 分钟有效期；
- 最多消费一次。

Critical `deny` 不会创建可覆盖的审批。人工明确拒绝后，相同动作在有效期内不会持续弹出新请求。

### 4.5 审计、校验与重播

默认数据目录解析顺序：

1. `--data-dir`；
2. `AFW_DATA_DIR`；
3. 操作系统用户配置目录下的 `agent-firewall`。

运行数据包括：

```text
audit/events.jsonl
audit/head.json
audit/ledger.lock
approvals/approvals.json
approvals/store.lock
```

决策和完成事件写入 append-only JSONL，并使用 previous hash + event hash 构成 SHA-256 链。记录前会对常见密钥、token、敏感字段与 session id 做脱敏或散列。

可执行：

```bash
agent-firewall audit list --limit 20
agent-firewall audit verify
agent-firewall audit export > evidence.jsonl
agent-firewall audit replay --policy candidate-policy.yaml
```

重播比较“当时的政策意图”而不是人工 override 后的最终结果。例如 `approved:ask-package-install` 会还原为 `ask` baseline，避免把人工批准误报为政策 drift。

Hash chain 只能证明相对 retained head 的内部一致性。能同时改写二进制、ledger 和 retained head 的同用户攻击者仍可重建整条链。

### 4.6 宿主适配器

#### Codex / Claude Code hooks

`agent-firewall init` 只创建政策文件并输出 hooks snippet，不会直接覆盖用户配置。适配器处理：

- `PreToolUse`：执行前策略判断；
- `PermissionRequest`：处理宿主已有审批；
- `PostToolUse`：写入完成状态证据。

解析或存储失败时，只要 hook 进程仍在运行，就输出宿主可识别的 fail-closed deny JSON。

#### OpenClaw plugin

`integrations/openclaw/` 已包含 TypeScript plugin、manifest、配置 schema 和安装说明。它在 `before_tool_call` 调用 Go CLI，并映射：

- `allow` → 不阻断；
- `deny` → `block: true`；
- `ask` → `requireApproval`；
- timeout、进程失败、无效 JSON → 阻断。

`after_tool_call` 只记录受限的完成状态。源代码已完成，但当前机器没有 Node/OpenClaw runtime，因此尚未做真实 plugin validate 和运行测试。

#### MCP stdio proxy

透明转发 newline-delimited JSON-RPC，只拦截 `tools/call`。安全/允许的请求发送给 child MCP server；待批准、拒绝、无效或无法分析的调用在本地返回错误，不会发送上游。

当前明确限制：

- v0.1 不支持 JSON-RPC batch；
- v0.1 不终止 Streamable HTTP；
- 只保护显式配置为经过该 proxy 的 MCP server。

测试中的 fake upstream 已证明 pending `create_issue` 没有到达上游，而安全读取正常转发。

## 5. 架构与数据流

```text
Codex hook ---------+
Claude hook --------+     +-------------------+     +------------------+
OpenClaw plugin ----+---->| action normalizer |--->| policy evaluator |
MCP stdio proxy ----+     +---------+---------+     +---------+--------+
JSON CLI -----------+               |                         |
                                    |                 allow / ask / deny
                                    |                         |
                                    |       +-----------------+----------------+
                                    |       |                                  |
                                    |  native approval                  one-shot store
                                    |       |                                  |
                                    |       +-----------------+----------------+
                                    |                         |
                                    +-------------------------v
                                              redacted hash-chain ledger
                                                        |
                                             verify / export / replay
```

安全判断主路径不调用模型，也不需要网络。

## 6. 代码地图

```text
cmd/agent-firewall/       CLI 入口
internal/action/          canonical action、risk、fingerprint
internal/analyze/         shell/path/network/tool/secret 行为分析
internal/policy/          YAML 解析、严格校验、匹配、trace、默认策略
internal/approval/        有锁、原子写入的单次审批存储
internal/redact/          action/metadata 脱敏
internal/audit/           JSONL hash chain、校验、导出
internal/engine/          策略、审批、审计的统一执行流程
internal/adapter/         Codex/Claude/OpenClaw hook codec
internal/mcpproxy/        MCP stdio JSON-RPC proxy
internal/cli/             命令、exit code、doctor、replay
integrations/openclaw/    OpenClaw TypeScript plugin
testdata/                 公开的 21-case adversarial action corpus
conformance_test.go       三个宿主来源的决策一致性测试
docs/                     详细计划、威胁模型、验收状态
.github/workflows/        macOS/Linux/Windows CI 与 release
.goreleaser.yaml          跨平台 archive、checksum、SBOM
```

最重要的阅读顺序：

1. 本文件；
2. `README.md`；
3. `internal/engine/engine.go`；
4. `internal/analyze/analyze.go`；
5. `internal/policy/policy.go`；
6. `internal/adapter/hook.go` 与 `internal/mcpproxy/proxy.go`；
7. `docs/THREAT_MODEL.md`；
8. `docs/IMPLEMENTATION_PLAN.md`。

## 7. CLI 与稳定行为

```text
agent-firewall init [--policy PATH]
agent-firewall check [--policy PATH] [--input PATH|-]
agent-firewall hook --host codex|claude|openclaw [--policy PATH]
agent-firewall mcp proxy [flags] -- COMMAND [ARG...]
agent-firewall approvals list|approve|deny [ID]
agent-firewall audit list|verify|export|replay
agent-firewall policy validate [PATH]
agent-firewall doctor
agent-firewall version
```

stdout 为 machine-readable JSON，stderr 为诊断信息。稳定 exit code：

| Code | 意义 |
| ---: | --- |
| `0` | 成功或 allow |
| `2` | deny |
| `3` | 需要审批 |
| `4` | 无效输入、参数或策略 |
| `5` | 内部、存储或证据错误 |

Hook mode 为了满足宿主协议，在失败时仍尽量以 exit 0 返回有效 deny JSON；不要仅靠进程退出码判断 hook 是否允许。

政策查找顺序：显式 `--policy`、`AFW_POLICY`、从当前目录向上寻找 `agent-firewall.yaml`。

## 8. 当前验证证据

已通过：

- `go test ./...`；
- `go test -race ./...`；
- `go vet ./...`；
- `gofmt` 检查；
- `govulncheck ./...`，当前依赖图无已知漏洞；
- 21 个 action corpus case × Codex/Claude/OpenClaw 三个 source；
- shell normalization、policy parsing、MCP frame decoding 三个 bounded fuzz run；
- MCP fake-upstream integration；
- approval fingerprint/workspace/policy/expiry/one-use 与并发测试；
- fake secret 不进入 ledger，篡改和截断校验；
- Codex deny、Codex one-shot approval、Claude native ask 的 CLI smoke；
- 四个决策事件的 hash chain 校验和同政策 0-drift replay；
- canonical action 伪报低风险的重新分析测试。

没有在测试中实际执行 `rm -rf /`、包安装或真实外部写操作；只把这些文本作为 hook/action 输入进行判断。

## 9. 明确不做与剩余风险

v0.1 不承诺：

- 拦截不触发本地 hook 的 hosted/specialized tools；
- 检查已允许 shell 进程之后产生的每个子进程副作用；
- 拦截绕过 MCP proxy 的直接 MCP 或网络连接；
- 防止 symlink/TOCTOU；
- 对能修改同用户 hook、binary、policy 和 ledger 的攻击者形成强边界；
- TLS interception 或系统级网络控制；
- Streamable HTTP MCP termination；
- 跨动作 taint tracking；
- 使用模型作最终安全决策。

生产使用应叠加宿主 sandbox、容器/microVM、最小权限凭据、只读 managed policy、独立 egress control 和外部 audit anchoring。

## 10. 还缺哪些步骤

### P0：换机器和公开前必须完成

#### 10.1 固化 Git 历史与仓库身份

- 选择最终 GitHub owner/repository。
- 检查并替换 `go.mod` 的 placeholder module path。
- 创建 initial commit 和独立 remote。
- 确认没有把本地 policy、审批数据库、ledger、凭据或 smoke 数据提交。
- 在 GitHub 开启 branch protection、Dependabot 和 secret scanning。

#### 10.2 真实 Codex 集成认证

- 在当时最新 Codex CLI/desktop 上运行 `agent-firewall init`。
- 人工审查后合并生成的 `PreToolUse`、`PermissionRequest`、`PostToolUse` snippets。
- 验证安全读操作 allow。
- 验证 package install 第一次被阻断并产生 approval id。
- 批准后验证完全相同动作仅放行一次；第二次再次 ask。
- 验证 `rm -rf /` 永远 deny，不能通过 approval 覆盖。
- 验证 hook binary 缺失、policy 损坏、data directory 不可写时的实际宿主行为。
- 保存脱敏 fixture 和宿主版本，不保存真实 transcript/secret。

#### 10.3 真实 Claude Code 集成认证

- 在最新 Claude Code 上安装 snippets。
- 验证 `ask` 使用原生 permission UI。
- 验证 allow/deny/PostToolUse wire shape。
- 覆盖 Bash、PowerShell、Write/Edit、WebFetch 和至少一个 MCP tool。
- 测试 project-local 与 user/managed settings 的优先级。

#### 10.4 OpenClaw plugin 运行验证

- 安装 Node.js 和匹配版本 OpenClaw。
- 运行 plugin manifest/schema validation。
- 执行 `openclaw plugins inspect agent-firewall --runtime --json`。
- 验证 `before_tool_call` 的 allow/block/requireApproval。
- 验证 approval timeout 为 deny。
- 验证 subprocess timeout、超大输出、invalid JSON 和 binary 不存在时 fail closed。
- 验证 `after_tool_call` 记录成功/失败但不泄漏结果正文。
- 根据真实 TypeScript 类型输出修正 API drift，并加入 golden fixture。

#### 10.5 Windows/PowerShell

- 在 Windows runner 和真实 Windows workstation 测试构建、文件锁和原子 rename。
- 增加 PowerShell destructive、download-execute、credential、registry、scheduled task、service、ACL 测试语料。
- 检查路径大小写、UNC path、drive-relative path、junction/reparse point。
- 验证 Claude/Codex 对 PowerShell tool name 和输入字段的真实格式。

#### 10.6 首次 release

- 在干净 clone 上运行所有 preflight。
- 安装 GoReleaser，执行 snapshot release。
- 解压每个目标 archive，运行 `version` 和基本 policy check。
- 在 GitHub Actions 生成 checksums、SBOM 和 provenance attestation。
- 发布 Draft `v0.1.0-rc.1`，不要直接宣称 production-ready。

#### 10.7 品牌决定

“Agent Firewall” 在 GitHub 上命名碰撞明显。公开发布前决定：

- 是否以更独特的品牌作 repository/binary 名；
- 是否保留 Agent Firewall 作为 category/tagline；
- Go module、binary、plugin id、data dir、schema 是否需要迁移。

越晚改名，兼容成本越高。

### P1：v0.1 质量提升

- 为每个受支持宿主版本建立脱敏 golden fixture。
- 扩充 attack corpus：PowerShell、Windows path、shell obfuscation、nested interpreter、MCP schema trick、Unicode/normalization。
- 给 hook Decode、canonical JSON、path inputs 增加长期 fuzz job。
- 给 `doctor` 增加宿主 hook presence/version/coverage 检查。
- 输出 machine-readable coverage certificate，明确 observer 和未覆盖路径。
- 增加 policy explain/lint 命令，提示被高优先级规则遮蔽的规则。
- 加入 benchmark，并建立同步 hook 的 p50/p95 延迟预算。
- 加入并发 MCP call、child crash、stderr flood 和 graceful shutdown 测试。
- 设计 policy layering：managed baseline 只能被 repository policy 收紧，不能放宽。
- 增加可选 trusted-head 导出/外部 anchor 流程。

### P2：v0.2 或托管版方向

- Streamable HTTP MCP reverse proxy；
- 跨动作 taint/lineage；
- 团队 policy distribution；
- 远程审批但本地 fail-closed；
- 集中 evidence ingestion 与外部 anchoring；
- 容器/microVM 或 OS-specific enforcement backend；
- 第三方 adapter SDK 和正式 conformance certification。

## 11. 建议的后续开发顺序

不要先增加大量规则。当前最大风险是“适配器看起来正确，但真实宿主 wire contract 已变化”。建议顺序：

1. 固化独立 Git remote 和最终 module path。
2. 在新机器重跑全部本地验证，确认迁移完整。
3. 完成 Codex 真实 E2E，收集第一组版本化 fixtures。
4. 完成 Claude Code 真实 E2E。
5. 安装 Node/OpenClaw，修正并测试 plugin。
6. 完成 Windows/PowerShell threat corpus 和 runner。
7. 强化 `doctor` 与兼容性说明。
8. 执行 GoReleaser snapshot 和干净 archive smoke。
9. 选择品牌、整理 README demo、录制短演示。
10. 发布 `v0.1.0-rc.1` Draft/Pre-release，观察 issue 后再发布稳定版。

### 推荐 4 周收尾安排

| 周 | 重点 | 退出条件 |
| --- | --- | --- |
| 1 | Git/品牌/module path、Codex/Claude E2E | 两个宿主的 versioned fixtures 和 fail-closed 证据 |
| 2 | OpenClaw、Windows/PowerShell | plugin runtime 与 Windows CI/实机矩阵通过 |
| 3 | doctor、性能、fuzz、release archive | clean clone preflight 与 snapshot artifacts 通过 |
| 4 | 文档/demo/RC 发布 | checksum、SBOM、attestation、RC 安装验证完成 |

## 12. 新机器启动清单

### 12.1 基础工具

必要：

- Git；
- Go 1.25 或更新版本。

P0 宿主认证还需要：

- 当前 Codex；
- 当前 Claude Code；
- Node.js 和 OpenClaw；
- GitHub CLI（创建 remote/release 时）；
- GoReleaser 与 Syft（本地 release smoke 时）。

### 12.2 恢复并确认仓库边界

```bash
cd /path/to/agent-firewall
git rev-parse --show-toplevel
git branch --show-current
git remote -v
git status --short
```

预期 toplevel 必须是 `agent-firewall` 自己，不能是 `project_icloud` 或任何相邻项目。

### 12.3 下载依赖并重跑基线

```bash
go version
go mod download
test -z "$(gofmt -l .)"
go vet ./...
go test ./...
go test -race ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
go build -trimpath -o ./bin/agent-firewall ./cmd/agent-firewall
```

Windows PowerShell 中将 formatting shell command 改为直接检查 `gofmt -l .` 输出为空。

### 12.4 隔离 smoke，不污染仓库

```bash
mkdir -p .tmp-handoff
./bin/agent-firewall init --policy .tmp-handoff/policy.yaml
./bin/agent-firewall policy validate .tmp-handoff/policy.yaml
./bin/agent-firewall doctor \
  --policy .tmp-handoff/policy.yaml \
  --data-dir .tmp-handoff/data
./bin/agent-firewall audit verify --data-dir .tmp-handoff/data
```

`.tmp-*` 和 `/bin/` 已被 `.gitignore` 忽略。真实部署时不要把 managed policy 和 audit data 放在 agent 可写仓库中。

### 12.5 短 fuzz smoke

```bash
go test ./internal/analyze -run '^$' -fuzz '^FuzzNormalizeShell$' -fuzztime=10s
go test ./internal/policy -run '^$' -fuzz '^FuzzPolicyParse$' -fuzztime=10s
go test ./internal/mcpproxy -run '^$' -fuzz '^FuzzDecodeFrame$' -fuzztime=10s
```

### 12.6 开始真实宿主测试前

- 使用临时 workspace 和 fake credentials。
- 所有危险命令只作为输入文本，不实际执行。
- 外部写工具指向测试账号/测试仓库。
- 先保留宿主原有 sandbox 和审批，不要为了测试关闭其他保护。
- 记录 host version、hook event、脱敏输入、预期与实际决策、是否执行。

## 13. Release definition of done

只有以下全部满足，才可将 v0.1 描述为公开 beta：

- Codex、Claude Code、OpenClaw 各至少一个明确版本通过真实 pre/post E2E；
- Linux、macOS、Windows 构建和测试通过；
- critical deny、native ask、Codex one-shot、MCP non-forwarding 都有自动或可重复证据；
- `go test -race`、vet、format、govulncheck、bounded fuzz 通过；
- clean archive 能独立运行；
- checksums、SBOM、provenance 已生成；
- threat model 和 coverage gaps 与实际行为一致；
- 没有真实 secret 或本地 audit data 进入 Git；
- 品牌、module path、binary/plugin id 已冻结；
- `SECURITY.md` 中的披露渠道可用。

在真实宿主测试完成前，只能称为“working security-focused MVP”，不能称为 production-certified endpoint enforcement。

## 14. 不应轻易改变的设计决定

- 最终安全决策必须确定性执行，不让模型决定 allow/deny。
- 错误默认 fail closed。
- Critical deny 不能被 one-shot approval 覆盖。
- Approval 必须绑定 fingerprint、workspace、policy digest、expiry 和 use count。
- 外部 action 的 risk/signals 不可信，必须重新分析。
- Parser 必须有 size bound、单一 document/value 和严格字段校验。
- Audit 先脱敏再持久化。
- 文档必须明确 observer coverage，不能把 hook 说成 OS-wide protection。
- 项目不能与 `research-grid` 或相邻项目共用代码、数据库、运行数据和 Git 历史。
- 不为了规则数量牺牲可解释性和低误报率。

如要改变这些决定，应同时更新 threat model、conformance corpus、迁移说明和 release notes。

## 15. 已知实现注意点

- OpenClaw TypeScript 尚未在真实编译器/runtime 验证，优先检查 API drift。
- MCP proxy 当前逐行读取，拒绝 batch；增加 HTTP 前不要暗中改变 stdio 语义。
- Shell regex 是检测层，不是完整执行模拟；不要在 README 宣称“理解所有命令”。
- Path scope 不能解决 symlink/TOCTOU，需要 OS 级防护。
- Audit reason 必须使用规则模板，不要拼接真实 secret。
- Policy regex 来自 trusted policy，但仍应注意复杂表达式的性能预算。
- `go mod tidy` 后必须检查 `go.mod` 的 Go 版本和 indirect dependency 变化。
- `golang.org/x/sys` 已升级到 `v0.44.0`，项目最低 Go 因此为 1.25。
- GitHub Actions 使用 commit SHA pin；升级 action 时继续保留 pin，而不是浮动 tag。

## 16. 官方契约来源

继续适配前必须重新核对当时最新官方文档，不能只依赖本文快照：

- Codex hooks：https://learn.chatgpt.com/codex/hooks
- Codex approvals/security：https://learn.chatgpt.com/codex/agent-approvals-security
- Codex config reference：https://learn.chatgpt.com/docs/config-file/config-reference
- Claude Code hooks：https://code.claude.com/docs/en/hooks
- OpenClaw hooks：https://docs.openclaw.ai/plugins/hooks
- OpenClaw manifest：https://docs.openclaw.ai/plugins/manifest
- OpenClaw plugin building：https://docs.openclaw.ai/plugins/building-plugins
- MCP transports：https://modelcontextprotocol.io/specification/draft/basic/transports
- MCP authorization：https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/authorization

宿主契约属于高变化面。每次发布兼容性声明都应记录具体宿主版本和 fixture。

## 17. 开新开发对话时可直接复制的指令

```text
请继续开发当前 agent-firewall 仓库。先完整读取 PROJECT_HANDOFF.md，再读取
README.md、docs/THREAT_MODEL.md 和 git status。仓库边界只限当前
agent-firewall 目录，不得修改、导入或共用相邻项目的代码、数据、数据库或
Git 历史。先在本机重跑 go test、race、vet 和 govulncheck，再从
PROJECT_HANDOFF.md 的 P0 清单选择尚未完成的第一项。任何安全边界变更都要
同步测试、threat model、acceptance status 和本 handoff 文件。不要执行真实
破坏性命令；使用临时 workspace、fake credential 和测试账号。
```

## 18. 相关文件

- `README.md`：面向最终用户的公开介绍和快速上手。
- `docs/IMPLEMENTATION_PLAN.md`：完整产品与工程决策、策略 schema、8–12 周计划。
- `docs/THREAT_MODEL.md`：资产、攻击者、信任边界、控制和残余风险。
- `docs/ACCEPTANCE.md`：本次本地验证证据与尚未完成的 release blockers。
- `SECURITY.md`：安全报告方式与支持边界。
- `CONTRIBUTING.md`：贡献和测试要求。

后续每完成一个 P0 项目，都应在本文对应条目打勾或改写状态，并同步 `docs/ACCEPTANCE.md`。这样下一台机器或下一位开发者只需要从本文件进入即可。

# Tech Spec

## Linked Issue

GH-57

## Product Spec

`specs/GH57/product.md`

## Codebase Context

| Area | Files | Current behavior | Why relevant |
| --- | --- | --- | --- |
| 核心类型 | `crates/argus-core/src/lib.rs` | `Finding`/`Severity`/`Decision`/`ScanReport`，`ArtifactKind` 只有 PackageDir/Lockfile | 复用全部类型；`ArtifactKind` 需新增 `AgentSurface` 变体 |
| 规则引擎模式 | `crates/argus-rules/src/lib.rs` | 纯函数规则 `run(&ctx, &mut findings)`，`collect_files` walk + 文本/二进制分流，`looks_binary` 导出 | argus-agent 套同一模式；`looks_binary` 直接复用 |
| 决策推导 | `crates/argus-rules/src/decision.rs` | 按 finding 严重度 + allowlist 推导三档决策 | agent 面决策更简单（无 native-build allowlist），独立实现 |
| CLI | `crates/argus-cli/src/main.rs` | clap Subcommand 枚举 + Text/Json 两种输出 | 新增 `Agent { Scan }` 子命令，复用输出渲染 |
| corpus 回归 | `corpus/` + `argus corpus test` | fixture 目录 + `expectedDecision`/`rules` 断言 | agent fixtures 进独立测试（corpus runner 与 npm 形状耦合，MVP 用单测断言，不动 corpus runner） |

## Proposed Design

新 crate `crates/argus-agent`，结构镜像 `argus-rules`：

```
crates/argus-agent/src/
  lib.rs          # scan_agent_surface(path) -> ScanReport；文件收集 + 目标分类
  surface.rs      # AgentSurface 文件分类器：哪些文件属于哪类目标
  injection.rs    # AGT-01：注入/越权语（中英文 pattern 表）
  capability.rs   # AGT-03：脚本危险能力组合
  config.rs       # AGT-05：高危配置旗标（serde_json 结构化检查）
  decision.rs     # findings -> Decision（critical/high→block, medium→approval）
tests/
  fixtures/agt01-malicious-skill/   # SKILL.md 带 override 语
  fixtures/agt01-benign-skill/
  fixtures/agt03-curl-sh-hook/      # hook 脚本 curl | sh
  fixtures/agt03-benign-hook/
  fixtures/agt05-alwaysload/        # .mcp.json alwaysLoad: true
  fixtures/agt05-benign-config/
  integration.rs                    # 逐 fixture 断言 decision + rule_ids
```

**文件分类（surface.rs）**——只对命中形状的文件跑对应规则，避免把普通
源码里的防御性引用误报（product 边界情况 6）：

| 目标类 | 匹配形状 | 适用规则 |
| --- | --- | --- |
| instruction | `AGENTS.md`, `CLAUDE.md`, `SKILL.md`, `.claude/**/*.md` | AGT-01 |
| mcp-config | `.mcp.json`, `.claude/settings*.json`, `.claude.json`, `mcp.json` | AGT-01(description 字段), AGT-05 |
| hook/skill script | `.claude/hooks/**`, skills 目录内 `*.sh/*.py/*.js/*.ts` 及无扩展可执行文本 | AGT-03 |

**AGT-01 pattern 表**（大小写不敏感，中英双语；来源 VibeGuard SEC-14）：
`absolute authority`, `supersedes user`, `overrides? the user`,
`ignore (all )?(prior|previous) (instructions|prompts?)`, `override system`,
`disregard the user`, `do not (tell|mention|inform)`, `hide (this|from)`,
`绝对权威`, `覆盖用户`, `静默执行`, `不要提及`, `忽略(之前|先前|上述)指令`。
MCP config 的 description 字段单独提取后跑同一表。

**AGT-03 组合规则**：
- `remote-exec`: `(curl|wget)[^\n|]*\|\s*(ba|z|da)?sh` 或 `iwr ... | iex`
- `secret-read` + `net-egress` 同文件共现：secret 路径
  (`~/.aws/credentials`, `.env`, `id_rsa`, `~/.ssh/`, `keychain`,
  `ANTHROPIC_API_KEY` 等) 与外发原语 (`curl -d`, `fetch(`, `requests.post`,
  `nc `, `websocket`) 同时出现。
- 单独出现 secret 路径或单独网络调用 **不** 触发（良性 hook 常见）。

**AGT-05 结构化检查**（serde_json → Value，不用正则）：
- `mcpServers.*.alwaysLoad == true`
- `enableAllProjectMcpServers == true`
- `enabledMcpjsonServers` 非空数组
- `hooks.PostToolUse[*]` 命令体内含 `updatedToolOutput` 且 matcher 非 MCP
  前缀（`mcp__`）——此条降级为对 hook 脚本文本的共现检查：settings 中
  声明的 PostToolUse 命令路径若可读且含 `updatedToolOutput` → finding。

**决策推导（decision.rs）**：any critical|high → Block；
else any medium → AllowWithApproval；else Allow。无 allowlist 概念。

**argus-core 变更**：`ArtifactKind` 新增 `AgentSurface` 变体（additive，
serde kebab-case 序列化为 `agent-surface`；不改既有变体，兼容）。

**CLI**：`argus agent scan <paths...> [--format text|json]`。多路径时逐个
产出 `ScanReport`，Json 模式输出数组；任一 report 为 Block 时退出码非零
（与现有 scan 行为一致）。

## Product-to-Test Mapping

| Product invariant | Implementation area | Verification |
| --- | --- | --- |
| P1 不执行被扫描代码 | lib.rs 只 read；无 Command | code review + 无 std::process 依赖断言 |
| P2 AGT-01 → block | injection.rs + decision.rs | fixtures agt01-malicious-skill / benign |
| P3 AGT-03 组合 → block | capability.rs | fixtures agt03-curl-sh-hook / benign-hook（含单独 secret 读不触发用例） |
| P4 AGT-05 → approval | config.rs | fixtures agt05-alwaysload / benign-config |
| P5 良性零误报 | 全部 | 每规则 benign fixture 断言 Allow + 空 findings |
| P6 形状外不扫 | surface.rs | 单测：普通 `src/main.rs` 含攻击字符串 → 无 finding |

## Data Flow

输入：本地路径（目录或单文件）。输出：`ScanReport`（stdout text/json）。
无网络调用、无持久化、无环境变量依赖。IO 错误按文件粒度跳过（product
边界情况 1），unparseable JSON → info finding（边界情况 3）。

## Alternatives Considered

- 把规则塞进 `argus-rules`：拒绝——那个 crate 的 `PackageContext` 以
  `package.json` 为必需入口，agent 面无此结构；独立 crate 边界更干净。
- 复用 corpus runner：拒绝（MVP）——runner 断言形状与 npm 包耦合，
  改造成本大于独立集成测试；后续如需要再统一。
- 用 YAML 外置 pattern 表：拒绝——MVP 规则集小且稳定，硬编码 + 单测
  更简单；外置化等规则数量增长后再做（U-02）。

## Risks

- Security: 误报/漏报都可能发生；MVP 定位为词法/结构层第一道闸，
  README 明确不承诺语义级检测。
- Compatibility: `ArtifactKind` 新变体对旧 JSON 消费者是新值——argus
  尚无稳定下游，风险可接受，CHANGELOG 记录。
- Performance: walk + 正则，目标目录通常 <10k 文件，无热点。
- Maintenance: pattern 表与 VibeGuard SEC 规则同源，注释标注来源规则号
  便于同步。

## Test Plan

- [ ] Unit tests: injection/capability/config 每模块正负例
- [ ] Integration tests: fixtures × (decision + rule_ids) 断言
- [ ] Manual verification: `argus agent scan ~/.claude`（本机真实配置）

## Rollback Plan

独立 crate + 独立子命令，回滚 = revert 提交；不影响既有 8 生态扫描路径。

# Tech Spec

## Linked Issue

GH-64

## Product Spec

`specs/GH64/product.md`

## 前置状态

本 spec 建立在 **GH-59 / PR #63 合并后**的 `argus-agent` 状态上：
- `argus_core::Finding` 已含可选 `capability` / `evidence` / `resolved_host`
  字段（additive）。AGT-02 不再改 `Finding` 形状，只复用 `location` +
  `detail`（+ 可选 `evidence` 承载 old/new 哈希）。
- `capability.rs` 已重构为能力清单 + 意图错配。AGT-02 与之正交，新增
  独立 `baseline.rs` 模块，不改 capability 逻辑。

## Codebase Context

| Area | Files | Current behavior | Why relevant |
| --- | --- | --- | --- |
| agent 扫描入口 | `crates/argus-agent/src/lib.rs` | `scan_agent_surface(path) -> ScanReport`，收集 `SurfaceFile` 后跑 injection/capability/config | AGT-02 需要一个能携带 baseline 的入口变体；`SurfaceFile{rel,content,kind}` 是漂移检测的输入 |
| 面分类 | `crates/argus-agent/src/surface.rs` | `SurfaceKind::{Instruction,McpConfig,Script}` | AGT-02 只对 `McpConfig`（tool description）与 `Instruction` 里的 `SKILL.md`（frontmatter）抽取 description |
| 决策派生 | `crates/argus-agent/src/decision.rs` | critical/high→block, medium→approval, else allow | AGT-02 漂移为 medium，天然走 allow-with-approval，无需改 decision.rs |
| 核心类型 | `crates/argus-core/src/lib.rs` | `Finding{rule_id,severity,detail,location,capability?,evidence?,resolved_host?}` | 复用，不新增字段；old/new 哈希放进 `evidence` 或 `detail` |
| CLI | `crates/argus-cli/src/main.rs` | `AgentOp::Scan{paths,format}` → `cmd_agent_scan` | 新增 `--baseline <file>` 与 `--update-baseline <file>` 两个可选 flag |
| 配置解析参考 | `crates/argus-agent/src/config.rs` | serde_json 结构化读 `.mcp.json` 等 | description 抽取复用同样的 serde_json 读法 |

## Proposed Design

新增 `crates/argus-agent/src/baseline.rs`，与既有规则模块正交：

```
crates/argus-agent/src/
  baseline.rs     # 新增：description 抽取、哈希、基线读写、漂移对比
  lib.rs          # 扩展：scan_agent_surface_with_baseline(path, BaselineMode)
tests/
  integration.rs  # 扩展：baseline create / unchanged / drift 三条路径
  fixtures/agt02-baseline-*/  # 新增 fixtures（见下）
```

### 1. Description 条目抽取（baseline.rs）

对每个 `SurfaceFile` 抽取 description 类条目，产出 `Vec<DescEntry>`：

```rust
struct DescEntry {
    key: String,     // 稳定定位符："<rel>#<locator>"
    hash: String,    // 稳定哈希（内容字节 → 十六进制摘要）
}
```

- `SurfaceKind::McpConfig`：serde_json 解析，遍历 `mcpServers.<name>` 与
  顶层/嵌套 `tools[].description` / `.description` 字段。key =
  `"<rel>#mcpServers.<name>.description"` 等。解析失败 → 跳过该文件的抽取
  （由 config.rs 已产 info finding，不重复报）。
- `SurfaceKind::Instruction` 且文件名为 `SKILL.md`：抽取 YAML frontmatter
  的 `name` / `description`。key = `"<rel>#frontmatter.description"`。
  frontmatter 缺失 → 无条目（非错误）。
- 其他 instruction 文件（`AGENTS.md`/`CLAUDE.md`/`.claude/**/*.md`）：MVP
  不纳入基线（整文件漂移噪声大，且已由 AGT-01 词法层守护）；non-goal 记录，
  留待后续。

哈希：用工作区已有依赖计算稳定摘要（优先 `sha2`；若工作区未引入则用
标准库 `std::hash` 不可跨版本稳定——**必须选内容确定性算法**，故引入
`sha2`（已在 argus-fetch 等 crate 使用，复用而非新增依赖）。摘要对
description 的 UTF-8 字节计算，输出十六进制，证据只展示前 12 字符。

### 2. 基线文件格式（baseline.rs）

JSON，稳定 key 排序（BTreeMap 保证确定性输出）：

```json
{
  "version": 1,
  "entries": {
    "<rel>#<locator>": "<hex-hash>"
  }
}
```

- `load(path) -> Result<Baseline>`：不存在 → 明确错误（调用方决定语义）；
  存在但解析失败 → `Err`（CLI 转 info finding，不 panic）。
- `save(path, &Baseline)`：确定性序列化（键有序），换行结尾。

### 3. 扫描入口扩展（lib.rs）

```rust
enum BaselineMode<'a> {
    None,                    // GH-57 行为，AGT-02 不参与
    Check(&'a Path),         // 对比基线，漂移 → AGT-02 finding
    Update(&'a Path),        // 抽取当前 description 写入基线，不产漂移 finding
}

pub fn scan_agent_surface_with_baseline(path, mode) -> Result<ScanReport>
```

- `scan_agent_surface(path)` 保留为 `..._with_baseline(path, None)` 的薄封装
  （不破坏既有调用点与测试）。
- `Update`：收集 SurfaceFile → 抽取全部 DescEntry → 写基线文件 → 正常跑
  injection/capability/config（更新基线不豁免其他规则）→ **不**跑 AGT-02 对比。
- `Check`：load 基线（失败→push info finding，continue）→ 抽取当前 DescEntry
  → 对比：
  - key 在基线且 hash 不同 → AGT-02 medium finding，`location = rel`，
    `detail` 含 locator + old/new 前缀，`evidence = ["<rel>:<locator> old=<h1> new=<h2>"]`。
  - key 在基线、当前缺失 → info finding（baseline entry missing）。
  - key 不在基线（新条目）→ 不产 AGT-02（product 非目标）。

**基线文件自身排除**：Update/Check 时若基线文件位于被扫描树内，collect 阶段
按绝对路径过滤掉它，避免自指。

### 4. 决策

无需改 `decision.rs`：AGT-02 漂移是 medium → 既有派生给出
allow-with-approval；若漂移文件同时命中 AGT-01（critical），既有派生
自然升级为 block（invariant P5 的规则叠加）。

### 5. CLI（main.rs）

```
argus agent scan <paths...> [--format text|json]
                            [--baseline <file>]        # Check 模式
                            [--update-baseline <file>] # Update 模式
```

- 两 flag 互斥（clap `conflicts_with`）；都不给 → None 模式。
- `--update-baseline` 成功后 stderr 打印 "baseline written: N entries"，退出码 0。
- `--baseline` 模式退出码沿用现有：任一 report 为 Block 非零。AGT-02 单独
  漂移为 allow-with-approval，不改变退出码为非零（与 medium 一致）。

## Product-to-Test Mapping

| Product invariant | Implementation area | Verification |
| --- | --- | --- |
| P1 不执行代码 | baseline.rs 只 read/write baseline 文件 | code review，无 std::process |
| P2 抽取 MCP+SKILL description | baseline.rs `extract_entries` | 单测：给定 .mcp.json / SKILL.md 断言 key 集 |
| P3 Update 即批准、不产漂移 | lib.rs Update 分支 | 集成测试：update 后 findings 无 AGT-02 |
| P4 漂移 → AGT-02 + old/new 哈希 | lib.rs Check 分支 | 集成测试 drift：改 description 后断言 AGT-02 + evidence |
| P5 medium→approval，叠加 AGT-01 | decision.rs（复用） | 单测：AGT-02 单独→approval；+AGT-01→block |
| P6 无 baseline 不降级 / 坏 baseline→info | lib.rs None/Check load 失败 | 单测：None 模式无 AGT-02；坏文件→info 不 panic |
| P7 缺失条目→info | lib.rs Check | 集成测试：删条目后断言 info finding |
| P8 未变→无 finding | lib.rs Check | 集成测试 unchanged：断言无 AGT-02 |

## Data Flow

输入：本地路径 + 可选基线文件。Update 写基线文件（唯一副作用，显式路径）。
Check 读基线文件。无网络、无环境变量、无执行被扫描内容。哈希对同一字节
确定输出。

## Alternatives Considered

- 把 old/new 明文写进 finding：拒绝——description 可能含注入语，报告二次
  渲染有风险（product 边界情况：只展示哈希前缀）。
- 整 instruction 文件哈希纳入基线：拒绝（MVP）——AGENTS.md/CLAUDE.md 正常
  编辑频繁，整文件漂移高 FP；只锁 SKILL.md frontmatter + MCP description
  这类"契约面"。
- 用 `std::hash::Hasher`（DefaultHasher）：拒绝——不保证跨版本/跨平台稳定，
  基线是持久化跨会话对比，必须用内容确定性摘要（sha2）。
- 漂移直接 block：拒绝——合法更新与 rug-pull 词法不可分，high FP；用
  re-approval（medium）暴露而不误伤（product invariant P5）。

## Risks

- Security: AGT-02 只测"变没变"，不测"变成什么"；README 明确它是 rug-pull
  的**检测**层，恶意判定仍靠 AGT-01/GH-59。
- Trust boundary: `--update-baseline` 是信任动作——谁能运行它谁就能"批准"
  任意描述。README 必须说明基线文件应纳入用户自己的版本控制/审计，argus
  不代管信任。
- Compatibility: 新增可选 CLI flag + 新公有函数，additive；`scan_agent_surface`
  签名不变。
- Dependency: 复用工作区已有 `sha2`，不新增依赖（先 `cargo tree` 确认）。

## Test Plan

- [ ] Unit: `extract_entries` 对 MCP config / SKILL.md 断言 key+hash
- [ ] Unit: baseline load/save 往返确定性；坏文件 → Err 不 panic
- [ ] Integration baseline-create：update 写出基线，条目数正确，无 AGT-02
- [ ] Integration unchanged：同面二次 Check 无 AGT-02 finding
- [ ] Integration drift：改一个 description 后 Check → AGT-02 + old/new 证据
- [ ] `cargo test` 全 workspace + `cargo clippy` 通过

## Rollback Plan

新增 `baseline.rs` + 两个可选 CLI flag + 一个新公有函数，全 additive。
回滚 = revert 提交；`--baseline`/`--update-baseline` 不给时行为与 GH-57 完全一致。

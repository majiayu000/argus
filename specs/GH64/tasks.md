# Tasks — GH-64 AGT-02 description 哈希漂移基线

| # | Task | Owner | Depends | Done-when / Verify | Status |
| --- | --- | --- | --- | --- | --- |
| SP64-T1 | `baseline.rs`：`DescEntry` 抽取（MCP `description` 字段 + `SKILL.md` frontmatter `name`/`description`），稳定 key；在 `crates/argus-agent/Cargo.toml` 显式加 `sha2 = { workspace = true }`（sha2 已在 workspace，但当前不在 argus-agent 依赖中） | agent crate | GH-59/#63 合并 | 单测：给定 fixture .mcp.json / SKILL.md 断言 key 集与 hash 确定；`cargo tree -p argus-agent \| grep sha2` 有输出 | todo |
| SP64-T2 | `baseline.rs`：基线文件 JSON `load`/`save`（BTreeMap 有序、确定性、坏文件→Err） | agent crate | T1 | 单测：save→load 往返一致；损坏文件 `Err` 不 panic | todo |
| SP64-T3 | `lib.rs`：`BaselineMode{None,Check,Update}` + `scan_agent_surface_with_baseline`；`scan_agent_surface` 变薄封装 | agent crate | T1,T2 | 既有调用点/测试不回归；`cargo test -p argus-agent` | todo |
| SP64-T4 | Update 分支：抽取当前 description 写基线、跑其余规则、不产 AGT-02；排除基线文件自身 | agent crate | T3 | 集成测试 baseline-create：写出基线、条目数正确、findings 无 AGT-02 | todo |
| SP64-T5 | Check 分支：漂移→AGT-02 medium（old/new 哈希前缀进 evidence）；缺失→info；新条目不产 | agent crate | T3 | 集成测试 drift + unchanged + missing 三路径断言 | todo |
| SP64-T6 | CLI `--baseline` / `--update-baseline`（互斥），退出码语义（medium 不改非零） | cli crate | T3-T5 | `cargo run -p argus-cli -- agent scan --update-baseline ... ` 手测 + 单测 clap 解析 | todo |
| SP64-T7 | README：基线工作流 + 信任边界段落（更新即批准、基线应纳入用户审计） | docs | T4-T6 | README 含 AGT-02 用法与信任边界说明 | todo |
| SP64-T8 | fixtures：`agt02-baseline-mcp`（含基线文件 + 漂移版）、`agt02-baseline-skill` | test | T1 | 集成测试引用；良性未变 fixture 断言无 AGT-02 | todo |

## Spec Packet

- Product: `product.md`
- Tech: `tech.md`

## Parallelization

- T1/T2 可并行（抽取 vs 文件 IO，文件所有权在 `baseline.rs` 内不同函数，
  但同文件——建议串行或一人写，避免中间态）。
- T4/T5（Update vs Check 分支）改同一 `lib.rs` 入口函数，**串行**。
- T6（CLI）依赖入口签名稳定，排 T3 之后。
- 文件所有权：新增 `crates/argus-agent/src/baseline.rs` 独占；`lib.rs` 与
  `main.rs` 少量扩展；不改 `capability.rs`/`injection.rs`/`config.rs`
  （与 GH-59 改动面正交，避免与 #63 后续冲突）。

## Verification

- [ ] `cargo test` 全 workspace 通过（含 baseline-create / unchanged / drift）
- [ ] `cargo clippy --all-targets` 无告警
- [ ] 手测 `argus agent scan --update-baseline b.json ~/.claude` 后改一个
      description 再 `--baseline b.json` 扫描 → 出 AGT-02

## Handoff Notes

- **前置**：GH-59 / PR #63 合并——`Finding` 的 `capability/evidence/resolved_host`
  字段与 `capability.rs` 重构落地后再动，避免基线代码建在旧形状上。
- 核心信任边界：`--update-baseline` = 批准动作。argus 不代管信任，基线文件
  应由用户自己版本控制/审计。README 必须讲清这点，否则 AGT-02 会被误解为
  "argus 保证描述可信"。
- AGT-02 只检测"变没变"，恶意判定仍靠 AGT-01（词法）与 GH-59（意图错配）。
  漂移后若新内容命中 AGT-01，既有 decision 派生自然升级为 block。
- 依赖：优先复用工作区已有 `sha2`；实现前先 `cargo tree | grep sha2` 确认，
  未引入再决定加依赖（U-06，标准库 DefaultHasher 不满足跨版本稳定，不可用）。
- 非目标（后续 issue）：AGENTS.md/CLAUDE.md 整文件漂移、registry 批量、
  语义级恶意判定。

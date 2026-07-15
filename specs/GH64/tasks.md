# Tasks — GH-64 AGT-02 description 哈希漂移基线

- [ ] `SP64-T1` 抽取稳定 description entries 并接入 sha2。Owner: agent crate。Done when: MCP/SKILL fixture 的 key 与 hash 确定。Verify: focused unit tests 与 `cargo tree -p argus-agent | grep sha2`。
- [ ] `SP64-T2` 实现确定性 baseline JSON load/save。Owner: agent crate。Done when: BTreeMap 往返一致且坏文件返回 Err。Verify: baseline round-trip/error tests。
- [ ] `SP64-T3` 接入 BaselineMode 与扫描入口。Owner: agent crate。Done when: None/Check/Update 调用点稳定且既有扫描不回归。Verify: `cargo test -p argus-agent`。
- [ ] `SP64-T4` 实现 Update 分支。Owner: agent crate。Done when: 写入当前 snapshot、排除 baseline 本身且不产 AGT-02。Verify: baseline-create integration test。
- [ ] `SP64-T5` 实现 Check 分支。Owner: agent crate。Done when: drift 为 medium、missing 为 info、new entry 不误报。Verify: drift/unchanged/missing integration tests。
- [ ] `SP64-T6` 增加 CLI baseline flags。Owner: CLI crate。Done when: `--baseline` 与 `--update-baseline` 互斥且退出码兼容。Verify: clap tests 与手动 CLI scan。
- [ ] `SP64-T7` 记录 baseline 工作流与信任边界。Owner: docs。Done when: README 明确 update 即批准且 baseline 由用户审计。Verify: README 内容检查。
- [ ] `SP64-T8` 增加 MCP/SKILL baseline fixtures。Owner: agent tests。Done when: 良性未变 fixture 无 AGT-02 且漂移 fixture 有断言。Verify: integration tests。

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

- workspace tests 覆盖 baseline-create、unchanged 与 drift。
- clippy all-targets 无告警。
- 手测 update baseline 后修改 description，再 check baseline 产生 AGT-02。

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

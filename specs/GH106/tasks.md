# Task Plan

## Linked Issue

GH-106

## Spec Packet

- Product: `product.md`
- Tech: `tech.md`

## 实现任务

- [ ] `SP106-T1` 只抽取 shared atomic byte writer，并让 AGT-02 baseline 改用它。Covers: B-006. Owner: persistence worker. Dependencies: none. Done when: 新 module 已在 crate root 注册，五阶段故障均保留旧 destination，AGT-02 bytes 不变，且本任务不引入 `SurfaceKind::InventoryOnly`。Verify: `cargo test -p argus-agent atomic_write_fault_matrix && cargo test -p argus-agent baseline`.
  File ownership:
  `crates/argus-agent/src/atomic_write.rs`,
  `crates/argus-agent/src/baseline.rs`,
  `crates/argus-agent/src/lib.rs`. `lib.rs` 仅增加
  `atomic_write` module declaration；production 路径保持
  tempfile → write → flush → file sync → persist；`atomic_write.rs` module
  内部私有 `#[cfg(test)]`
  `CreateTemp/Write/Flush/FileSync/Persist` 故障矩阵逐项证明旧 destination
  bytes/mtime 不变、missing destination 不产生半文件、无 tempfile 泄漏；AGT-02
  序列化 bytes 与现状相同。fault enum/seam 不导出 crate，也不增加 Cargo
  feature、hidden flag/env。完成后将 `baseline.rs` 串行移交 T2，并将
  `lib.rs` 串行移交 T2；不得并行编辑这些共享路径。

- [ ] `SP106-T2` 实现 strict v1 schema、canonical inventory core、全字节 hash、五类 Medium rule 与单一 surface membership。Covers: B-001, B-002, B-003, B-005, B-008, B-010. Owner: inventory worker. Dependencies: SP106-T1. Done when: snapshot module 已注册，InventoryOnly/legacy-pruned path 分类、baseline/injection exhaustive no-op、合法空 snapshot、双向 transition、全字节/隐私/schema/core fail-closed/rule unit matrix 通过；不要求尚由 T3 实现的 walker、snapshot target guard、semantic skip 或默认 scan compatibility。Verify: `cargo test -p argus-agent snapshot && cargo test -p argus-agent surface && cargo test -p argus-agent baseline && cargo test -p argus-agent injection`.
  File ownership:
  `crates/argus-agent/src/baseline.rs`,
  `crates/argus-agent/src/injection.rs`,
  `crates/argus-agent/src/lib.rs`,
  `crates/argus-agent/src/snapshot.rs`,
  `crates/argus-agent/src/surface.rs`.
  `lib.rs` 只注册 `snapshot` module 并暴露 T3 所需的 crate API。
  Snapshot 模块不含高上下文路径名单；所有
  membership 来自扩展后的 `surface::classify`；multi-chunk binary file hash 到
  EOF；symlink 仅存 raw-target SHA-256；严格 schema/path/hash/race 错误全部
  fail closed；合法 `entries: {}` round-trip；
  空集合 transition 四项分别为 file/directory added、symlink
  symlink-changed、file/directory removed、symlink symlink-changed；同 path
  按 symlink → add/remove → type → content 优先级只产生一个固定 rule；
  evidence 逐字节匹配 B-003 无空格分号 grammar，`change=` 只允许
  `entry_added|entry_removed|content_modified|entry_type_changed|symlink_changed`
  并与五个 rule 一一映射，且所有值无 escaping。`surface::classify` 新 shape
  只返回 `InventoryOnly`，既有 shape 保持原 kind；inventory core 记录 discovery
  交给它的全部 classified `Some`，
  baseline extraction 与 injection exhaustive match 都对 InventoryOnly 显式
  no-op。传入的 logical path 位于 `.git`/`node_modules` ancestor 后时仍可分类为
  InventoryOnly。`baseline.rs` 与 `lib.rs` 只能在 T1 完成并移交后修改；T2
  完成后再将 `lib.rs` 串行移交 T3。

- [ ] `SP106-T3` 接入 mode-split discovery、snapshot membership guard、正交 `DiscoveredEntry`、semantic projection、SnapshotMode 与 persist-before-render outcome。Covers: B-001, B-003, B-004, B-005, B-007, B-009, B-010. Owner: agent orchestration worker. Dependencies: SP106-T1, SP106-T2. Done when: None/AGT-02-only 完全保留 legacy pruning；Check/Update complete-discover 所有 descendant；classified snapshot target 在排除/load/write 前拒绝；entry_type/surface_kind 正交；projection 先跳过 directory、再跳过 InventoryOnly file/symlink，并保留既有 semantic symlink hard error；semantic/judge/persist error 返回 partial outcome。Verify: `cargo test -p argus-agent --test gh106_snapshot && cargo test -p argus-agent`.
  File ownership:
  `crates/argus-agent/src/lib.rs`,
  `crates/argus-agent/tests/gh106_snapshot.rs`,
  `crates/argus-agent/tests/fixtures/agt04-snapshot-base/AGENTS.md`,
  `crates/argus-agent/tests/fixtures/agt04-snapshot-base/.claude/settings.json`,
  `crates/argus-agent/tests/fixtures/agt04-snapshot-base/.claude/rules/policy.txt`,
  `crates/argus-agent/tests/fixtures/agt04-snapshot-base/.cursorrules`.
  `SnapshotMode::None`（含无 snapshot 与 AGT-02-only check/update）原样调用
  legacy `.git`/`node_modules` pruning collector，并仅在现有 classification
  阶段让 InventoryOnly 在 state/body/symlink validation 前 no-op。只有
  Check/Update 执行
  complete non-pruning discovery，生成 filesystem
  `entry_type=file|directory|symlink` 与 `surface_kind=Option<SurfaceKind>` 正交的
  `DiscoveredEntry`；root 内 snapshot target 若 classify Some，在 exact
  exclusion/load/render/write 前 operational reject。inventory 收集全部
  classified entry；semantic projection 先跳过 directory，再在任何正文/
  binary/UTF-8/size/symlink validation 前跳过 InventoryOnly file/symlink，然后
  跳过 unclassified，最后让既有 semantic symlink/file 走原 hard error/
  validation。integration regression 分别锁定 legacy mode pruning 与 snapshot
  mode complete discovery/projection。check 完成
  compare 后才跑 injection/capability/config/AGT-02/judge；update report/decision
  只存内存，atomic persist 成功后才能交给 normal renderer；semantic/judge/
  persist error 返回携带内存 report/findings 的 incomplete outcome。

- [ ] `SP106-T4` 为 semantic/judge/persist incomplete outcome 增加 SARIF 失败 invocation，保留 results 且不泄露敏感内容。Covers: B-004, B-006, B-008. Owner: SARIF worker. Dependencies: SP106-T3. Done when: 所有 partial invocation 为 false、finding 不丢不重复且 notification 无敏感内容。Verify: `cargo test -p argus-cli sarif_snapshot_incomplete && cargo test -p argus-cli sarif`.
  File ownership: `crates/argus-cli/src/sarif.rs`. Complete report 仍为
  `executionSuccessful=true`；partial report 为
  `false` 并有 sanitized error notification；AGT-04 results 只出现一次，
  decision 为 block，target/plaintext 不出现在 document。T4 只提供并冻结
  pure SARIF renderer API 与 unit tests，不修改 CLI call site；T5 负责接线。

- [ ] `SP106-T5` 接入精确 Clap/handler、snapshot target rejection、persist-before-render 与 text/JSON/SARIF/exit 行为。Covers: B-001, B-004, B-005, B-006, B-007, B-008, B-009. Owner: CLI worker. Dependencies: SP106-T3, SP106-T4. Done when: classified target 的 check/update 均在 load/render/write 前失败；`CARGO_BIN_EXE` production persist failure 从未调用 normal renderer/exit；三种 partial 输出、success control、flags/readonly/既有 CLI 行为兼容均通过，且无跨 crate fault seam。Verify: `cargo test -p argus-cli --test agent_snapshot_cli`.
  File ownership:
  `crates/argus-cli/src/main.rs`,
  `crates/argus-cli/src/agent.rs`,
  `crates/argus-cli/tests/agent_snapshot_cli.rs`. Help 只新增
  `--check-snapshot <FILE>` 与
  `--update-snapshot <FILE>`；check+check (`--baseline` + `--check-snapshot`)
  成功，其余 update/persistence 组合由 Clap 和 handler 双重拒绝；所有
  persistence mode 拒绝多 PATH；check 前后 snapshot bytes/mtime 相同；
  partial JSON 精确为
  `{schemaVersion:1,executionSuccessful:false,operationalError:
  {kind:"agent_scan_incomplete",message:<sanitized>},report:<ScanReport>}`，
  report decision=block 且保留 finding；完整 snapshot/无 snapshot JSON 继续
  输出 bare report。partial text/SARIF 保留 finding、stderr 报 operational
  error、exit 2；
  update report 先留内存。CLI test 用 `env!("CARGO_BIN_EXE_argus")` 启动
  production binary，以 root 外含 sentinel 的 non-empty directory 作为
  destination 触发真实 Persist failure；text/JSON/SARIF 均断言 sentinel
  bytes/mtime/目录内容不变、no normal render/exit、no `snapshot written`、
  partial output、sanitized stderr/exit 2。普通 file destination success
  control 证明 persist 后才输出 normal report 与固定 entry count，且不把
  semantic block/approval 强制改为 exit 0。不得添加 Cargo feature、公开/隐藏
  API、hidden flag/env。
  Root 内 existing/missing `AGENTS.md`、`.claude/settings.json`、`.cursorrules`
  与 skill script target 均断言 stdout 空、sanitized operational error、exit 2、
  bytes/mtime 不变；unclassified root 内 target 与 root 外 target 为正例。

- [ ] `SP106-T6` 更新 AGT-04 用户文档。Covers: B-001, B-004, B-005, B-006, B-007, B-008, B-009, B-010. Owner: docs worker. Dependencies: SP106-T5. Done when: workflow/rules/共存、snapshot target 禁止形状、snapshot-only complete discovery、legacy mode pruning compatibility、批准/存放/persist-before-render/InventoryOnly projection/partial 限制完整且移除 follow-up 表述。Verify: `rg -n "check-snapshot|update-snapshot|AGT-04-(entry|content|symlink)" README.md && cargo test -p argus-cli --test agent_snapshot_cli`.
  File ownership: `README.md`. 文档给出安装前
  `--update-snapshot` → 安装 → 安装后
  `--check-snapshot` 示例、AGT-02 共存矩阵、五个 rule/Medium 决策、snapshot
  外置/版本控制建议、schema/platform 与并发限制、partial operational
  semantics；移除“AGT-04 remains follow-up”。

- [ ] `SP106-T7` 执行 fresh 全量门禁并提交实现证据。Covers: B-001, B-002, B-003, B-004, B-005, B-006, B-007, B-008, B-009, B-010. Owner: verification owner. Dependencies: SP106-T1, SP106-T2, SP106-T3, SP106-T4, SP106-T5, SP106-T6. Done when: 最终 HEAD 的 targeted/all-spec/Rust/corpus/coverage/diff 全绿且 coverage 达标；review 证明 SnapshotMode None/AGT-02-only 仍走 legacy prune、CLI persist failure 来自 production filesystem，且实现未新增 Cargo feature、公开/隐藏 fault API、hidden flag/env。Verify: `python3 checks/check_workflow.py --repo . --spec-dir specs/GH106 && python3 checks/check_workflow.py --repo . --all-specs && cargo fmt --all -- --check && cargo check --workspace --all-targets && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace --all-targets && cargo run --quiet -p argus-cli -- corpus test --corpus corpus && cargo llvm-cov -p argus-agent -p argus-cli --summary-only && git diff --check origin/main...HEAD`.
  File ownership: none（只读验证；不得与 Cargo 写入任务并发）.
  Targeted/all-spec、fmt/check/clippy/workspace tests、agent corpus、
  coverage 与 diff hygiene 均以最终 HEAD fresh 通过；新代码行 ≥80%，
  schema/hash/atomic/fail-closed 关键路径 100%；product ID 集合与 `Covers:`
  并集均为 B-001..B-010。

## 并行拆分

- SP106-T1 与任何其他写入任务不并行：它先独占
  `atomic_write.rs`、`baseline.rs`、`lib.rs` 完成 shared writer 抽取与 module
  registration；完成并通过 targeted tests 后，`baseline.rs` ownership 串行
  移交 T2，`lib.rs` ownership 也串行移交 T2。
- SP106-T2 依赖 T1，接管 `baseline.rs`/`lib.rs`，注册 snapshot core，并与
  `injection.rs` 一起补齐 `InventoryOnly` exhaustive no-op；core unit tests
  通过后，`lib.rs` ownership 串行移交 T3，`baseline.rs` 不再修改。T3 再独占
  `lib.rs` 与 `gh106_snapshot.rs`/fixtures 接入 collector 和 compatibility
  regression。这些 ownership transfer 不是并行共享写。
- SP106-T4 独占 `sarif.rs` 并冻结 renderer API；完成后 SP106-T5 才在
  `main.rs`/`agent.rs` 与单独 integration test 接线，不回写 `sarif.rs`。
- SP106-T6 仅写 README，可在 T5 通过 targeted CLI tests 后执行。
- SP106-T7 是唯一 verification owner，不修改文件，也不与写入任务或其他 Cargo
  进程并发。若实际实现需要 manifest 外路径，先停止并修订/批准 spec，不能越界。

## 验证

Product invariant 集合
`{B-001,B-002,B-003,B-004,B-005,B-006,B-007,B-008,B-009,B-010}` 与任务
`Covers:` 并集必须完全一致。实现完成后按 SP106-T7 的顺序运行 fresh 命令，
并记录最终 HEAD；不得复用旧输出，不得通过削弱断言绕过 failure fixture。

## Handoff Notes

- GH-106 当前为 open 且带 `ready_to_implement` label；SpecRail implement gate
  仍要求维护者确认本次修订后的 spec approval 与 duplicate evidence，不能把
  label 当作自动批准。
- CLI 选择两个最小且明确的新 flag：`--check-snapshot` 与
  `--update-snapshot`。初次创建也是显式 update；不再引入第三个 create flag。
- 唯一允许的 AGT-02/04 组合是两个只读 check。任一 update 与其他 persistence
  flag 冲突，因为两个 trust artifact 不能在一个命令中原子批准。
- snapshot inventory 先于语义扫描是刻意的：既保留当前 protected symlink
  hard error，又保证 symlink diff 不因后续 `Err` 被静默丢弃。
- update 的 normal renderer/exit 必须严格 happens-after atomic persist；任一
  persist fault 都复用 partial envelope/SARIF/text，不能先打印 bare clean。
- `SurfaceKind::InventoryOnly` 是单一 membership 闭集内的 no-semantic 类别；
  `baseline.rs`/`injection.rs` 显式 no-op，`lib.rs` 在任何正文与 validation 前
  跳过。无 snapshot 默认扫描的 binary/oversized/symlink regression 必须锁定。
- Discovery 按 mode 分流：None/AGT-02-only 必须保留 legacy
  `.git`/`node_modules` pruning；Check/Update 才 complete-discover。snapshot
  inventory 按正交 entry_type/surface_kind 收集全部 classified entry，semantic
  projection 按 directory → InventoryOnly → unclassified → legacy semantic
  symlink/file。classified snapshot target 不是合法 self-exclusion：root 内
  Some 一律在 load/render/write 前拒绝。
- 五阶段 fault injection 只存在于 `argus-agent` 私有 unit tests；CLI 只能用
  root 外 non-empty directory destination 触发 production Persist failure，
  禁止 feature、公开/隐藏 API、hidden flag/env。
- 空 inventory 是合法且完整的状态，不是 fail-closed 错误；实现必须锁定四项
  transition：empty→file/directory 为 added，empty→symlink 为
  symlink-changed，file/directory→empty 为 removed，symlink→empty 为
  symlink-changed。只有 missing、malformed 或 incomplete traversal 才
  operational failure。
- `crates/argus-agent/tests/integration.rs` 已超过 750 行，因此 GH-106 使用新的
  `gh106_snapshot.rs`，不得继续把 heavy-tier matrix 塞入旧文件。

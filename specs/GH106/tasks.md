# Task Plan

## Linked Issue

GH-106

## Spec Packet

- Product: `product.md`
- Tech: `tech.md`

## 实现任务

- [ ] `SP106-T1` 抽取 shared atomic byte writer，并让 AGT-02 baseline 改用它。Covers: B-006, B-010. Owner: persistence worker. Dependencies: none. Done when: 五阶段故障均保留旧 destination，AGT-02 bytes 不变，baseline exhaustive match 显式忽略 InventoryOnly。Verify: `cargo test -p argus-agent atomic_write_fault_matrix && cargo test -p argus-agent baseline`.
  File ownership:
  `crates/argus-agent/src/atomic_write.rs`,
  `crates/argus-agent/src/baseline.rs`. Production 路径保持
  tempfile → write → flush → file sync → persist；test-only
  `CreateTemp/Write/Flush/FileSync/Persist` 故障矩阵逐项证明旧 destination
  bytes/mtime 不变、missing destination 不产生半文件、无 tempfile 泄漏；AGT-02
  序列化 bytes 与现状相同；`SurfaceKind::InventoryOnly` 在 baseline extraction
  中显式 no-op。

- [ ] `SP106-T2` 实现 strict v1 schema、canonical inventory、全字节 hash、五类 Medium rule 与单一 surface membership。Covers: B-001, B-002, B-003, B-005, B-008, B-010. Owner: inventory worker. Dependencies: SP106-T1. Done when: InventoryOnly 单一类别、默认扫描兼容、合法空 snapshot、双向 transition、全字节/隐私/schema/fail-closed/rule 矩阵通过。Verify: `cargo test -p argus-agent --test gh106_snapshot && cargo test -p argus-agent surface`.
  File ownership:
  `crates/argus-agent/src/injection.rs`,
  `crates/argus-agent/src/snapshot.rs`,
  `crates/argus-agent/src/surface.rs`,
  `crates/argus-agent/tests/gh106_snapshot.rs`,
  `crates/argus-agent/tests/fixtures/agt04-snapshot-base/AGENTS.md`,
  `crates/argus-agent/tests/fixtures/agt04-snapshot-base/.claude/settings.json`,
  `crates/argus-agent/tests/fixtures/agt04-snapshot-base/.claude/rules/policy.txt`,
  `crates/argus-agent/tests/fixtures/agt04-snapshot-base/.cursorrules`.
  Snapshot 模块不含高上下文路径名单；所有
  membership 来自扩展后的 `surface::classify`；multi-chunk binary file hash 到
  EOF，snapshot 自身排除；symlink 仅存 raw-target SHA-256；严格 schema/path/
  UTF-8/race/incomplete 错误全部 fail closed；合法 `entries: {}` round-trip；
  空集合 transition 四项分别为 file/directory added、symlink
  symlink-changed、file/directory removed、symlink symlink-changed；同 path
  按 symlink → add/remove → type → content 优先级只产生一个固定 rule；
  evidence 逐字节匹配 B-003 无空格分号 grammar，`change=` 只允许
  `entry_added|entry_removed|content_modified|entry_type_changed|symlink_changed`
  并与五个 rule 一一映射，且所有值无 escaping。`surface::classify` 新 shape
  只返回 `InventoryOnly`，既有 shape 保持原 kind；AGT-04 收集所有 Some，
  injection exhaustive match 对 InventoryOnly 显式 no-op。

- [ ] `SP106-T3` 接入两阶段 semantic collector、SnapshotMode 与 persist-before-render outcome。Covers: B-003, B-004, B-005, B-007, B-009, B-010. Owner: agent orchestration worker. Dependencies: SP106-T1, SP106-T2. Done when: InventoryOnly 在正文/validation 前跳过，report 留内存直至 persist，semantic/judge/persist error 均返回 partial outcome。Verify: `cargo test -p argus-agent --test gh106_snapshot && cargo test -p argus-agent`.
  File ownership: `crates/argus-agent/src/lib.rs`.
  Metadata-only discovery/classify 后在任何正文/binary/UTF-8/size/symlink
  validation 前跳过 InventoryOnly；既有 semantic kinds 的行为不变。check 完成
  compare 后才跑 injection/capability/config/AGT-02/judge；update report/decision
  只存内存，atomic persist 成功后才能交给 normal renderer；semantic/judge/
  persist error 返回携带内存 report/findings 的 incomplete outcome。

- [ ] `SP106-T4` 为 semantic/judge/persist incomplete outcome 增加 SARIF 失败 invocation，保留 results 且不泄露敏感内容。Covers: B-004, B-006, B-008. Owner: SARIF worker. Dependencies: SP106-T3. Done when: 所有 partial invocation 为 false、finding 不丢不重复且 notification 无敏感内容。Verify: `cargo test -p argus-cli sarif_snapshot_incomplete && cargo test -p argus-cli sarif`.
  File ownership: `crates/argus-cli/src/sarif.rs`. Complete report 仍为
  `executionSuccessful=true`；partial report 为
  `false` 并有 sanitized error notification；AGT-04 results 只出现一次，
  decision 为 block，target/plaintext 不出现在 document。

- [ ] `SP106-T5` 接入精确 Clap/handler、persist-before-render 与 text/JSON/SARIF/exit 行为。Covers: B-004, B-006, B-007, B-008, B-009. Owner: CLI worker. Dependencies: SP106-T3, SP106-T4. Done when: fault-injected persist failure 从未调用 normal renderer/exit，三种 partial 输出与成功顺序、flags/readonly/兼容均通过。Verify: `cargo test -p argus-cli --test agent_snapshot_cli`.
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
  update report 先留内存；CreateTemp/Write/Flush/FileSync/Persist fault-injection
  均断言 old bytes/mtime、no normal render/exit、partial outputs、sanitized
  stderr/exit 2。仅 persist 成功后输出 normal report 与固定 entry count，且不把
  semantic block/approval 强制改为 exit 0。

- [ ] `SP106-T6` 更新 AGT-04 用户文档。Covers: B-004, B-006, B-007, B-008, B-009, B-010. Owner: docs worker. Dependencies: SP106-T5. Done when: workflow/rules/共存/批准/存放/persist-before-render/InventoryOnly 默认兼容/partial 限制完整且移除 follow-up 表述。Verify: `rg -n "check-snapshot|update-snapshot|AGT-04-(entry|content|symlink)" README.md && cargo test -p argus-cli --test agent_snapshot_cli`.
  File ownership: `README.md`. 文档给出安装前
  `--update-snapshot` → 安装 → 安装后
  `--check-snapshot` 示例、AGT-02 共存矩阵、五个 rule/Medium 决策、snapshot
  外置/版本控制建议、schema/platform 与并发限制、partial operational
  semantics；移除“AGT-04 remains follow-up”。

- [ ] `SP106-T7` 执行 fresh 全量门禁并提交实现证据。Covers: B-001, B-002, B-003, B-004, B-005, B-006, B-007, B-008, B-009, B-010. Owner: verification owner. Dependencies: SP106-T1, SP106-T2, SP106-T3, SP106-T4, SP106-T5, SP106-T6. Done when: 最终 HEAD 的 targeted/all-spec/Rust/corpus/coverage/diff 全绿且 coverage 达标。Verify: `python3 checks/check_workflow.py --repo . --spec-dir specs/GH106 && python3 checks/check_workflow.py --repo . --all-specs && cargo fmt --all -- --check && cargo check --workspace --all-targets && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace --all-targets && cargo run --quiet -p argus-cli -- corpus test --corpus corpus && cargo llvm-cov -p argus-agent -p argus-cli --summary-only && git diff --check origin/main...HEAD`.
  File ownership: none（只读验证；不得与 Cargo 写入任务并发）.
  Targeted/all-spec、fmt/check/clippy/workspace tests、agent corpus、
  coverage 与 diff hygiene 均以最终 HEAD fresh 通过；新代码行 ≥80%，
  schema/hash/atomic/fail-closed 关键路径 100%；product ID 集合与 `Covers:`
  并集均为 B-001..B-010。

## 并行拆分

- SP106-T1 与任何其他写入任务不并行：T2/T3 都依赖 shared writer 契约。
- SP106-T2 完成后，SP106-T3 串行接入；二者文件不重叠，但 T3 依赖已冻结 API。
- SP106-T4 独占 `sarif.rs`；完成后 SP106-T5 才写 CLI 与单独 integration test。
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
- 空 inventory 是合法且完整的状态，不是 fail-closed 错误；实现必须锁定四项
  transition：empty→file/directory 为 added，empty→symlink 为
  symlink-changed，file/directory→empty 为 removed，symlink→empty 为
  symlink-changed。只有 missing、malformed 或 incomplete traversal 才
  operational failure。
- `crates/argus-agent/tests/integration.rs` 已超过 750 行，因此 GH-106 使用新的
  `gh106_snapshot.rs`，不得继续把 heavy-tier matrix 塞入旧文件。

# Task Plan

## Linked Issue

GH-106

## Spec Packet

- Product: `product.md`
- Tech: `tech.md`

## 实现任务

- [ ] `SP106-T1` 抽取 shared atomic byte writer，并让 AGT-02 baseline 改用它。Covers: B-006. Owner: persistence worker. Dependencies: none. Done when: 五阶段故障均保留旧 destination 且 AGT-02 bytes 不变。Verify: `cargo test -p argus-agent atomic_write_fault_matrix && cargo test -p argus-agent baseline`.
  File ownership:
  `crates/argus-agent/src/atomic_write.rs`,
  `crates/argus-agent/src/baseline.rs`. Production 路径保持
  tempfile → write → flush → file sync → persist；test-only
  `CreateTemp/Write/Flush/FileSync/Persist` 故障矩阵逐项证明旧 destination
  bytes/mtime 不变、missing destination 不产生半文件、无 tempfile 泄漏；AGT-02
  序列化 bytes 与现状相同。

- [ ] `SP106-T2` 实现 strict v1 schema、canonical inventory、全字节 hash、五类 Medium rule 与单一 surface membership。Covers: B-001, B-002, B-003, B-005, B-008, B-010. Owner: inventory worker. Dependencies: SP106-T1. Done when: membership 单一来源、全字节/隐私/schema/fail-closed/rule 优先级矩阵通过。Verify: `cargo test -p argus-agent --test gh106_snapshot && cargo test -p argus-agent surface`.
  File ownership:
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
  UTF-8/empty/race 错误全部 fail closed；同 path 按 symlink → add/remove →
  type → content 优先级只产生一个固定 rule。

- [ ] `SP106-T3` 在 agent crate 接入 SnapshotMode、冻结 inventory → semantic → optional persist 顺序，并保留 partial finding。Covers: B-003, B-004, B-005, B-007, B-009. Owner: agent orchestration worker. Dependencies: SP106-T1, SP106-T2. Done when: 成功顺序固定，hard error 保留 diff，失败 update 不写且 decision 不降级。Verify: `cargo test -p argus-agent --test gh106_snapshot && cargo test -p argus-agent`.
  File ownership: `crates/argus-agent/src/lib.rs`.
  check 完成 compare 后才跑 injection/capability/config/AGT-02/judge；成功时既有
  finding 顺序不变、AGT-04 按路径追加；protected symlink/judge hard error
  返回携带已完成 AGT-04 finding 的 incomplete outcome；update 仅在所有扫描
  完整后调用 atomic writer，且不压低已有 decision。

- [ ] `SP106-T4` 为 incomplete snapshot outcome 增加 SARIF 失败 invocation，保留 results 且不泄露敏感内容。Covers: B-004, B-008. Owner: SARIF worker. Dependencies: SP106-T3. Done when: partial invocation 为 false、finding 不丢不重复且 notification 无敏感内容。Verify: `cargo test -p argus-cli sarif_snapshot_incomplete && cargo test -p argus-cli sarif`.
  File ownership: `crates/argus-cli/src/sarif.rs`. Complete report 仍为
  `executionSuccessful=true`；partial report 为
  `false` 并有 sanitized error notification；AGT-04 results 只出现一次，
  decision 为 block，target/plaintext 不出现在 document。

- [ ] `SP106-T5` 接入精确 Clap/handler 契约与 text/JSON/SARIF/exit 行为。Covers: B-004, B-007, B-008, B-009. Owner: CLI worker. Dependencies: SP106-T3, SP106-T4. Done when: help/互斥/单路径/AGT-02 check 共存、readonly、partial 与 update exit 契约全部通过。Verify: `cargo test -p argus-cli --test agent_snapshot_cli`.
  File ownership:
  `crates/argus-cli/src/main.rs`,
  `crates/argus-cli/src/agent.rs`,
  `crates/argus-cli/tests/agent_snapshot_cli.rs`. Help 只新增
  `--check-snapshot <FILE>` 与
  `--update-snapshot <FILE>`；check+check (`--baseline` + `--check-snapshot`)
  成功，其余 update/persistence 组合由 Clap 和 handler 双重拒绝；所有
  persistence mode 拒绝多 PATH；check 前后 snapshot bytes/mtime 相同；
  partial text/JSON/SARIF 保留 finding、stderr 报 operational error、exit 2；
  update 写成功打印固定 entry count，但不把 semantic block/approval 强制改为
  exit 0。

- [ ] `SP106-T6` 更新 AGT-04 用户文档。Covers: B-007, B-008, B-009, B-010. Owner: docs worker. Dependencies: SP106-T5. Done when: workflow/rules/共存/批准/存放/partial 限制完整且移除 follow-up 表述。Verify: `rg -n "check-snapshot|update-snapshot|AGT-04-(entry|content|symlink)" README.md && cargo test -p argus-cli --test agent_snapshot_cli`.
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
- `crates/argus-agent/tests/integration.rs` 已超过 750 行，因此 GH-106 使用新的
  `gh106_snapshot.rs`，不得继续把 heavy-tier matrix 塞入旧文件。

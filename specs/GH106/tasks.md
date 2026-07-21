# Task Plan

## Linked Issue

GH-106

## Spec Packet

- Product: `product.md`
- Tech: `tech.md`

## 实现任务

- [ ] `SP106-T1` 新增 `crates/argus-agent/src/snapshot.rs`：定义版本化 `Snapshot` / `Entry` / `EntryKind`，实现确定性序列化与严格版本校验的 `load`，并复用 `baseline::save` 的临时文件 → flush → sync → 原子 persist 写入范式。Covers: B-001, B-002, B-006, B-008. Owner: implementation worker. Dependencies: none. Done when: 同一输入重复序列化逐字节一致；未知版本 `load` 返回错误而非按当前版本解释；写入任一阶段失败保留旧 snapshot 且清理临时文件；序列化结果不含文件正文。Verify: `cargo test -p argus-agent snapshot_deterministic && cargo test -p argus-agent snapshot_version && cargo test -p argus-agent snapshot_atomic_update && cargo test -p argus-agent snapshot_no_plaintext`.
- [ ] `SP106-T2` 实现集合比较，产生新增、删除、内容修改、条目类型变化与 symlink 变化五类 finding，各带逻辑路径、变化类型与旧/新 digest。Covers: B-003, B-008. Owner: implementation worker. Dependencies: SP106-T1. Done when: 离线 fixture 覆盖五类变化及“无变化”，symlink 目标变化与内容修改产生不同 rule id，输出仅含路径/digest/类型。Verify: `cargo test -p argus-agent snapshot_change_kinds`.
- [ ] `SP106-T3` 实现 fail-closed 语义：snapshot 缺失、解析失败、版本不受支持、目标不可读、遍历不完整均产生显式 operational error 结论，不得报告 clean。Covers: B-005, B-002. Owner: implementation worker. Dependencies: SP106-T1. Done when: 五类失败各有测试，且断言结论不是 clean、不是“无变化”。Verify: `cargo test -p argus-agent snapshot_fail_closed`.
- [ ] `SP106-T4` 扩展 `surface.rs` 的高上下文路径形状以覆盖 `.cursorrules` 等 issue 列出的输入，并让 AGT-04 的成员集合完全由该分类决定。Covers: B-010. Owner: implementation worker. Dependencies: none. Done when: AGT-04 内不存在第二份路径清单；新增路径形状同时对既有 AGT-01 生效或显式说明为何不生效。Verify: `cargo test -p argus-agent surface`.
- [ ] `SP106-T5` 接入 CLI：新增 snapshot / check / update 模式开关，模式互斥，沿用既有 baseline 多路径守卫；check 严格只读，update 为显式批准动作。Covers: B-004, B-007, B-009. Owner: implementation worker. Dependencies: SP106-T1, SP106-T2, SP106-T3. Done when: check 后 snapshot 文件 mtime 与内容不变；多路径在 AGT-04 模式下被拒绝；check 与 update 不能同时指定。Verify: `cargo test -p argus-cli agt04 && cargo test -p argus-cli agt04_approval`.
- [ ] `SP106-T6` 接入 JSON / text / SARIF 输出并更新 README：文档化审批边界、推荐的“安装前 snapshot → 安装 → 安装后 check”流程、snapshot 存放位置建议与能力限制。Covers: B-003, B-008, B-009. Owner: implementation worker. Dependencies: SP106-T2, SP106-T5. Done when: 三种输出都保留变化类型与旧/新 digest 且不含正文；README 说明 snapshot 本身是信任锚点。Verify: `cargo test -p argus-cli sarif && cargo test --workspace --all-targets`.
- [ ] `SP106-T7` 运行完整验证。Covers: B-001, B-004, B-005, B-010. Owner: verification owner. Dependencies: SP106-T1, SP106-T2, SP106-T3, SP106-T4, SP106-T5, SP106-T6. Done when: 工作区测试、corpus 门禁与工作流检查全部通过，既有 AGT-01/02/03/05 行为无回归。Verify: `cargo test --workspace --all-targets && cargo clippy --workspace --all-targets && python3 checks/check_workflow.py --repo . --spec-dir specs/GH106`.

## 并行拆分

- SP106-T1 独占 `crates/argus-agent/src/snapshot.rs`。
- SP106-T2 与 SP106-T3 都在 `snapshot.rs` 内实现，与 SP106-T1 文件重叠，
  必须串行提交。
- SP106-T4 独占 `crates/argus-agent/src/surface.rs`，可与 T1 并行。
- SP106-T5 独占 `crates/argus-cli/src/agent.rs`；SP106-T6 独占
  `crates/argus-cli/src/sarif.rs` 与 `README.md`，二者文件不重叠。
- SP106-T7 为串行 verification owner，不与写入任务并发运行 Cargo。

## 验证

Product invariant 集合
`{B-001,B-002,B-003,B-004,B-005,B-006,B-007,B-008,B-009,B-010}` 必须与任务
`Covers:` 并集一致。运行
`python3 checks/check_workflow.py --repo . --spec-dir specs/GH106`、
`cargo test --workspace --all-targets` 与 `cargo clippy --workspace --all-targets`。

## Handoff Notes

- 本规格为 spec-only。Issue #106 尚未设置 readiness 标签，实现开始前
  维护者需先选择 `ready_to_spec` / `ready_to_implement` 等路由状态。
- snapshot 本身是信任锚点：若它可被安装脚本写入则保护失效。实现必须在
  README 中给出存放位置建议，维护者需确认这一威胁模型表述是否足够。
- AGT-04 的失败语义严格于 AGT-02：AGT-02 把缺失 baseline 转为 info finding
  是可接受的，AGT-04 缺失 snapshot 必须是显式失败。若维护者希望二者一致，
  必须先修订 B-005，而不是在实现中放宽。
- digest 算法需与既有 baseline 保持一致，避免两套强度不同的完整性保证；
  具体算法在实现前确认。

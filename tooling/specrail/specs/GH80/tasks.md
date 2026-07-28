# Task Plan

## Linked Issue

GH-80

## Spec Packet

- Product: `product.md`
- Tech: `tech.md`

## 实现任务

- [x] `SP80-T1` 固定 source commit 并审计路径冲突。Covers: B-002, B-008。Owner: coordinator。Dependencies: none。Done when: 来源 SHA 与保留清单写入 spec，冲突已逐项决策。Verify: source `rev-parse HEAD` 与文件列表交集检查。
- [x] `SP80-T2` 复制完整 workflow pack 与依赖闭包。Covers: B-001, B-002, B-008。Owner: coordinator。Dependencies: SP80-T1。Done when: pack 文件进入 GH80 branch、consumer adaptations 已记录且 Argus 原文件未修改。Verify: `git diff --name-status origin/main...HEAD` 与 `git diff --check`。
- [x] `SP80-T3` 接入独立 workflow-check CI。Covers: B-007。Owner: coordinator。Dependencies: SP80-T2。Done when: Rust CI 与 workflow check 同时存在。Verify: 检查两个 workflow 文件。
- [x] `SP80-T4` 运行 pack、schema、template、skills-lock、adoption manifest 与全部 packet 验证。Covers: B-001, B-003, B-008。Owner: verification_owner。Dependencies: SP80-T2。Done when: pack check、manifest、`--all-specs` 与完整 pytest 零退出。Verify: `check_workflow.py`、`verify_specrail_adoption.py`、`--all-specs`、pytest。
- [ ] `SP80-T5` 对当前 PR 与 runtime checkpoint 做 gate smoke。Covers: B-004, B-005, B-006。Owner: verification_owner。Dependencies: SP80-T4。Done when: evidence 与 gates 产生可解释 decision，缺失证据不被允许。Verify: `github_pr_evidence.py`、`pr_gate.py`、`runtime_ledger_gate.py`。
- [ ] `SP80-T6` 运行 Rust 回归并完成独立 reviewer/merge gate。Covers: B-002, B-007。Owner: verification_owner + reviewer。Dependencies: SP80-T3, SP80-T5。Done when: Rust 检查、CI、threads 与 PR gate 都绑定当前 head。Verify: cargo check/test 与 GitHub CI/GraphQL/pr_gate。

## 并行拆分

pack 复制与共享验证依赖同一 branch，串行执行。只读 source 清单研究可与
spec 写作并行；最终 reviewer 为独立只读 lane，不拥有文件。

## 验证

- Product invariant 集：B-001..B-008。
- Task Covers 并集：B-001..B-008。
- `check_workflow.py`、`--all-specs`、pytest、Rust check/test 均需有新输出。
- 当前 PR evidence、PR gate、runtime ledger gate 与 review threads 需刷新。

## Handoff Notes

- SpecRail 采用来源固定为 `f3251fe27e13a61c73304dbe001b1d9091c948e2`。
- 不覆盖 Argus README、LICENSE、CHANGELOG、既有 docs/specs 或 Rust CI。
- gate smoke 的 decision 可以是 `needs_human`/`blocked`，但不得因工具缺失而失败，
  也不得把缺失证据误报为 `allowed`。

# Tasks — GH-58 agent-skill 回归语料 + 标注 worklist

- [x] `SP58-T1` 新增六个合成 agent fixtures。Owner: corpus。Done when: 3 block、1 injection、2 negative fixture 均存在且 host 为 `.example.invalid`。Verify: 检查 `corpus/agent/fixtures/` 与 host。
- [x] `SP58-T2` 新增 agent corpus index。Owner: corpus。Done when: `schemaVersion: 1`、`surface: agent-skill` 且包含六个 case。Verify: Python JSON load。
- [x] `SP58-T3` 提交 849 行真实命中标注 worklist。Owner: corpus。Done when: JSONL 行数为 849 且保留上下文与空 label。Verify: `wc -l corpus/agent/labeling-worklist.jsonl`。
- [x] `SP58-T4` 提交 census 方法与结果。Owner: docs。Done when: 数据来源、方法和数字可审计。Verify: 人工阅读 `corpus/agent/census.md`。
- [ ] `SP58-T5` 让 corpus runner 发现 agent index。Owner: CLI crate。Done when: runner 同时执行 npm 与 agent corpus。Verify: `cargo run -p argus-cli -- corpus test --corpus corpus`。
- [ ] `SP58-T6` CI 断言两个负例非 block。Owner: CI/verification。Done when: benign installer 为 allow、benign net tool 为 allow-with-approval。Verify: corpus test 输出。

## Spec Packet

- Product: `product.md`
- Tech: `tech.md`

## Parallelization

Task 1-4 为纯文件新增，本 PR 已完成。Task 5-6 需改 `argus corpus` 的发现
逻辑（Rust 侧），由 maintainer 在实现 PR 中完成，文件所有权：`corpus/` 命令
相关 crate，与本 spec 包不重叠。

## Verification

- JSON load 已验证 `corpus/agent/index.json`。
- host 检查确认全部使用 `.example.invalid`。
- 端到端 corpus test 依赖 SP58-T5。

## Handoff Notes

- 6 个 fixture 照真实普查暴露的攻击/FP 形状写成，非真实 skill 拷贝。
- 两个负例是本语料的重点：它们锁死"检测器不得误杀合法安装器/API 工具"。
- worklist 的 `label` 字段留空，人工标注（TP/FP/needs-context）后喂给 GH-59
  计算词法层 precision/recall。
- Task 5-6 是 Rust 接线，本 spec-first PR 不含实现代码；实现走 GH-59 或独立
  impl PR。

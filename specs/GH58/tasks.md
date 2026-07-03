# Tasks — GH-58 agent-skill 回归语料 + 标注 worklist

| # | Task | Verify | Status |
| --- | --- | --- | --- |
| 1 | 新增 `corpus/agent/fixtures/` 6 个合成 fixture（3 block / 1 注入 / 2 负例） | 目录结构存在，host 全 `.example.invalid` | done |
| 2 | 新增 `corpus/agent/index.json`（schemaVersion:1, surface:agent-skill, 6 cases） | `python3 -c 'json.load'` 通过 | done |
| 3 | 提交 `corpus/agent/labeling-worklist.jsonl`（849 条真实命中带上下文） | 行数 = 849 | done |
| 4 | 提交 `corpus/agent/census.md`（普查方法学 + 数字） | 文档可复现 | done |
| 5 | `corpus test` runner 发现 `corpus/agent/index.json` | `cargo run -p argus-cli -- corpus test` 全绿 | todo（maintainer 侧接线） |
| 6 | CI 断言两负例非 block | `corpus test` 中 benign-* 判决 = allow / allow-with-approval | todo |

## Spec Packet

- Product: `product.md`
- Tech: `tech.md`

## Parallelization

Task 1-4 为纯文件新增，本 PR 已完成。Task 5-6 需改 `argus corpus` 的发现
逻辑（Rust 侧），由 maintainer 在实现 PR 中完成，文件所有权：`corpus/` 命令
相关 crate，与本 spec 包不重叠。

## Verification

- [x] `json.load(corpus/agent/index.json)` 通过
- [x] `grep -rn` 确认所有 host 为 `.example.invalid`
- [ ] `argus corpus test` 端到端（依赖 Task 5 接线）

## Handoff Notes

- 6 个 fixture 照真实普查暴露的攻击/FP 形状写成，非真实 skill 拷贝。
- 两个负例是本语料的重点：它们锁死"检测器不得误杀合法安装器/API 工具"。
- worklist 的 `label` 字段留空，人工标注（TP/FP/needs-context）后喂给 GH-59
  计算词法层 precision/recall。
- Task 5-6 是 Rust 接线，本 spec-first PR 不含实现代码；实现走 GH-59 或独立
  impl PR。

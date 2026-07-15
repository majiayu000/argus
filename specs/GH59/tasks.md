# Tasks — GH-59 能力清单 + 意图-能力错配检测

- [ ] `SP59-T1` 将词法层降级为候选粗筛。Owner: agent lexical rules。Done when: AGT-01/03/05 不再单独承担最终恶意判定且现有单测不回归。Verify: `cargo test -p argus-agent`。
- [ ] `SP59-T2` 提取 shell 脚本能力。Owner: agent capability。Done when: shell 正负例产生稳定 manifest。Verify: capability focused tests。
- [ ] `SP59-T3` 提取 Python 与 JS/TS 脚本能力。Owner: agent capability。Done when: 各语言正负例产生稳定 manifest。Verify: capability focused tests。
- [ ] `SP59-T4` 解析静态 host 并输出 unresolved signal。Owner: agent capability。Done when: 字面 host 与无法解析的拼接均有测试。Verify: host-resolution tests。
- [ ] `SP59-T5` 将 manifest 字段接入 JSON 输出。Owner: core + CLI。Done when: JSON 含 capability/evidence/resolved_host。Verify: schema 与 snapshot tests。
- [ ] `SP59-T6` 从 frontmatter/description 提取意图粗类。Owner: agent intent。Done when: 意图分类单测通过。Verify: intent focused tests。
- [ ] `SP59-T7` 实现意图-能力错配三档判决。Owner: agent decision。Done when: GH58 六个 fixture 全部符合 expected decision。Verify: `cargo run -p argus-cli -- corpus test --corpus corpus`。
- [ ] `SP59-T8` 在冻结且人工标注的评估集上计算指标。Owner: evaluation。Done when: 评估契约明确且 PR 报告可识别的 precision/recall 数字。Verify: 复验评估输入、标签、预测与计算结果。
- [ ] `SP59-T9` 增加可选 `--llm-judge`。Owner: CLI + agent judge。Done when: 默认关闭且确定性核心不依赖网络/LLM。Verify: 关闭态重复扫描输出一致。

## Spec Packet

- Product: `product.md`
- Tech: `tech.md`

## Parallelization

- Task 2/3/4（能力提取，按语言）文件所有权互不重叠，可并行。
- Task 6/7（意图 + 错配）依赖 Task 2-5 的 manifest 输出，串行在后。
- Task 8 依赖 GH-58 worklist 完成人工标注（外部前置）。
- 文件所有权：新增 `argus-agent` 内 capability 子模块；Task 1 改词法模块，
  与 capability 子模块不共写。

## Verification

- corpus test 必须覆盖 GH58 六个 fixture，两负例保持非 block。
- 评估指标必须有冻结输入、标签与预测证据。
- `--llm-judge` 关闭时输出必须确定性可复现。

## Handoff Notes

- **前置**：GH-58 语料 PR（#60）合并 + worklist 完成人工标注，Task 7/8 才有
  验收锚。
- 核心原则：能力**陈述**与判决**分离**——出现能力不等于 block，只有意图错配
  或高危组合才升级。benign-net-tool 是这条原则的守门 fixture。
- LLM 判官是可选增强，不得进确定性核心，避免破坏可复现与离线可用。
- 分阶段合并：L2 清单先行（低风险陈述层），L3 错配后行（改 verdict，需
  eval 数字）。

# Tasks — GH-59 能力清单 + 意图-能力错配检测

| # | Task | Verify | Status |
| --- | --- | --- | --- |
| 1 | 词法层降级为粗筛（AGT-01/03/05 输出候选信号而非终判） | 现有单测不回归 | todo |
| 2 | L2 能力提取：shell（tree-sitter-bash） | 单测正负例 | todo |
| 3 | L2 能力提取：python + js/ts | 单测正负例 | todo |
| 4 | host 静态解析 + `unresolved_host` 信号 | 单测：字面/拼接 | todo |
| 5 | manifest JSON schema 接入 `--format json` | schema 校验 + 快照测试 | todo |
| 6 | L3 意图粗类分类（frontmatter/description → 类别） | 单测 | todo |
| 7 | L3 意图-能力错配规则 + 三档判决 | `corpus test` 过 GH-58 6 fixture | todo |
| 8 | 在 GH-58 worklist（人工标注后）算 precision/recall | 数字写进 PR | todo |
| 9 | 可选 `--llm-judge` 增强层（默认关，核心确定性） | 关闭态输出确定 | todo |

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

- [ ] `corpus test` 过 GH-58 全部 6 fixture，两负例保持非 block
- [ ] precision/recall 在标注 worklist 上有具体数字
- [ ] `--llm-judge` 关闭时确定性可复现

## Handoff Notes

- **前置**：GH-58 语料 PR（#60）合并 + worklist 完成人工标注，Task 7/8 才有
  验收锚。
- 核心原则：能力**陈述**与判决**分离**——出现能力不等于 block，只有意图错配
  或高危组合才升级。benign-net-tool 是这条原则的守门 fixture。
- LLM 判官是可选增强，不得进确定性核心，避免破坏可复现与离线可用。
- 分阶段合并：L2 清单先行（低风险陈述层），L3 错配后行（改 verdict，需
  eval 数字）。

# Tasks — GH-59 能力清单 + 意图-能力错配检测

- [x] `SP59-T1` 将词法层降级为候选粗筛。Owner: agent lexical rules。Done when: AGT-01/03/05 不再单独承担最终恶意判定且现有单测不回归。Verify: `cargo test -p argus-agent`。Evidence: PR #63 + 当前 25 个 agent tests 通过。
- [x] `SP59-T2` 提取 shell 脚本能力。Owner: agent capability。Done when: shell 正负例产生稳定 manifest。Verify: capability focused tests。Evidence: PR #63。
- [x] `SP59-T3` 提取 Python 与 JS/TS 脚本能力。Owner: agent capability。Done when: 各语言正负例产生稳定 manifest。Verify: capability focused tests。Evidence: PR #63。
- [x] `SP59-T4` 解析静态 host 并输出 unresolved signal。Owner: agent capability。Done when: 字面 host 与无法解析的拼接均有测试。Verify: host-resolution tests。Evidence: PR #63。
- [x] `SP59-T5` 将 manifest 字段接入 JSON 输出。Owner: core + CLI。Done when: JSON 含 capability/evidence/resolved_host。Verify: schema 与 snapshot tests。Evidence: PR #63。
- [x] `SP59-T6` 从 frontmatter/description 提取意图粗类。Owner: agent intent。Done when: 意图分类单测通过。Verify: intent focused tests。Evidence: PR #63。
- [x] `SP59-T7` 实现意图-能力错配三档判决。Owner: agent decision。Done when: GH58 六个 fixture 全部符合 expected decision。Verify: `cargo run -p argus-cli -- corpus test --corpus corpus/agent`。Evidence: PR #63 + 当前 6/6 corpus 通过。
- [x] `SP59-T8` 在冻结且维护者已合并的 synthetic fixture 评估集上计算指标。Owner: evaluation。Done when: 输出数据集类型、TP/FP/FN/TN、precision/recall；真实 worklist 不伪造 recall。Verify: `cargo run -p argus-cli -- corpus eval --corpus corpus/agent --format json`。Evidence: 6 samples，TP=4/FP=0/FN=0/TN=2，synthetic precision=1.0/recall=1.0。
- [x] `SP59-T9` 增加可选 `--llm-judge`。Owner: CLI + agent judge。Done when: 默认关闭且确定性核心不依赖网络/LLM。Verify: 关闭态重复扫描输出一致。Evidence: request/response、升级不降级、缺 command、非零退出、超时、stdout/stderr 超限 tests。

## Spec Packet

- Product: `product.md`
- Tech: `tech.md`

## Parallelization

- Task 2/3/4（能力提取，按语言）文件所有权互不重叠，可并行。
- Task 6/7（意图 + 错配）依赖 Task 2-5 的 manifest 输出，串行在后。
- Task 8 使用 GH-58 已维护者合并的 6 个冻结 fixture 形成可复验的 synthetic
  指标；真实 worklist 仍依赖后续人工标注与完整负例，只能作为后续 precision
  输入，不能作为 recall 分母。
- 文件所有权：新增 `argus-agent` 内 capability 子模块；Task 1 改词法模块，
  与 capability 子模块不共写。

## Verification

- corpus test 必须覆盖 GH58 六个 fixture，两负例保持非 block。
- 评估指标必须有冻结输入、维护者合并的标签、实时预测与混淆矩阵证据，并明确
  标记 synthetic。
- `--llm-judge` 关闭时输出必须确定性可复现。

## Handoff Notes

- **评估决策**：GH-58 语料 PR（#60）已合并，6 个 fixture 的
  `expectedDecision` 是本次 synthetic eval 标签；849 行 worklist 当前 0 标签、
  0 未命中样本，禁止据此声称 recall。
- 核心原则：能力**陈述**与判决**分离**——出现能力不等于 block，只有意图错配
  或高危组合才升级。benign-net-tool 是这条原则的守门 fixture。
- LLM 判官是可选增强，不进入确定性核心；默认路径重复扫描输出一致且不启动
  外部进程。显式开启时使用无 shell 的 command path、严格 JSON、超时与双向
  输出限制，错误不静默降级。
- T1-T9 均已有实现与复验命令；真实 worklist 的人工 precision 与完整语料
  recall 仍是明确标注的后续评估，不影响本 issue 的 synthetic 验收限定。

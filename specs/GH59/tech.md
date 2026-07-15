# Tech Spec

## Linked Issue

GH-59

## Product Spec

见 `product.md`。依赖 GH-58 的语料 + worklist 作为验收基线。

## Codebase Context

| Area | Files | Current behavior | Why relevant |
| --- | --- | --- | --- |
| agent 扫描 | `argus-agent`（GH-57） | AGT-01/03/05 词法规则，输出 Finding | 词法层降级为粗筛，新增能力提取 + 错配规则 |
| 决策模型 | argus 三档 `block/allow-with-approval/allow` | 词法命中即判决 | 判决改由能力清单 + 错配驱动 |
| 语料 | `corpus/agent/`（GH-58） | 6 fixture + worklist | 错配规则的验收断言与精度测量来源 |
| JSON 输出 | `--format json` Finding 形状 | 现有 Finding schema | 扩展加入 capability manifest |
| agent 扫描编排 | `crates/argus-agent/src/lib.rs:67` | 收集 surface 后运行确定性规则并派生 decision | 在同一次安全收集上构造可选 judge request，默认路径不调用 judge |
| CLI agent 命令 | `crates/argus-cli/src/agent.rs:21` | 编排多路径扫描、baseline 与输出 | 增加显式 opt-in 的外部 judge adapter，使用 argv 路径直接启动、不经 shell |
| corpus runner | `crates/argus-cli/src/main.rs:613` | 测试 expected decision/rules；实现位于接近 800 行的 `main.rs` | 拆到 `corpus.rs` 并增加冻结 fixture 指标命令 |
| 冻结标签 | `corpus/agent/index.json:4` | 6 个 fixture 已含维护者合并的 `expectedDecision` | 声明 synthetic eval 元数据并以 `block` 为 positive label |

## Proposed Design

三层，确定性核心 + 可选增强：

```
SKILL.md + scripts
      │
      ▼
[L1 词法粗筛]  AGT-01/03/05 → 候选信号（不再是终判）
      │
      ▼
[L2 能力提取]  tree-sitter 解析 shell/python/js/ts
      │         提取：net_egress(+host), sensitive_read, agent_config_write,
      │         exec_eval, obfuscation, persistence, destructive
      │         host 静态解析；拼接变量 → unresolved_host
      ▼
[L3 意图-能力错配]  声明用途(frontmatter/description) × 能力集
      │         一致 → allow-with-approval（呈现 manifest）
      │         明确不符 / 高危组合 → block
      │         无能力 → allow
      ▼
[可选 --llm-judge]  SKILL.md 语义意图判断（默认关，核心之外）
```

`--llm-judge` 通过 `--llm-judge-command <FILE>` 调用用户明确指定的外部
可执行文件。CLI 使用 `Command::new(path)` 直接启动，不解析 shell 字符串；将
版本化 JSON request 写入 stdin，并从受大小限制的 stdout 读取严格 JSON
response。request 只含本次已安全收集的 instruction 文件与确定性 report；
response 为 `{decision, rationale}`。judge 只能新增 finding，因此不能把核心的
`block` 降级。进程失败、超限或响应无效均返回错误，不静默降级。

能力提取用 tree-sitter 各语言 grammar 走 AST 查询（比正则稳，能区分注释/
字符串/真实调用），避免普查里正则那种 FP。host 解析：字面量直接取；变量/
拼接 → `unresolved_host`（本身是信号）。

manifest JSON（扩展现有 Finding）：

```json
{
  "capability": "net_egress",
  "evidence": ["scripts/collect.sh:14"],
  "resolved_host": "collector.attacker.example.invalid"
}
```

评估命令读取 `corpus/agent/index.json` 中冻结的 6 个 fixture；label 为
`expectedDecision == block`，prediction 为实时扫描的 decision 是否为 `block`。
输出数据集类型、TP/FP/FN/TN、precision、recall。没有 actual positive 或没有
predicted positive 时必须报错，不用 0 掩盖未定义分母。该结果明确标记为
synthetic，不代替真实 worklist 的人工标注。

## Planned Changes Manifest

<!-- specrail-planned-changes
{"version":1,"issue":59,"complete":true,"paths":["README.md","corpus/agent/README.md","corpus/agent/index.json","crates/argus-agent/src/judge.rs","crates/argus-agent/src/lib.rs","crates/argus-agent/tests/integration.rs","crates/argus-cli/src/agent.rs","crates/argus-cli/src/corpus.rs","crates/argus-cli/src/main.rs","crates/argus-cli/tests/corpus.rs"],"spec_refs":["specs/GH59/product.md","specs/GH59/tech.md","specs/GH59/tasks.md"]}
-->

错配规则（确定性）：声明用途归一到粗类（formatter/docs/stats/network-tool/
installer…）× 能力白名单。formatter 出现 net_egress+sensitive_read → 错配 →
block。network-tool 出现 net_egress 到自家 host → 一致 → allow-with-approval。

## Product-to-Test Mapping

| Product invariant | Implementation area | Verification |
| --- | --- | --- |
| P1 多语言能力提取 | L2 tree-sitter | 单测：每语言正负例 |
| P2 unresolved host 不静默 | host 解析器 | 单测：变量拼接 → unresolved |
| P3 6 fixture 判决通过 | L3 错配规则 | `corpus test`（GH-58 语料） |
| P4 synthetic 指标可复验 | corpus eval | 输出 6 个 fixture 的混淆矩阵与 precision/recall，标记 synthetic |
| P5 llm-judge 默认关且确定性 | CLI flag + 外部 adapter | 关闭时同输入同输出；开启时失败/无效响应报错 |
| P6 能力陈述不改判决 | L2/L3 分离 | benign-net-tool 有能力仍非 block；judge 不得降级核心 block |

## Data Flow

输入：fixture/真实 skill 目录。L2 静态解析脚本（无执行）。L3 读 SKILL.md
frontmatter。可选 L4 把版本化 request 交给用户指定的 judge 可执行文件（默认
关；argus 自身不持有网络凭据）。输出：manifest + 三档判决。确定性路径无网络
无持久化；外部 judge 只能升级，不能覆盖确定性 finding。

## Alternatives Considered

- 继续堆正则规则：否，普查已证明 FP 天花板。
- 直接上 LLM 判决：否，破坏确定性 + 可复现，且成本/延迟不可控；LLM 仅作
  可选增强。
- 沙箱动态分析：否，超出 argus "install 前静态判定，永不执行" 的定位。

## Risks

- Security：能力提取本身只读静态，无执行面。
- Compatibility：词法层降级不得回归 AGT-01/03/05 现有单测；manifest 为 JSON
  增量字段，向后兼容。
- Performance：tree-sitter 解析比正则重，但只跑在带脚本的 <0.1% skill 上。
- Maintenance：意图粗类 × 能力白名单表需随语料演进；worklist 精度是回归锚。
- Evaluation：6 个 fixture 只证明冻结 synthetic 集上的行为，不代表真实世界
  泛化精度；输出、文档和 PR 必须保留该限定。
- External execution：仅在用户同时传入 `--llm-judge` 与明确 command path 时
  启动；不经 shell，不接受拼接参数，stdout 有上限，失败即报错。

## Test Plan

- [ ] Unit：各语言能力提取正负例；host 解析（字面/unresolved）。
- [ ] Integration：`corpus test` 过 GH-58 全部 6 fixture，两负例非 block。
- [ ] Eval：`corpus eval` 在冻结 6 fixture 上输出 synthetic 混淆矩阵与
      precision/recall；真实 worklist 不宣称 recall。
- [ ] Unit/Integration：judge request/response、无效响应、非零退出、升级但不
      降级；关闭态重复扫描输出一致。
- [ ] Manual：`--llm-judge` 缺 command 时拒绝；关闭态不启动任何外部进程。

## Rollback Plan

分阶段落地，每阶段独立可回退：L2 能力清单（陈述层）可先合、后撤不影响
词法判决；L3 错配规则以 feature 开关引入，回退即回到 GH-57 词法判决。

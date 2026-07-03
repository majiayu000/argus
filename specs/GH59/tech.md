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

错配规则（确定性）：声明用途归一到粗类（formatter/docs/stats/network-tool/
installer…）× 能力白名单。formatter 出现 net_egress+sensitive_read → 错配 →
block。network-tool 出现 net_egress 到自家 host → 一致 → allow-with-approval。

## Product-to-Test Mapping

| Product invariant | Implementation area | Verification |
| --- | --- | --- |
| P1 多语言能力提取 | L2 tree-sitter | 单测：每语言正负例 |
| P2 unresolved host 不静默 | host 解析器 | 单测：变量拼接 → unresolved |
| P3 6 fixture 判决通过 | L3 错配规则 | `corpus test`（GH-58 语料） |
| P4 llm-judge 默认关且确定性 | CLI flag | 关闭时同输入同输出 |
| P5 能力陈述不改判决 | L2/L3 分离 | benign-net-tool 有能力仍非 block |

## Data Flow

输入：fixture/真实 skill 目录。L2 解析脚本 AST（无执行）。L3 读 SKILL.md
frontmatter。可选 L4 调 LLM（唯一网络路径，默认关）。输出：manifest +
三档判决。确定性路径无网络无持久化。

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

## Test Plan

- [ ] Unit：各语言能力提取正负例；host 解析（字面/unresolved）。
- [ ] Integration：`corpus test` 过 GH-58 全部 6 fixture，两负例非 block。
- [ ] Eval：在 GH-58 worklist 标注结果上算 precision/recall，写进 PR。
- [ ] Manual：`--llm-judge` 开/关对确定性 fixture 输出一致（关闭态）。

## Rollback Plan

分阶段落地，每阶段独立可回退：L2 能力清单（陈述层）可先合、后撤不影响
词法判决；L3 错配规则以 feature 开关引入，回退即回到 GH-57 词法判决。

# Product Spec

## Linked Issue

GH-59

## 用户问题

普查（见 GH-58）证明 `argus agent scan` 的词法层无法区分恶意与良性 skill：
合法安装器、正经 API 工具触发和真实攻击相同的模式，而真正的攻击面主要是
**SKILL.md 指令文本**，不是脚本。在这一层给关键词判决 = 高误报 + 误导。

可判的信号不是"有没有坏词"，而是两层：

1. **能力清单**：静态提取一个 skill *能做什么*（网络出口 + host、
   凭据/密钥读取、agent 配置写入、exec/eval、混淆、持久化）。**陈述事实，
   不下判断**——等价于手机 App 的权限页。
2. **意图-能力错配**：把声明用途（SKILL.md frontmatter/description）和提取
   到的能力比对。一个"markdown 格式化器"却写 `~/.claude/settings` 或外发
   密钥——这才是可判的信号，block 在这里才站得住。

普查里多数"真阳性"能力命中其实良性甚至防御性（例如脚本检测到 agent 环境
反而保留确认），所以能力必须以清单呈现，`block` 只留给明确错配。

## 目标

- `argus agent scan` 对每个 skill 输出**能力清单**（`--format json` 机读）。
- 一个确定性的**意图-能力错配**规则：只有明确不符才 `block`；能力与声明
  用途一致 → `allow-with-approval`（呈现清单）；干净 → `allow`。
- 词法层降级为喂给清单的第一道粗筛，不再是最终判决。
- 可选 `--llm-judge` 增强层做 SKILL.md 语义意图，置于确定性核心之外。

## 非目标

- 确定性路径不强制依赖网络/LLM。
- 不做多 skill 组合分析、版本漂移/rug-pull 检测（后续）。
- 不做 trust badge（gated on eval 精度）。

## 行为不变量

1. 能力提取覆盖 shell + python + js/ts 脚本，输出 `{capability, evidence:
   [file:line], resolved_host?}`。
2. 无法静态解析的 host（变量拼接）产出显式 `unresolved_host` 信号，不静默。
3. 意图-能力错配规则对 GH-58 的 6 个 fixture 判决全部通过，含两负例非 block。
4. `--llm-judge` 默认关闭；关闭时 `agent scan` 完全确定性、可复现。
5. 能力清单是陈述性输出：出现能力本身不改变判决，只有错配或高危组合才升级。

## Acceptance Criteria

- [ ] 脚本能力提取（tree-sitter 或等价），含 host 静态解析 + unresolved 信号。
- [ ] JSON 清单 schema：`{capability, evidence:[file:line], resolved_host?}`。
- [ ] 意图/错配规则过全部 GH-58 fixture，两负例保持非 block。
- [ ] 在 GH-58 标注 worklist 上测出的 precision/recall 写进实现 PR。
- [ ] `--llm-judge` 可选、默认关；核心保持确定性。

## Edge Cases

- 纯文本 skill（无脚本）：只有 SKILL.md 语义信号，走注入/错配文本层。
- 能力与意图一致（weather 工具读 key 调自家 API）：allow-with-approval。
- host 变量拼接无法解析：标 unresolved，视为风险信号而非直接 block。

## Rollout Notes

分阶段：先出能力清单（陈述层，低风险，可先合），再上错配判决（改变
verdict，需 eval 数字支撑）。词法层降级需保证现有 AGT-01/03/05 单测不回归。

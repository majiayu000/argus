# Tech Spec

## Linked Issue

GH-58

## Product Spec

见 `product.md`。

## Codebase Context

| Area | Files | Current behavior | Why relevant |
| --- | --- | --- | --- |
| 语料 schema | `corpus/index.json`, `corpus/README.md` | npm 风格 fixture，`{id,path,packageName,expectedDecision,rules,notes}` | agent 语料复用同一 schema，新增 `surface` 字段 |
| corpus runner | `argus corpus test` | 遍历 `index.json`，扫每个 fixture 断言判决 | 需能加载 `corpus/agent/index.json` |
| agent 扫描 | `argus-agent`（GH-57） | AGT-01/03/05 词法规则 | fixture 的期望判决由这些规则 + 后续 GH-59 规则驱动 |

## Proposed Design

新增独立语料子树 `corpus/agent/`，与 npm 语料并列、互不影响：

```
corpus/agent/
  index.json                 # schemaVersion:1, surface:"agent-skill", 6 cases
  fixtures/
    skill-config-backdoor/   # SKILL.md + scripts/setup.sh   -> block
    skill-cred-exfil/        # SKILL.md + scripts/collect.sh -> block
    skill-obfuscated-dropper/# SKILL.md + scripts/postinstall.sh -> block
    skill-injection-md/      # SKILL.md（纯文本注入）        -> block
    skill-benign-installer/  # SKILL.md（官方安装器文档）    -> allow
    skill-benign-net-tool/   # SKILL.md + scripts/fetch.sh   -> allow-with-approval
  labeling-worklist.jsonl    # 849 条真实命中，待人工标注
  census.md                  # 普查方法学 + 数字
```

`corpus test` 增加对 `corpus/agent/index.json` 的发现（沿用现有加载逻辑，
按目录枚举或在 README 记录第二个 index 路径）。fixture 的 `expectedDecision`
覆盖三档：`block` / `allow-with-approval` / `allow`。

## Product-to-Test Mapping

| Product invariant | Implementation area | Verification |
| --- | --- | --- |
| P1 六 fixture 判决通过 | `corpus/agent/index.json` | `argus corpus test` |
| P2 两负例非 block | benign-installer / benign-net-tool | `corpus test` 断言 allow / allow-with-approval |
| P3 host 全 `.example.invalid` | 所有 fixture 内容 | `grep -r` 无真实 host |
| P4 不影响 npm 语料 | 独立子树 | 现有 `corpus test` 保持绿 |
| P5 worklist 只读 | `labeling-worklist.jsonl` | 不被 runner 加载为 case |

## Data Flow

输入：静态 fixture 目录。输出：`corpus test` 判决对比。无网络、无执行、无
持久化。worklist 为离线证据，人工填 `label` 字段后用于 GH-59 精度计算。

## Alternatives Considered

- 把 agent fixture 混进现有 `corpus/index.json`：否，会污染 npm 语料的
  独立性，且 `surface` 语义不同。
- 用真实 skill 内容做 fixture：否，含真实 host 且有版权/隐私问题；改为
  照真实攻击**形状**写合成样本。

## Risks

- Security：fixture 含攻击形状字符串，但全部 `.example.invalid` 且不执行；
  README 明确标注 synthetic。
- Compatibility：纯新增，无。
- Performance：语料 +6 case，可忽略。
- Maintenance：worklist 是一次性基线快照，标注结果进 GH-59。

## Test Plan

- [ ] Unit：`argus corpus test` 覆盖 6 个 agent fixture。
- [ ] Integration：完整 `corpus test` 同时通过 npm + agent 两套语料。
- [ ] Manual：`grep -rn 'example.invalid' corpus/agent` 确认无真实 host；
      抽查两个负例判决非 block。

## Rollback Plan

删除 `corpus/agent/` 子树并还原 `corpus test` 的发现逻辑即可，无其他耦合。

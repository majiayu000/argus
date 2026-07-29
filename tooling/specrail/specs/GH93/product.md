# Product Spec

## Linked Issue

GH-93

complexity: medium

## 用户问题

Argus 目前只输出 text 与 JSON。CI 集成必须自行转换才能上传 GitHub Code
Scanning，转换过程中容易丢失稳定 rule ID、真实文件/行号、artifact/package
坐标、decision 语义和 operational error 边界。

## 目标

- 所有扫描命令支持显式 `--format sarif`，输出 SARIF 2.1.0。
- 每个 finding 保留稳定 rule descriptor、severity、证据位置、artifact/package
  坐标和机器稳定 fingerprint。
- GitHub Code Scanning 与通用 SARIF consumer 可直接使用输出。
- 只有成功产生 `ScanReport` 后才输出 SARIF；扫描/解析/网络错误仍以 exit 2
  失败，stdout 不得伪造成 clean run。

## 非目标

- 不改变现有 text/JSON schema、finding 生成、decision 或退出码。
- 不把 SARIF renderer 变成规则注册中心，也不要求每个规则新增手写元数据。
- 不在 unit tests 中访问网络或 GitHub API。

## 行为不变量

1. B-001 `scan`、八生态 fetch 命令与 `agent scan` 必须接受闭集格式
   `text | json | sarif`；`corpus eval` 仍只接受其原有 text/JSON 格式。
2. B-002 SARIF 顶层必须声明 `$schema` 与 `version: 2.1.0`，每次输出包含一个
   Argus run 和带版本的 tool driver。
3. B-003 每个 distinct `Finding.rule_id` 必须产生唯一、稳定的 rule descriptor；
   result 使用同一 `ruleId`/`ruleIndex`，同一位置的不同 rule 不得合并。
4. B-004 Critical/High 映射为 SARIF `error`，Medium 映射 `warning`，Low/Info
   映射 `note`；映射不得改变 Argus 原始 decision 或进程退出码。
5. B-005 可解析的 `file:line` evidence 必须输出真实 `startLine`；只有 path 时
   输出 artifact-level physical location，不得伪造 line 1。
6. B-006 finding 无 source location 时必须回退到 report artifact path，并在
   properties 中保留 `artifact_kind`、`package_name`、`package_version` 与 decision。
7. B-007 每个 result 必须包含稳定 `partialFingerprints`，输入包括 rule、位置、
   artifact/package 坐标与 detail，使不同 rule 在同一位置仍有不同 fingerprint。
8. B-008 capability、resolved host 与原始 evidence 在存在时必须保留为
   machine-readable result properties。
9. B-009 package、lockfile、agent-surface 与 provenance finding 必须有离线
   snapshot/结构测试；输出需覆盖有行号、无行号、重复位置多 rule 和无 finding。
10. B-010 扫描、解析、网络或输入错误必须 exit 2 且不向 stdout 写 SARIF run；
    `block` 与 `allow-with-approval` 仍分别 exit 1 与 2，即使 SARIF 已成功输出。
11. B-011 CI smoke 必须生成无 finding 的 SARIF 并通过 GitHub 官方 upload action
    上传/验证；unit tests 不依赖该网络步骤。
12. B-012 README 必须给出本地生成、GitHub upload 与 generic consumer 用法，
    并说明 SARIF 输出不把 operational failure 表示为空结果。

## Acceptance Criteria

- [x] 输出可被 GitHub SARIF upload validator 接受为 SARIF 2.1.0。
- [x] package、lockfile、agent、provenance snapshot tests 通过。
- [x] 同位置多个 finding 保留不同 stable rule ID 与 fingerprint。
- [x] 无行号时只有 artifact-level location，不生成假行号。
- [x] operational error exit 2 且 stdout 为空。
- [x] CI 生成并上传空 finding smoke SARIF，unit tests 离线。

## Boundary Checklist

| Category | Verdict |
| --- | --- |
| Empty / missing input | covered: B-006, B-009, B-010。 |
| Error and failure paths | covered: B-010, B-012。 |
| Authorization / permission | covered: B-011（CI upload 需要 `security-events: write`，fork PR 不执行 upload）。 |
| Concurrency / race / ordering | N/A：renderer 为纯函数；CI 在生成文件后串行 upload。 |
| Retry / repetition / idempotency | covered: B-007（相同输入产生稳定 fingerprint）。 |
| Illegal state transitions | covered: B-010（错误不得转成成功 run）。 |
| Compatibility / migration | covered: B-001, B-004。 |
| Degradation / fallback | covered: B-005, B-006, B-010。 |
| Evidence and audit integrity | covered: B-003, B-005, B-007, B-008。 |
| Cancellation / interruption / partial completion | covered: B-010（未形成完整 report 时不输出 SARIF）。 |

## Edge Cases

- 一个 location 同时触发多个 rule：产生多个 result，`ruleId` 与 fingerprint 不同。
- `evidence` 含非 `file:line` 审计文字：保留 property，但不伪造 physical line。
- 多路径 `agent scan`：合并到同一 SARIF run，退出码仍由 worst decision 决定。
- clean report：合法的 run、rules/results 可为空；仅 operational error 禁止伪装成 clean。

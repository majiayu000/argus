# Product Spec

## Linked Issue

GH-94

complexity: large

## 用户问题

Argus 扫描供应链行为与完整性，但不会查询已知漏洞。用户通常仍需要另一个工具把
精确 package version 映射到 OSV advisory，并自行区分“无 advisory”“查询失败”
“生态不支持”和“结果可能不完整”。这使安装前决策缺少一个常见但语义独立的维度。

## 目标

- 提供显式 `vulns` 模式，对精确 ecosystem/name/version 查询 OSV。
- 支持单坐标与 lockfile 批量查询，复用统一 package/lockfile normalization。
- 输出 advisory ID、aliases、affected range、severity、source URL 与数据时间。
- 支持有界缓存、离线读取和明确的 freshness 信息。
- 严格区分 clean query、query failure、unsupported 与 incomplete。

## 非目标

- 不自动升级、修改 manifest/lockfile 或执行 package manager。
- 不把漏洞 advisory 等同于恶意包；GH-90 情报保持独立 rule/source。
- 不声称 OSV 覆盖所有生态或所有漏洞，也不推导未发布 exploitability。
- 不取代现有内容、provenance、integrity 与 agent 扫描。

## Behavior Invariants

1. B-001 查询输入必须是支持生态中的规范化精确坐标；缺版本、范围输入、歧义名称
   或 unsupported ecosystem 必须在联网前明确拒绝/标记，不得猜测 latest。
2. B-002 批量 lockfile 查询必须消费 GH-91 的 normalized records，按完整坐标去重并
   保留所有原始 locator；不得为每种 lockfile 再实现一套 parser。
3. B-003 网络模式使用 OSV batch API、HTTPS、固定 host、请求/响应大小、batch 数量、
   timeout 与 redirect 限制；部分 batch 失败使整个查询 operational error。
4. B-004 响应必须校验 query/result 一一对应并规范化 advisory ID、aliases、ranges、
   severity 与 source URL；缺失必需关联不得被当成空结果。
5. B-005 命中 finding 必须保留坐标、所有 lockfile locators、advisory ID/aliases、
   affected range、数据库修改时间和 source；severity 缺失时标为 unknown，不猜等级。
6. B-006 “0 advisories”只在完整成功响应或完整有效离线缓存中成立；query failure、
   unsupported、stale/incomplete cache 必须使用不同状态与退出语义。
7. B-007 cache key 包含 API/schema version 与完整规范化坐标；写入原子、内容可校验、
   TTL/age 可见，相同响应产生确定性记录。
8. B-008 `--offline` 禁止所有网络；任一请求坐标没有有效缓存时整体返回 incomplete
   operational error，不得输出其余坐标组成的伪完整报告。
9. B-009 漏洞 findings 属于独立 `vulnerability` family，不改变 GH-90
   `known-malicious-package`、provenance 或启发式 finding 的含义，也不相互覆盖。
10. B-010 text、JSON、SARIF 必须稳定呈现多坐标/多 advisory、无结果、unknown
    severity、stale cache 与错误边界，且不泄露本地缓存路径中的敏感目录信息。

## 验收标准

- [ ] 单坐标与九类 lockfile 批量查询使用相同 coordinate contract。
- [ ] batch 对齐、部分失败、超限、malformed 与 zero-result 有离线 mock 测试。
- [ ] cache 命中/过期/损坏/缺失和 `--offline` 行为有完整矩阵。
- [ ] 输出包含 advisory 证据并明确区分漏洞与已知恶意包。
- [ ] 不运行包管理器，不自动修改依赖。

## 边界情况清单

| 类别 | 判定（covered: B-xxx / N/A + 原因） |
| --- | --- |
| 空/缺失输入 | covered: B-001, B-008 |
| 错误与失败路径 | covered: B-003, B-004, B-006, B-008 |
| 授权/权限 | covered: B-007；cache 创建/替换失败直接报错 |
| 并发/竞态 | covered: B-007；原子 cache 写，同 key 确定内容 |
| 重试/幂等 | covered: B-002, B-007 |
| 非法状态转换 | covered: B-006, B-008；partial 不得成为 clean |
| 兼容/迁移 | covered: B-001, B-009 |
| 降级/回退 | covered: B-005, B-006, B-008 |
| 证据与审计完整性 | covered: B-004, B-005, B-010 |
| 取消/中断 | covered: B-003, B-007；不提交 partial cache/report |

## 发布说明

新增可选的 OSV 已知漏洞查询模式，可对精确坐标或 lockfile 批量运行。它与已知恶意
包情报分开呈现，并明确暴露网络、缓存与覆盖不完整状态。

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

1. B-001 查询输入必须复用 GH-90 的八生态 `PackageCoordinate` 闭集和 exact version；
   缺版本、范围输入、歧义名称、超限字段或 unsupported ecosystem 在联网前以
   operational error 拒绝，不得猜 latest、互转生态或只按 purl 猜 identity。
2. B-002 lockfile 模式只消费 GH-91 的 normalized records，按完整坐标去重并合并所有
   locator；root/path/workspace 等明确 local record 计入 excluded-local 状态，任一
   非 local external record 缺完整坐标则整次查询 incomplete operational error。
3. B-003 网络模式使用固定 OSV HTTPS host 的两阶段协议：完整耗尽每个
   `/v1/querybatch` page，再对唯一 advisory ID 调 `/v1/vulns/{id}`；所有请求、页数、
   坐标、ID、字节、时间、并发和 redirect 均有技术规范中的数字硬上限。
4. B-004 query/result 必须按位置一一对应；page token 必须收敛；详情 ID/modified
   必须与 batch summary 一致，并用共享 ecosystem comparator 复验该 exact coordinate
   仍被 affected。任一部分失败、错位、race、malformed 或资源超限使整批失败。
5. B-005 每个 active finding 保留完整坐标、全部 lockfile locators、primary ID、
   aliases、命中的 affected ranges、原始/规范化 severity、database modified time
   和固定 OSV source URL；缺失/不可比较 severity 标为 unknown，不猜等级。
6. B-006 `complete_no_match` 只来自所有 page/detail 完整成功或完整有效 cache；
   成功状态闭集为 complete-no-match/with-findings/stale，unsupported、incomplete、
   query/cache failure 是 typed operational error。OSV query 不返回 withdrawn；
   意外 withdrawn detail 必须按一致性 race 重试/失败，绝不冒充 active 或 clean。
7. B-007 cache key 包含 API/schema-set version 与完整坐标；cache envelope 有界、
   带摘要、并发无 lost update，写入以同目录 temp+fsync+rename+directory fsync 原子
   提交；网络批次失败不得提交本轮任一 entry。
8. B-008 `--offline` 禁止所有网络；任一 query key 缺失、损坏或超过
   `--max-age-seconds`
   时整体 operational error。只有同时显式 `--offline --allow-stale` 才可读取完整
   stale 集，并产生可见 approval evidence；网络失败不得回退 stale。
9. B-009 active vulnerability 使用独立 `vulnerability` family 和
   `known-vulnerability` rule；默认 approval，可选 severity threshold 只升级本
   family，绝不改变 GH-90 malicious、provenance、integrity 或 heuristic findings。
10. B-010 text、JSON、SARIF 对同一 snapshot 稳定呈现多坐标/多 advisory、
    complete-no-match、unknown severity、cache age/source 和 stale；
    operational error 为 exit 2、stderr、empty stdout/no SARIF，且不泄露 cache 路径。

## 验收标准

- [ ] 单坐标与九类 lockfile 批量查询使用相同 coordinate contract。
- [ ] batch 对齐、per-query pagination、详情 hydration、snapshot race、部分失败、
  超限、malformed 与 zero-result 有离线 mock 测试。
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

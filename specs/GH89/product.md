# Product Spec

## Linked Issue

GH-89

complexity: medium

## 用户问题

Argus 的 npm 安装前扫描会校验制品并扫描源码，但尚未利用 packument 中已有的
发布时间与版本序列识别两类已出现在真实攻击中的元数据异常：不符合包既有演进
形状的版本跳变，以及同一发布主体在短窗口内密集发布多个包。用户因此看不到可
审计的早期风险信号，也无法把它们与内容扫描结果一起纳入审批。

## 目标

- 基于规范化 SemVer 与 packument `time` 字段，按版本化的
  `npm-anomaly-v1` 策略产生 `version-shape-anomaly` 信号。
- 基于 npm registry 的有界 search 响应与固定默认窗口产生
  `rapid-publish-window` 信号。
- finding 明确列出参与判断的版本、时间、发布主体来源与窗口计数。
- 弱的单一元数据信号只要求审批；只有与既有高风险 finding 组合时才维持既有阻断。
- 所有网络读取复用现有受限 transport，并可被离线 fixture 完整测试。

## 非目标

- 不把任意 major bump、预发布、回移补丁或批量正常发布直接判为恶意。
- 不建立实时 registry 监控、全局发布者信誉服务或 SaaS 情报 feed。
- 不执行包管理器、安装脚本或待扫描制品。
- 不改变现有完整性、provenance 与内容规则的含义。

## Behavior Invariants

1. B-001 仅当请求解析到一个无 prerelease 的有效 SemVer 版本，且 packument
   提供目标版本时间、至少 6 个更早的稳定版本及不少于 30 天的历史跨度时，才
   评估版本形状。结构完整但历史量不足时必须输出稳定 rule ID
   `npm-version-shape-unassessed` 的 Info finding，列出缺少的前置条件；该 finding
   不改变 decision，也不能伪装成 evaluated-clean。
2. B-002 `version-shape-anomaly` 必须基于去重、规范化并按发布时间排序的稳定
   版本序列；JSON 对象顺序、dist-tag 顺序不得影响结果。
3. B-003 `npm-anomaly-v1` 只在以下条件同时成立时触发版本形状异常：目标版本在
   时间序列中的直接前驱之后大于 0 且不超过 72 小时发布；目标版本高于前驱；
   跳变为 major 增量至少 2，或在 major 不变时 minor 增量至少 10；此前最近
   5 个相邻稳定版本转换均未达到同类阈值。单步 major、预发布、backport、相同
   时间戳和晚补录时间不得触发。
4. B-004 命中时 finding 必须包含目标版本、相邻基线版本、对应时间与命中的
   阈值版本；不得只输出不可复核的风险分数。
5. B-005 `rapid-publish-window` 的发布主体只能取目标版本
   `versions[resolved]._npmUser.name`；不得回退到 author、maintainers 或邮箱。
   `npm-anomaly-v1` 从 registry search 的候选结果中精确筛选同一
   `publisher.username`，检查目标发布时间之前 24 小时（含端点）内的最新版本
   事件；至少 5 个不同 package 命中时触发。search 文本只用于候选发现，不得把
   它解释为 registry 承诺的 publisher/maintainer 完整过滤。
6. B-006 registry search 响应最多接受 250 个对象，只读取
   `package.{name,version,date,publisher.username}`，按
   `(name,version,date,publisher)` 去重，再按 package name 去重计数。重复对象、
   同一包多次出现与乱序响应必须得到稳定计数。计数未达到 5 时必须输出
   `npm-rapid-publish-unassessed` Info finding，因为 search API 不承诺返回某一
   publisher 的完整活动；不得把候选不足当作 evaluated-clean。响应声明
   `total > 250` 时不得把截断页当作完整证据。
7. B-007 `version-shape-anomaly` 与 `rapid-publish-window` 均为 Medium，并且是
   闭集 approval-only rule：仅它们（一个或两个）与纯 Info finding 共存时，
   decision 为 `allow-with-approval`；与现有 native-build approval 组合共存时仍为
   `allow-with-approval`；只要存在任一按现有规则会 block 的 finding，最终仍为
   block。两个 `*-unassessed` rule 是闭集 info-only rule，单独出现不改变 allow。
8. B-008 显式启用元数据检测后，缺失或损坏的 `time`、目标版本
   `_npmUser.name`、search 响应必需字段、`total > 250`、body 超限、缓存损坏与
   transport 失败都必须以 operational error 失败；不得 warning 后按“无异常”
   继续。仅“字段均合法但不足 B-001 的 6 个前驱/30 天跨度”以及“合法的有界
   search 候选不足 5 个”属于可继续的 unassessed，不属于错误。
9. B-009 附加请求只能在已批准 registry base URL 下解析
   `-/v1/search`，最终 URL 必须保持同 origin 且不能逃出该 base path；必须复用
   HTTPS、host allowlist、redirect 校验、2 MiB body cap 和可注入 transport；
   单次 scan 每个 publisher 最多一页、一次网络请求。
   可选持久缓存以 `(normalized full registry base URL,publisher,npm-anomaly-v1)`
   为键、TTL 15 分钟；base path 必须参与身份，命中后仍执行同一 schema 与上限
   校验。
10. B-010 text、JSON 与 SARIF 必须保留稳定 rule ID、证据与 package 坐标；相同
    fixture 重复运行产生相同 decision 和审计字段。

## 验收标准

- [ ] 可疑版本跳变、合法 major、预发布、backport 与乱序时间均有离线测试。
- [ ] 发布者跨包密集发布、同包正常批次、重复/乱序事件均有离线测试。
- [ ] fixture 冻结 `npm-anomaly-v1` 的 72 小时/版本跳变、24 小时/5 包、
  250 对象、2 MiB 和 15 分钟缓存边界。
- [ ] finding 可复核地展示版本、时间、主体来源、策略版本、窗口和计数。
- [ ] 单一弱信号只要求审批，且不能降级已有 block。
- [ ] 合法但历史不足输出 Info unassessed；缺失/损坏/截断的请求数据 fail closed，
  所有网络测试使用 mock transport。
- [ ] 攻击目录链接两个 rule ID，并明确 search API 只暴露每个包最新发布事件的
  已知限制。

## 边界情况清单

| 类别 | 判定（covered: B-xxx / N/A + 原因） |
| --- | --- |
| 空/缺失输入 | covered: B-001, B-005, B-008 |
| 错误与失败路径 | covered: B-008, B-009 |
| 授权/权限 | N/A：只读取公开或用户指定 registry 元数据 |
| 并发/竞态 | covered: B-006；事件去重与排序消除响应顺序影响 |
| 重试/幂等 | covered: B-002, B-006, B-010 |
| 非法状态转换 | N/A：不引入持久化工作流状态机 |
| 兼容/迁移 | covered: B-003, B-007, B-010 |
| 降级/回退 | covered: B-001, B-008 |
| 证据与审计完整性 | covered: B-004, B-005, B-010 |
| 取消/中断 | covered: B-008；未形成完整元数据结果时不输出 clean report |

## 发布说明

这是 npm fetch 的新增静态元数据启发式。它提供可审计的审批信号，不宣称证明包
恶意，也不会把一个孤立的版本或发布时间异常直接升级为阻断。

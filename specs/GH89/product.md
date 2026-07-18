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

- 基于规范化 SemVer 与 packument `time` 字段产生 `version-shape-anomaly` 信号。
- 基于有界、可配置的时间窗口产生 `rapid-publish-window` 信号。
- finding 明确列出参与判断的版本、时间、发布主体来源与窗口计数。
- 弱的单一元数据信号只要求审批；只有与既有高风险 finding 组合时才维持既有阻断。
- 所有网络读取复用现有受限 transport，并可被离线 fixture 完整测试。

## 非目标

- 不把任意 major bump、预发布、回移补丁或批量正常发布直接判为恶意。
- 不建立实时 registry 监控、全局发布者信誉服务或 SaaS 情报 feed。
- 不执行包管理器、安装脚本或待扫描制品。
- 不改变现有完整性、provenance 与内容规则的含义。

## Behavior Invariants

1. B-001 仅当请求解析到一个有效 SemVer 版本，且 packument 提供足够的可解析
   历史版本与时间数据时，才评估版本形状；信息不足必须明确报告为未评估，不能
   伪造 clean 结论。
2. B-002 `version-shape-anomaly` 必须基于去重、规范化并按发布时间排序的稳定
   版本序列；JSON 对象顺序、dist-tag 顺序不得影响结果。
3. B-003 合法 major 升级、预发布序列、backport 和晚补录时间不得仅因数字跨度
   触发异常；触发必须满足文档化的历史基线与跳变阈值。
4. B-004 命中时 finding 必须包含目标版本、相邻基线版本、对应时间与命中的
   阈值版本；不得只输出不可复核的风险分数。
5. B-005 `rapid-publish-window` 必须使用显式的发布主体字段来源、固定时间窗口、
   去重后的 package/version 事件和上限；缺少主体或时间时不得猜测身份。
6. B-006 同一包的正常批量发布、重复事件、分页重放与乱序响应必须得到稳定计数，
   并由正负 fixture 约束误报。
7. B-007 元数据异常单独出现时最高为 Medium、结果为
   `allow-with-approval`；不得覆盖或降低既有 High/Critical finding 导出的 block。
8. B-008 请求了元数据检测但 registry 返回缺失、损坏或超限的必需数据时，命令
   必须以 operational error 失败；不得 warning 后按“无异常”继续。
9. B-009 所有附加请求必须复用 HTTPS、host allowlist、redirect 校验、body cap
   和可注入 transport；不得引入无界抓取或隐式访问第三方主机。
10. B-010 text、JSON 与 SARIF 必须保留稳定 rule ID、证据与 package 坐标；相同
    fixture 重复运行产生相同 decision 和审计字段。

## 验收标准

- [ ] 可疑版本跳变、合法 major、预发布、backport 与乱序时间均有离线测试。
- [ ] 发布者跨包密集发布、同包正常批次、重复/乱序事件均有离线测试。
- [ ] finding 可复核地展示版本、时间、主体来源、窗口和计数。
- [ ] 单一弱信号只要求审批，且不能降级已有 block。
- [ ] 缺失/损坏的请求数据 fail closed，所有网络测试使用 mock transport。

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

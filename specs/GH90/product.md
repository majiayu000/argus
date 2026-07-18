# Product Spec

## Linked Issue

GH-90

complexity: large

## 用户问题

Argus 当前只能从制品本身与 registry 元数据推断风险，无法离线回答“这个精确包
版本是否已被 OpenSSF malicious-packages 数据集确认”。用户即使持有公开情报，
也需要自行下载、解析和比对，且容易混淆恶意包情报与普通 CVE 数据。

## 目标

- 从固定 revision 的 OpenSSF malicious-packages OSV 数据生成本地、可审计快照。
- 统一生态、名称、版本与 purl 后，对八个已支持生态做精确/范围匹配。
- 扫描完全离线；更新是显式命令，记录来源、revision、导入时间和内容摘要。
- finding 包含 advisory ID、数据源、命中坐标与匹配依据。
- 数据集启用后缺失、损坏或不兼容必须 fail closed。

## 非目标

- 不提供实时威胁监控、云端判定、匿名遥测或人工分析服务。
- 不把普通 CVE/漏洞 advisory 混入恶意包命中；该能力由 GH-94 单独负责。
- 不自动删除依赖、修改 lockfile 或执行包管理器。
- 不把包名相似、弱信誉或启发式信号冒充已知恶意情报。

## Behavior Invariants

1. B-001 导入只接受明确支持的 OSV schema 与 OpenSSF malicious-packages 来源；
   每个快照必须记录 canonical source、revision、imported_at、schema version 和摘要。
2. B-002 导入结果按规范化 advisory ID 与 package coordinate 确定性排序；相同输入
   重复导入必须产生字节一致的数据库，导入时间元数据除外且须被隔离。
3. B-003 生态与名称规范化必须形成闭集并保留原始值；大小写、scope、Composer/
   Maven/Go 等命名语义不得跨生态误合并。
4. B-004 exact version、OSV affected ranges、aliases 与 withdrawn 状态必须按 OSV
   语义处理；withdrawn 记录默认不产生阻断 finding，但保留可审计状态。
5. B-005 命中 finding 必须包含 advisory ID、source revision、规范化坐标、命中
   范围/版本和原始生态；已知恶意命中为 High/Critical 并导出 block。
6. B-006 未命中只能表示“当前固定快照中无匹配”，不得表述为包安全；输出必须能
   暴露数据 revision 与 age。
7. B-007 启用恶意情报而数据库缺失、摘要不符、解析失败或 schema 不兼容时，扫描
   必须 operational error；不得退化为未命中。
8. B-008 更新必须下载到临时位置，完成容量限制、schema 校验、规范化和摘要后原子
   替换；中断或失败保留上一份有效快照。
9. B-009 扫描路径不联网且不执行数据集内容；导入过程使用固定来源、HTTPS、重定向
   主机校验和 body/file 数量上限。
10. B-010 八生态代表 fixture、exact/range/withdrawn/alias/malformed 与跨生态同名
    fixture 必须稳定覆盖 text、JSON 和 SARIF 输出。

## 验收标准

- [ ] 固定 revision 可重复导入为可校验的离线快照。
- [ ] 八生态代表坐标和 exact/range/alias/withdrawn 均有测试。
- [ ] 命中输出 advisory、source revision、坐标与匹配依据并阻断。
- [ ] 启用后数据库缺失/损坏/不兼容 fail closed；失败更新不破坏旧快照。
- [ ] 文档明确区分 malicious-package intel 与 GH-94 漏洞查询。

## 边界情况清单

| 类别 | 判定（covered: B-xxx / N/A + 原因） |
| --- | --- |
| 空/缺失输入 | covered: B-001, B-007 |
| 错误与失败路径 | covered: B-007, B-008, B-009 |
| 授权/权限 | covered: B-008；替换失败不得破坏现有可读数据库 |
| 并发/竞态 | covered: B-008；临时文件加原子替换，扫描只打开完整快照 |
| 重试/幂等 | covered: B-002, B-008 |
| 非法状态转换 | covered: B-008；invalid 不得成为 current |
| 兼容/迁移 | covered: B-001, B-003, B-004 |
| 降级/回退 | covered: B-006, B-007 |
| 证据与审计完整性 | covered: B-001, B-005, B-006 |
| 取消/中断 | covered: B-008 |

## 发布说明

新增可选的本地已知恶意包情报层。它只依据用户显式导入的固定数据快照匹配，不
包含实时服务，也不把“未命中”解释为安全证明。

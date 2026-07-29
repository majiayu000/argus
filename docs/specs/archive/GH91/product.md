# Product Spec

## Linked Issue

GH-91

complexity: large

## 用户问题

`argus lockfile` 目前只理解 npm `package-lock.json`，而项目往往使用 yarn、pnpm、
Poetry/uv、Cargo、Go、Bundler 或 Composer。其他 lockfile 即使包含明文 HTTP、陌生
下载主机、可变 git 引用或缺失完整性证据，Argus 也无法识别，用户容易把“未支持”
误解成“扫描通过”。

## 目标

- 支持 yarn.lock、pnpm-lock.yaml、poetry.lock、uv.lock、Cargo.lock、go.sum、
  Gemfile.lock 与 composer.lock，并保留 package-lock.json。
- 确定性检测格式，输出统一 dependency/source/integrity record。
- 检查明文 HTTP、非信任主机、可变 git ref 与格式要求下缺失的 integrity。
- 将 unsupported、partial 与 parse failure 明确作为 operational error，绝不输出
  report 或伪装 clean。
- 全程静态读取，不调用任何包管理器或网络。

## 非目标

- 不查询 CVE、恶意包情报或 registry 最新状态。
- 不重新解析依赖、修改 lockfile、下载包或验证远端对象仍存在。
- 不承诺跨生态完全相同的完整性语义；每个格式按其可表达证据说明结论。
- 不把缺少本就不携带 hash 的合法格式字段一律升级为恶意。

## Behavior Invariants

1. B-001 格式检测以文件名与版本/结构签名共同判定；冲突、未知或歧义输入必须
   operational error，并列出检测依据。
2. B-002 每个 parser 输出复用 GH-90 `PackageCoordinate` 的统一 record：生态、
   规范化坐标、source kind/location、immutable reference、integrity
   state/algorithm/value、原始 locator 与 condition；只有缺少 name/version 的
   root/path/workspace record 可令 coordinate 为空，仍须保留 raw fields 与 coverage；
   按技术规范稳定排序且不丢重复项。
3. B-003 package-lock、Yarn Classic/Berry、pnpm、Poetry、uv、Cargo、go.sum、
   Gemfile.lock 与 composer.lock 的受支持版本/结构形成技术规范中的闭集矩阵；
   basename 与结构/version signature 必须一致，新版本不得被当作旧版本静默解析。
4. B-004 任一依赖的下载源使用 plain HTTP 必须产生 Critical 阻断 finding；可解析
   HTTPS/SSH host 不在该格式默认 exact-host 闭集或用户 exact-host allowlist 时，
   必须产生独立 High 阻断 finding；URL parse failure 是 operational error。
5. B-005 git source 使用 branch、tag 名、HEAD 或其他可变 ref 时必须报告；完整
   commit digest 可作为 immutable evidence，但不得被误称为制品内容 hash。
6. B-006 技术规范的 per-format matrix 将 integrity 状态闭合为 required、optional
   或 unavailable-by-format。required 缺失为 High/block，编码/长度非法为
   Critical/block，SHA-1/MD5 等弱证据为 Medium/approval，unavailable 为 Info 且
   不改变 decision；immutable VCS revision 不得冒充制品内容 hash。
7. B-007 parser 遇到任一未支持 section/entry、无法完整归一化的记录或 coverage
   count 不守恒时，整次扫描必须 operational error（exit 2、stderr、stdout 为空）；
   不得生成 partial report、finding 或 allow/approval decision。
8. B-008 重复 entry、平台条件、workspace/root entry、同包多版本与乱序输入不得
   丢记录或产生非确定结果。
9. B-009 不执行 package manager、VCS、shell 或网络；输入最多 64 MiB、100,000
   records、64 层 nesting、单 scalar 1 MiB、总 scalar 1,000,000，任一等号边界
   允许、超限一为 operational error；YAML alias/tag 与 duplicate map key 被拒绝。
   finding/evidence canonical JSON 合计最多 64 MiB，禁止静默截断，超限同样失败。
10. B-010 成功扫描的 text、JSON、SARIF 使用现有 exit 0/1/2（allow/block/
    allow-with-approval）；unknown/ambiguous/new-version/partial/parse/limit 错误
    使用 operational exit 2、stderr 与空 stdout，不生成 SARIF/report，也不得产生
    漏洞或恶意包命中文案。

## 验收标准

- [ ] 九类 lockfile 的受支持版本、代表性正例与 clean fixture 均通过。
- [ ] HTTP、陌生 host、可变 git ref、缺失/弱 integrity 有独立测试。
- [ ] unknown/ambiguous/new-version/partial/oversized 以 operational error 失败且
  stdout 为空。
- [ ] 统一 record 可被后续 GH-90/GH-94 复用且保留生态原生 locator。
- [ ] 测试证明未启动子进程、未访问网络。

## 边界情况清单

| 类别 | 判定（covered: B-xxx / N/A + 原因） |
| --- | --- |
| 空/缺失输入 | covered: B-001, B-009 |
| 错误与失败路径 | covered: B-001, B-007, B-009 |
| 授权/权限 | covered: B-009；只读打开失败直接报错 |
| 并发/竞态 | N/A：单次扫描读取一份不可变输入快照 |
| 重试/幂等 | covered: B-002, B-008 |
| 非法状态转换 | covered: B-007；partial 不得转为 clean |
| 兼容/迁移 | covered: B-003, B-010 |
| 降级/回退 | covered: B-001, B-006, B-007 |
| 证据与审计完整性 | covered: B-002, B-005, B-006 |
| 取消/中断 | covered: B-009；未完成解析不输出 report |

## 发布说明

lockfile 扫描从 npm 单格式扩展到九类常用格式，并显式区分风险、部分支持和操作
失败。该功能只审查锁定来源与完整性证据，不提供漏洞或恶意包判断。

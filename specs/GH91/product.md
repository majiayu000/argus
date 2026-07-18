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
- 明确报告 unsupported、partial 与 parse failure，绝不伪装 clean。
- 全程静态读取，不调用任何包管理器或网络。

## 非目标

- 不查询 CVE、恶意包情报或 registry 最新状态。
- 不重新解析依赖、修改 lockfile、下载包或验证远端对象仍存在。
- 不承诺跨生态完全相同的完整性语义；每个格式按其可表达证据说明结论。
- 不把缺少本就不携带 hash 的合法格式字段一律升级为恶意。

## Behavior Invariants

1. B-001 格式检测以文件名与版本/结构签名共同判定；冲突、未知或歧义输入必须
   operational error，并列出检测依据。
2. B-002 每个 parser 输出统一、确定性排序的 record：生态、规范化坐标、source
   kind/location、immutable reference、integrity algorithm/value 和原始 locator。
3. B-003 package-lock、yarn、pnpm、poetry、uv、Cargo、Go、Gemfile 与 Composer
   的受支持版本形成显式矩阵；新版本不得被当作旧版本静默解析。
4. B-004 任一依赖的下载源使用 plain HTTP 必须产生阻断 finding；可解析 HTTPS
   host 不在生态默认/用户 allowlist 时必须产生独立高风险 finding。
5. B-005 git source 使用 branch、tag 名、HEAD 或其他可变 ref 时必须报告；完整
   commit digest 可作为 immutable evidence，但不得被误称为制品内容 hash。
6. B-006 只有格式规范要求且该 entry 应携带 integrity/checksum 时，缺失或无法
   解析才产生 `lockfile-integrity-missing`；算法弱度与未验证状态必须明确区分。
7. B-007 parser 能安全读取但存在未支持 section/entry 时，report 必须标为 partial、
   产生审批 finding 并给出计数；不得跳过后返回 allow。
8. B-008 重复 entry、平台条件、workspace/root entry、同包多版本与乱序输入不得
   丢记录或产生非确定结果。
9. B-009 不执行 package manager、VCS、shell 或网络；文件大小、entry 数、嵌套
   深度与字符串长度均有硬上限，超限为 operational error。
10. B-010 text、JSON、SARIF 和退出码必须区分 clean、risk finding、partial 与
    operational failure；不得产生漏洞或恶意包命中文案。

## 验收标准

- [ ] 九类 lockfile 的受支持版本、代表性正例与 clean fixture 均通过。
- [ ] HTTP、陌生 host、可变 git ref、缺失/弱 integrity 有独立测试。
- [ ] unknown/ambiguous/new-version/partial/oversized 不返回伪 clean。
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

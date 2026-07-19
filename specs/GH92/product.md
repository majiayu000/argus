# Product Spec

## Linked Issue

GH-92

complexity: large

## 用户问题

Argus 仍是未打 tag 的源码项目。使用者必须自行安装 Rust、编译并手工接入 CI，无法
验证下载产物对应哪个源码 revision，也没有稳定的官方 GitHub Action 输入/退出码
契约。这使已有检测能力难以被实际采用。

## 目标

- 以当前 workspace `0.1.0` 定义首个受支持 binary release，并冻结后续 SemVer
  兼容策略和 tag 驱动的可重复发布流程。
- 发布 Linux、macOS、Windows 的预编译 `argus`，在可实践目标上覆盖 arm64。
- 每个产物提供 checksum、签名/attestation 与源码 revision 关联。
- 提供仓库内官方 GitHub Action，支持 package、lockfile、agent scan 和 SARIF。
- 下载器严格校验版本、平台、HTTPS、checksum 与 provenance，失败即停止。

## 非目标

- 不发布 SaaS、registry 监控、托管策略服务或遥测。
- 不在首版承诺所有 libc/CPU/旧系统组合。
- 不隐藏 Argus 原生退出码，也不把 block 当作 Action 自身故障。
- 不从浮动 branch、`workflow_dispatch` 或未经独立人工授权的 ref 发布正式版本。
- 不在实现 PR 中创建 tag、GitHub Release、Marketplace listing 或移动 `v1`。

## Behavior Invariants

1. B-001 正式发布只能由独立人工授权、符合 SemVer 的 `vX.Y.Z` tag 触发；tag commit
   必须位于 `main`，Cargo、CLI、release tag、Action 下载版本必须一致。首版固定为
   `v0.1.0`；Action 接口 major `v1` 与 binary SemVer 是两个不同版本域。publish 前
   必须只读确认 repository immutable releases 已启用，且 active rulesets 分别保护
   SemVer tag 与 `refs/heads/v1`；缺一即失败。
2. B-002 发布矩阵固定为 Linux GNU x86_64/aarch64、macOS x86_64/aarch64 与
   Windows MSVC x86_64；每个目标必须在同 OS/arch runner 上运行 `argus --version`
   smoke。不支持的平台在下载前报错，不得回退到源码编译或其他架构。
3. B-003 每个目标的 raw binary 和 deterministic archive、`release_manifest.json`、
   `SHA256SUMS`、license/readme、size/SHA-256、tag commit 与 provenance
   attestation 必须确定性关联。所有资产先进入 draft release，缺失或不一致时不得
   publish。
4. B-004 发布前必须通过 fmt、clippy、workspace test、corpus、Action distribution
   drift check 与全部目标 smoke；只有完整资产复验通过后才 publish immutable
   release，失败只可留下不可见 draft，不得创建 latest/major 指针。
5. B-005 根目录 `action.yml` 的公开引用为 `majiayu000/argus@v1`；`v1` 是受保护的
   Action major branch，只允许经新的明确人工授权，在兼容 immutable release 发布后
   向后代 commit fast-forward，禁止 workflow token 自动 promotion、force push 或
   delete。用户也可 pin `vX.Y.Z` 或完整 commit SHA。
6. B-006 Action 使用单一 `scanType=package|lockfile|agent` 与单一 workspace 内
   `path`，支持 `format=text|json|sarif`、精确 `argusVersion` 和
   `failOn=block|approval`。输入是闭集，不接受任意 argv、registry、命令、secret、
   baseline 更新或 LLM judge 参数。Action `v1` 初始只接受
   `>=0.1.0,<0.2.0`；默认 `0.1.0`。未先更新 Action compatibility contract 和 fixture
   的版本必须拒绝。
7. B-007 Action 对 exit 0/1/2 均须按所选格式解析完整 report，并分别要求
   allow/block/allow-with-approval；空、截断、malformed 或 decision/exit 矛盾都是
   operational error。outputs 遵循无数据即空：下载/校验/启动前失败时 `decision`、
   `exitCode`、`reportPath`、`sarifFile` 为空，仅 `argusVersion` 可保留已验证请求值；
   CLI exit 后 report 无效时只填实际 `exitCode`。完整 report 才填
   decision/reportPath，完整 SARIF 才填 sarifFile；然后按 `failOn` 设置 conclusion，
   禁止伪造 clean/exit/report path。
8. B-008 Action 先验证已 attested 的 manifest，再下载 manifest 指定的 raw binary；
   GitHub Release/API 请求有固定 HTTPS origin、单次受控 redirect、长度/时间/总字节
   上限且不转发凭证。binary 必须同时通过 release-asset digest、manifest SHA-256
   和绑定 repo/workflow/tag/commit 的 GitHub attestation，之后才可执行；不得执行
   下载内容提供的脚本。Attestation bundle 来自 immutable Release；受信根只允许由
   `gh` 的 Sigstore/TUF 验证链在线取得，不访问 Attestations API，失败即停止。
9. B-009 新 workflow 的默认权限为 `contents: read`；只有 publish job 获得
   `contents: write`，attest job 获得 `id-token: write`/`attestations: write`。
   所有外部 Action 固定完整 commit。官方 Action 不上传 SARIF；调用方需显式授予
   `security-events: write` 并在 fork PR 跳过 upload。
10. B-010 README、CHANGELOG、SECURITY/release 文档必须同步安装命令、支持矩阵、
    `gh` 前置条件、校验方法、兼容承诺、人工发布门、撤回流程与未覆盖边界。撤回
    不改写 tag/asset/历史：以安全公告和新 patch release 向前修复，再
    fast-forward `v1`。没有通过完整 immutable patch release 的即时静默撤回不存在。

## 兼容策略

- Binary `0.x`：patch release 不得移除/改名 CLI 参数、改变 0/1/2 report 语义或
  machine-readable 字段含义；需要破坏性变更时提升 minor，并在 CHANGELOG 给迁移。
- Action `v1`：既有 input/output 名称、默认值和四态映射保持兼容；只允许新增
  optional 字段。移除或改变语义必须发布新的 Action major branch。
- Binary minor 可破坏内部 CLI/report contract，但发布前必须先在同一 release commit
  更新 Action 的 tested compatibility range/validator；旧 Action commit 对超范围
  binary fail closed。若对外 Action input/output 也不兼容，则必须使用新 Action major。
- 现有 JSON report 没有 schema 字段；Action 按 tested binary range 与当前完整字段
  闭集验证，不虚构版本。新 release manifest 使用整数 `schemaVersion`；同版本只允许
  增加明确 optional 字段，unknown required/schema version 必须 fail closed。
- SARIF 固定 2.1.0；rule ID、decision property 与 fingerprint key 在同 Action major
  内稳定，只允许增加 rule/result property。
- 首版运行下限与 native smoke 一致：Ubuntu 24.04（glibc 2.39）、macOS 15、
  Windows Server 2025；更旧系统、Windows client 与 Windows arm64 不在支持矩阵。

## 验收标准

- [ ] 不创建公开 release 的 candidate fixture 能产生完整矩阵、checksum 和
  provenance plan；独立授权后的真实 `v0.1.0` tag 可复用相同 workflow publish。
- [ ] Linux/macOS/Windows 安装器对正确、损坏、缺失和错误架构产物有测试。
- [ ] 官方 Action 覆盖 package/lockfile/agent 和 SARIF，输出/退出语义稳定。
- [ ] 发布失败不会移动 latest/major 指针或留下貌似完整的公开 release。
- [ ] 文档可让新用户无需 Rust 工具链完成安装与 CI 集成。
- [ ] 实现合并后，创建 tag/release 与首次 fast-forward `v1` 仍是明确列出的
  `human_decision`，没有该授权不得关闭 GH-92。
- [ ] 管理员已独立确认 immutable releases、SemVer tag ruleset、exact `v1` branch
  ruleset 与受保护 `release` environment；当前远程事实为它们均未配置，因此实现
  完成也不得绕过该门。

## 边界情况清单

| 类别 | 判定（covered: B-xxx / N/A + 原因） |
| --- | --- |
| 空/缺失输入 | covered: B-002, B-003, B-006, B-008 |
| 错误与失败路径 | covered: B-003, B-004, B-007, B-008 |
| 授权/权限 | covered: B-001, B-009 |
| 并发/竞态 | covered: B-001, B-003, B-005；同 tag 单并发，publish/指针最后更新 |
| 重试/幂等 | covered: B-001, B-003；同 tag/draft 先比摘要，不覆盖不同字节 |
| 非法状态转换 | covered: B-004, B-005；未验证不可 publish/promote |
| 兼容/迁移 | covered: B-001, B-005, B-010 |
| 降级/回退 | covered: B-002, B-007, B-008 |
| 证据与审计完整性 | covered: B-003, B-008, B-009 |
| 取消/中断 | covered: B-003, B-004；partial draft 不 publish/promote |

## 发布说明

这是 Argus 首个受支持二进制与 CI 分发契约。Action `v1` 接口稳定不代表 0.x binary
API 已达到 1.0；用户可以验证下载产物、固定版本，并通过官方 Action 将既有扫描接入
流水线。

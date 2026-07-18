# Product Spec

## Linked Issue

GH-92

complexity: large

## 用户问题

Argus 仍是未打 tag 的源码项目。使用者必须自行安装 Rust、编译并手工接入 CI，无法
验证下载产物对应哪个源码 revision，也没有稳定的官方 GitHub Action 输入/退出码
契约。这使已有检测能力难以被实际采用。

## 目标

- 定义首个稳定版本、兼容策略和 tag 驱动的可重复发布流程。
- 发布 Linux、macOS、Windows 的预编译 `argus`，在可实践目标上覆盖 arm64。
- 每个产物提供 checksum、签名/attestation 与源码 revision 关联。
- 提供仓库内官方 GitHub Action，支持 package、lockfile、agent scan 和 SARIF。
- 下载器严格校验版本、平台、HTTPS、checksum 与 provenance，失败即停止。

## 非目标

- 不发布 SaaS、registry 监控、托管策略服务或遥测。
- 不在首版承诺所有 libc/CPU/旧系统组合。
- 不隐藏 Argus 原生退出码，也不把 block 当作 Action 自身故障。
- 不从浮动 branch 或未经批准的 workflow_dispatch 发布正式版本。

## Behavior Invariants

1. B-001 正式发布只能由符合 SemVer 的受保护 `vX.Y.Z` tag 触发，且 Cargo、CLI、
   release 与 Action 报告的版本必须一致并指向同一 commit。
2. B-002 发布矩阵必须明确列出 OS/arch/ABI 支持状态；不支持平台在下载前报错，
   不得静默回退到源码编译或其他架构。
3. B-003 每个 archive 的文件名、内部 binary、license/readme、SHA-256 checksum 与
   provenance attestation 必须确定性关联；缺任一必需发布物则 release 不可完成。
4. B-004 CI 产物在发布前必须通过 fmt、clippy、workspace test、corpus、binary
   `--version` 与目标平台 smoke；失败不得创建 latest/stable 指针。
5. B-005 官方 Action 使用固定 major 入口 `argus/action@v1`，同时允许完整 commit
   pin；major 指针只能在已验证兼容 release 后更新。
6. B-006 Action 必须为 package directory、lockfile、agent surface 提供互斥输入，
   并支持 text/JSON/SARIF、额外只读参数和显式 binary version。
7. B-007 Action 必须保留原生语义：allow=0、block=1、
   allow-with-approval/operational error 的区分通过稳定 output 与 step conclusion 表达，
   不得把错误伪装成 clean。
8. B-008 下载只允许 GitHub Releases HTTPS 端点，校验 redirect host、长度、checksum
   与 attestation 后才安装；不得执行下载内容提供的脚本。
9. B-009 Action 与 release workflow 使用最小权限、固定第三方 action commit，并
   不接收/回显任意 secret；SARIF upload 权限必须显式、fork 安全。
10. B-010 README、CHANGELOG、SECURITY/release 文档必须同步安装命令、支持矩阵、
    校验方法、兼容承诺、撤回流程与未覆盖边界。

## 验收标准

- [ ] 一个候选 tag 能产生完整矩阵、checksum 和 provenance，并通过 smoke。
- [ ] Linux/macOS/Windows 安装器对正确、损坏、缺失和错误架构产物有测试。
- [ ] 官方 Action 覆盖 package/lockfile/agent 和 SARIF，输出/退出语义稳定。
- [ ] 发布失败不会移动 stable/major 指针或留下貌似完整的 release。
- [ ] 文档可让新用户无需 Rust 工具链完成安装与 CI 集成。

## 边界情况清单

| 类别 | 判定（covered: B-xxx / N/A + 原因） |
| --- | --- |
| 空/缺失输入 | covered: B-002, B-006, B-008 |
| 错误与失败路径 | covered: B-003, B-004, B-007, B-008 |
| 授权/权限 | covered: B-001, B-009 |
| 并发/竞态 | covered: B-001, B-005；同 tag 单并发，指针最后更新 |
| 重试/幂等 | covered: B-001, B-003；同 tag 不覆盖不同字节 |
| 非法状态转换 | covered: B-004, B-005；未验证不可 promoted |
| 兼容/迁移 | covered: B-001, B-005, B-010 |
| 降级/回退 | covered: B-002, B-007, B-008 |
| 证据与审计完整性 | covered: B-003, B-008, B-009 |
| 取消/中断 | covered: B-003, B-004；partial release 不 promoted |

## 发布说明

这是 Argus 首个正式二进制与 CI 分发契约。安全能力不变，但用户可以验证下载产物、
固定版本，并通过官方 Action 将既有扫描接入流水线。

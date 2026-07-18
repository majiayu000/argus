# Tech Spec

## Linked Issue

GH-92

## Product Spec

Link to `product.md`.

## Codebase Context

| Area | Verified anchor | Current behavior | Why relevant |
| --- | --- | --- | --- |
| workspace version | `Cargo.toml:20` | workspace version 为 0.1.0 | tag、binary 与 release 的单一版本源 |
| release profile | `Cargo.toml:80` | thin LTO、单 codegen unit、strip | 生产 binary 构建基线 |
| CI gate | `.github/workflows/ci.yml:17` | Ubuntu 上 fmt/clippy/test/corpus/SARIF smoke | release 必须复用并扩展这些门禁 |
| CLI exit boundary | `crates/argus-cli/src/main.rs:286` | main 统一映射 command 结果为 ExitCode | Action 必须保留原生语义 |
| report output | `crates/argus-cli/src/main.rs:566` | text/JSON/SARIF 在完整 report 后输出 | Action 不需要二次解释扫描结果 |
| status docs | `README.md:287` | 明确 pre-release、无 tagged binary | 发布成功后需原子更新用户契约 |

## Proposed Design

新增 tag-only `release.yml`，先执行版本一致性与现有质量门禁，再用显式 target matrix
构建 archives。第一版支持 x86_64/arm64 macOS、x86_64 Linux GNU、x86_64 Windows
MSVC；Linux arm64 只有在受支持 runner/cross smoke 可验证时纳入，不能生成未运行的
“名义支持”产物。每个 archive 包含 binary、LICENSE、README，并由单一 manifest
列出 target、size、SHA-256、commit 与 version。

workflow 使用 GitHub artifact attestation 为每个 archive 和 checksum manifest 生成
provenance；第三方 actions 固定完整 commit。所有 matrix job 成功后才创建 GitHub
Release，最后一步才移动 `v1` major tag。重跑相同 tag 时先比对现有资产摘要，不同
字节直接失败，不覆盖。

仓库内 Action 使用 Node 运行时，源代码提交、由锁定依赖构建的 `dist/index.js` 也
提交并由 CI 验证无 diff。Action 解析闭集输入，选择平台资产，通过 GitHub API
下载 manifest/archive/attestation，先校验长度与 SHA-256，再验证 provenance subject
和 release commit，最后安装到 `RUNNER_TEMP` 并加 PATH。它直接以 argv 数组启动
binary，不经 shell 拼接。

扫描模式映射为互斥的 `package_path`、`lockfile_path`、`agent_path`，format 为闭集；
输出 `decision`、`exit_code`、`sarif_file`、`argus_version`。Action wrapper 区分 block、
approval 与 operational error，并提供 `fail_on` 策略，但永不把 operational error
转换为成功。

## Planned Changes Manifest

<!-- specrail-planned-changes
{"version":1,"issue":92,"complete":true,"paths":[".github/workflows/action-dist.yml",".github/workflows/release.yml","CHANGELOG.md","Cargo.lock","Cargo.toml","README.md","SECURITY.md","action.yml","action/dist/index.js","action/package-lock.json","action/package.json","action/src/main.js","action/tests/action.test.js","crates/argus-cli/src/main.rs","docs/releasing.md","scripts/verify-release-assets.sh","specs/GH92/product.md","specs/GH92/tech.md"],"spec_refs":["specs/GH92/product.md","specs/GH92/tech.md"]}
-->

## Product-to-Test Mapping

| Behavior invariant | Implementation area | Verification |
| --- | --- | --- |
| B-001 | tag/version gate | release workflow dry-run fixture + `argus --version` smoke |
| B-002 | target matrix + Action selector | Node platform matrix tests |
| B-003 | archive/manifest/attestation jobs | `scripts/verify-release-assets.sh` on candidate assets |
| B-004 | release needs graph + target smoke | candidate workflow required checks |
| B-005 | promotion job | test release verifies `v1` moves only after all needs pass |
| B-006 | `action.yml` + argv builder | `npm test --prefix action` input matrix |
| B-007 | exit mapper + outputs | Node tests for allow/block/approval/error |
| B-008 | downloader/verifier | corruption/redirect/attestation negative tests |
| B-009 | workflow permissions + pinned actions | workflow policy check and fork SARIF smoke |
| B-010 | README/CHANGELOG/SECURITY/docs | release checklist review + command smoke |

## 数据流

受保护 tag 触发门禁与 target builds；archives 汇聚成 manifest/checksums，完成
attestation 后创建 release，最后 promote major tag。Action 读取固定 version，验证并
安装 asset，以参数数组运行 Argus，将 report/退出状态映射为 outputs 和 step result。

## 备选方案

- `curl | sh` 安装：与项目检测的风险模式冲突且难以验证执行前内容，拒绝。
- Action 每次 `cargo install`：慢、依赖工具链且不能提供同一发布物 provenance，拒绝。
- 自动发布所有 cross-compiled target：未 smoke 的二进制不应宣称支持，拒绝。

## 风险

- Release compromise：最小权限、environment protection、固定 actions 与 attestation。
- Major tag mutation：只允许 promotion job 更新，文档建议高保障用户 pin commit。
- Node bundle drift：CI 从锁文件重建并比较 `dist`。
- Exit ambiguity：稳定 outputs 保留 decision，operational error 永不放行。

## 测试计划

- [ ] Rust workspace 与每目标 binary smoke。
- [ ] Node unit：input、platform、download verification、argv、exit mapping。
- [ ] Candidate release：assets/checksum/attestation 端到端验证。
- [ ] Action dogfood：package/lockfile/agent/SARIF 四类 workflow fixture。

## 回滚方案

撤回受影响 release、冻结 `v1` 到最后一个安全 commit，并在 SECURITY/CHANGELOG 记录
原因；不得重写或覆盖既有 tag/asset。Action 用户可 pin 回已知 commit，源码构建仍
保留。后续修复以新 patch tag 发布。

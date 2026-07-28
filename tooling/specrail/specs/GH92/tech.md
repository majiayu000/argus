# Tech Spec

## Linked Issue

GH-92

## Product Spec

Link to `product.md`.

## Codebase Context

| Area | Verified anchor | Current behavior | Why relevant |
| --- | --- | --- | --- |
| workspace version | `Cargo.toml:20` | workspace version 为 0.1.0 | 首版 tag、binary 与 release 的版本源 |
| release profile | `Cargo.toml:80` | thin LTO、单 codegen unit、strip | 生产 binary 构建基线 |
| CI gate | `.github/workflows/ci.yml:17` | Ubuntu 上 fmt/clippy/test/corpus/SARIF smoke | release 必须复用并扩展这些门禁 |
| CLI exit boundary | `crates/argus-cli/src/main.rs:295` | report 为 0/1/2；operational error 也为 2 但 stderr-only | Action 必须验证 report 后区分 |
| report output | `crates/argus-cli/src/main.rs:586` | text/JSON/SARIF 只在完整 report 后输出 | Action 可用格式契约判定 approval |
| status docs | `README.md:287` | 明确 pre-release、无 tagged binary | 发布成功后需原子更新用户契约 |

## Proposed Design

新增 tag-only `release.yml`。它只接受已存在的 `vX.Y.Z` tag push；先验证 tag commit
位于 `main`、tag 与 workspace/CLI/Action binary version 全等，并通过受保护
`release` environment 的独立人工 gate。`workflow_dispatch` 只允许
`candidateOnly=true` 且禁止 create/update ref 或 release，用于不产生公开状态的
端到端 fixture。当前远程只读事实是 immutable releases
`enabled=false,enforced_by_owner=false`、repository rulesets 为空且 `release`
environment endpoint 为 404；管理员必须先单独启用 immutable releases、建立 active
SemVer tag 和 `v1` branch rulesets，并配置 `release` environment。environment 必须
有至少一名 required reviewer、`prevent_self_review=true` 且 deployment tag policy 为
`v*.*.*`；tag ruleset 必须覆盖同一 pattern 并限制 create/update/delete，`v1`
ruleset 必须以 exact ref pattern 限制 creation/update/delete/non-fast-forward，首次
创建也只能由另一次明确授权的受限 maintainer 完成。两者 bypass 只列明确 release
maintainer/team/app，不能是任意 actor；workflow 自身再以 strict SemVer regex 收紧
glob。publish job 通过 REST 只读解析并重查每个字段，不满足即失败；实现/auto mode
不修改 repository settings。

目标矩阵与 native runner 固定如下，不发布仅 cross-compile、未运行过的二进制：

| target | runner | binary | archive |
| --- | --- | --- | --- |
| `x86_64-unknown-linux-gnu` | `ubuntu-24.04` | `argus-v{version}-x86_64-unknown-linux-gnu` | 同前缀 `.tar.gz` |
| `aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` | `argus-v{version}-aarch64-unknown-linux-gnu` | 同前缀 `.tar.gz` |
| `x86_64-apple-darwin` | `macos-15-intel` | `argus-v{version}-x86_64-apple-darwin` | 同前缀 `.tar.gz` |
| `aarch64-apple-darwin` | `macos-15` | `argus-v{version}-aarch64-apple-darwin` | 同前缀 `.tar.gz` |
| `x86_64-pc-windows-msvc` | `windows-2025` | `argus-v{version}-x86_64-pc-windows-msvc.exe` | 同前缀 `.zip` |

`scripts/package_release.py` 用稳定排序、固定 UTC timestamp、owner/mode 与 gzip header
生成 raw binary 和 deterministic archive。汇聚 job 生成 canonical
`release_manifest.json` 与 `SHA256SUMS`：`schemaVersion`、`binaryVersion`、tag、commit、
target、runner、asset/archive name、size、SHA-256 均为必需闭集，重复/额外/缺失 target
均失败。manifest JSON 使用 UTF-8、LF、sorted keys、无 insignificant whitespace 的
canonical bytes，parser 拒绝 duplicate keys、unknown required schema 和未知 target。
每个 target build job 使用固定完整 commit 的 `actions/attest` 同时签 raw binary 与
archive，并把其 `bundle-path` 以 `{target}.sigstore.json` 汇聚；汇聚 job 分别为
manifest 和 checksum file 生成 `release_manifest.sigstore.json` 与
`SHA256SUMS.sigstore.json`。bundle 是固定 release asset，每个限 4 MiB；Action 只用
manifest/target bundle。权限只在相应 attest job 提升为 `id-token: write`、
`attestations: write` 与官方 Action 要求的 `artifact-metadata: write`。

publish job 在单 tag concurrency 下创建或复用 draft release。raw binary、archive、
manifest 与 `SHA256SUMS` 是 deterministic payload，复用时必须与本地 size/SHA-256
全等。Sigstore bundle 包含每次签发的新证书/timestamp，重跑不得按 bundle bytes
比较：已有 bundle 必须下载并以其预期 subject digest、repo、workflow、tag ref 与
source commit 完整密码学复验，合法则原样复用，缺失才上传本轮 bundle；invalid、
subject 冲突或重复 bundle 失败并要求人工检查 draft，禁止 clobber。所有资产通过
`scripts/verify_release_assets.py` 后才 publish；仓库必须预先启用 immutable releases，
publish 后再用 `gh release verify`/`verify-asset` 复验。workflow 不携带 promotion
secret，也不更新 `refs/heads/v1`；它只输出 proposed old/new SHA 与 ancestor proof。
release 发布后由另一次明确人工授权，让 ruleset 允许的 maintainer 将 `v1` 正常
fast-forward 到 release commit，随后只读验证 ref。candidate mode 到验证为止，不
执行 attest API、draft、publish 或 ref mutation，只用冻结 fixture 验证 attestation
plan/policy。

根目录 `action.yml` 使用 `node24`，公开引用是 `majiayu000/argus@v1`。`action/src/`
源代码、锁定依赖与构建后的 `action/dist/index.js` 全部提交，`action_dist.yml` 从
lockfile 重建并要求 zero diff。`action/release.json` 保存
`schemaVersion=1`、`defaultBinaryVersion="0.1.0"` 与
`compatibilityRange=">=0.1.0,<0.2.0"`，release gate 保证 default 与 Cargo/tag
一致；Action version 域单独固定为接口 major 1。未来 release 只有在
validator/fixture 先覆盖后才能扩大 range。

Action 输入只有：

- `scanType`：`package|lockfile|agent`，必需；
- `path`：相对 `GITHUB_WORKSPACE` 的单一路径，realpath 后仍须位于 workspace；
- `format`：`text|json|sarif`，默认 `text`；
- `argusVersion`：严格 `X.Y.Z`，默认 `action/release.json` 的 exact version；
- `failOn`：`block|approval`，默认 `block`。

`argusVersion` 还必须落在 tested range，禁止 prerelease、build metadata、`latest`、
URL 或 repository override。`failOn` 真值表固定如下：

| decision/state | `failOn=block` | `failOn=approval` |
| --- | --- | --- |
| allow | success | success |
| block | failure | failure |
| allow-with-approval | success（output 保留审批态） | failure |
| operational error | failure | failure |

Action 先从固定 `https://api.github.com/repos/majiayu000/argus/releases/tags/v{version}`
取得 release/tag commit 和 asset metadata，要求 release 非 draft/non-prerelease 且
`immutable=true`。所有读取均使用 public unauthenticated endpoint，Action 不读取
调用方 `GITHUB_TOKEN`。REST 请求固定 `Accept: application/vnd.github+json` 与
`X-GitHub-Api-Version: 2026-03-10`，要求 JSON content-type 和 release/asset 字段闭集；
`immutable`/`digest` 缺失或类型错误不得按 false/空值降级。release artifact 下载只
允许 `api.github.com`，最多一次 302 到
`release-assets.githubusercontent.com`，不得将 `Authorization` 转发到 redirect。
manifest/checksum 各限 1 MiB、attestation bundle 限 4 MiB、binary 限 128 MiB，
单响应 30 秒、全流程 180 秒；
Content-Length 缺失时仍按 streaming bytes 截断。先用 GitHub REST asset
`digest=sha256:...` 与本地 digest 复核 manifest 和
`release_manifest.sigstore.json`，再以 argv 启动 runner 已安装的
`gh attestation verify --bundle release_manifest.sigstore.json`，同时固定：

- `--repo majiayu000/argus`
- `--signer-workflow majiayu000/argus/.github/workflows/release.yml`
- `--source-ref refs/tags/v{version}`
- `--source-digest {release_commit}`
- `--deny-self-hosted-runners`
- `--format json`

Action 必须预检 `gh attestation verify --help` 支持上述 flags；缺失/过旧时显式失败，
不退化为 checksum-only，也不从 Attestations API 取 bundle。`--bundle` 只固定本地
attestation input，不声称完全 offline；允许 `gh` 在同一 180 秒总时限内使用其内建
Sigstore/TUF 验证链取得 public trusted root，失败即 operational error，禁止从 release
下载自签 trusted root。它还必须解析成功验证 JSON，要求至少一个唯一 attestation、
SLSA provenance v1、GitHub OIDC issuer、GitHub-hosted runner以及与 flags 一致的
certificate source fields；零条、多条冲突或 malformed JSON 均失败。manifest 验证
后，按 OS/arch 选择 raw binary 与 `{target}.sigstore.json`，再重复 REST digest、
manifest SHA-256 和同一 local-bundle attestation policy 三重验证，之后才
chmod。首次执行固定为 `{binary} --version`，要求 exit 0、stdout byte-exact
`argus {argusVersion}\n`、stderr 为空并受同一 timeout/byte bounds 约束；wrong
embedded version、额外输出、nonzero 或 timeout 均 operational error，之后才允许扫描。
所有 subprocess 使用 executable+argv，不经 shell；stdout 限 64 MiB、stderr 限
1 MiB，超限/timeout/invalid UTF-8 均 operational failure。

运行映射固定为 package/lockfile=`argus scan {path}`、agent=`argus agent scan {path}`；
调用前 package 必须是 directory、lockfile 必须是 regular file，类型错配直接失败，
只追加闭集 `--format`。exit 0/1/2 都必须按所选格式解析完整 report，并分别要求
decision 为 allow/block/allow-with-approval；text 验证完整固定 header/body，JSON
验证当前 `ScanReport` 必需字段闭集，SARIF 验证 2.1.0 run/tool/invocation/result
结构。clean SARIF 可为 zero results，但必须有完整 run/tool/version/
`executionSuccessful=true` 且 exit 0；非空 results 的 decision 必须全等最终 decision。
空、截断、malformed、invalid UTF-8 或 exit/decision 矛盾均 operational error。

report 只在验证完成后原子写入 `RUNNER_TEMP`，SARIF 只输出路径、不自行上传。outputs
初始化为空：下载/校验/启动前失败时 `decision`/`exitCode`/`reportPath`/`sarifFile`
为空，`argusVersion` 只在输入/range 验证后填写；CLI exit 后 report validator 失败时
仅 `exitCode` 填实际 0/1/2，其余 report outputs 为空。完整 report 才填写
decision/reportPath，完整 SARIF 才填写 sarifFile。写完可用 outputs 后再按 `failOn`
真值表设置 conclusion；任何 operational error 一律 `setFailed`，禁止虚构 output。

## Planned Changes Manifest

<!-- specrail-planned-changes
{"version":1,"issue":92,"complete":true,"paths":[".github/workflows/action_dist.yml",".github/workflows/action_dogfood.yml",".github/workflows/release.yml","CHANGELOG.md","README.md","SECURITY.md","action.yml","action/dist/index.js","action/package-lock.json","action/package.json","action/release.json","action/src/contract.js","action/src/download.js","action/src/main.js","action/src/run.js","action/tests/action.test.js","action/tests/download.test.js","crates/argus-cli/tests/action_contract_cli.rs","docs/releasing.md","release/manifest.schema.json","scripts/package_release.py","scripts/tests/test_release_contract.py","scripts/tests/test_release_docs.py","scripts/tests/test_release_workflow.py","scripts/verify_release_assets.py","specs/GH92/product.md","specs/GH92/tasks.md","specs/GH92/tech.md"],"spec_refs":["specs/GH92/product.md","specs/GH92/tasks.md","specs/GH92/tech.md"]}
-->

## Product-to-Test Mapping

| Behavior invariant | Implementation area | Verification |
| --- | --- | --- |
| B-001 | tag/version/human gate | candidate fixture + forbidden dispatch/tag mismatch cases |
| B-002 | target matrix + Action selector | Node platform matrix tests |
| B-003 | packager/manifest/attestation jobs | deterministic rebuild + manifest negative matrix |
| B-004 | draft/publish needs graph + target smoke | candidate mode and mocked release state machine |
| B-005 | root Action + protected manual promotion contract | ruleset fixture + no workflow ref mutation |
| B-006 | `action.yml` + argv builder | `npm test --prefix action` input matrix |
| B-007 | bounded runner + report validators + outputs | 0/1/2/malformed/timeout/output-limit matrix |
| B-008 | downloader + REST/manifest/`gh` verifier | origin/redirect/digest/attestation negative matrix |
| B-009 | job-scoped permissions + pinned actions | workflow policy test and fork SARIF fixture |
| B-010 | README/CHANGELOG/SECURITY/docs | install/verify/revoke/human-gate review |

## 数据流

人工授权 tag 触发版本门禁与 native target builds；raw binaries/archives 汇聚成
manifest/checksums，完成 attestation 后进入 draft，全部复验后 publish immutable
release；新的明确人工授权下，受限 maintainer 才可将 `v1` branch 正常
fast-forward。Action 验证 immutable release、manifest 和选定 binary 后，以 argv
运行 Argus，将完整 report/退出状态映射为 outputs 和 step result。

交付分两阶段。实现 PR 只加入 Action、candidate/release workflow、local-bundle
fixture 和
operator 文档；README 必须继续诚实标记 pre-release/source install，PR/CI 不引用
尚不存在的 `v0.1.0` 或 `@v1`。管理员门满足且用户另行授权后，在一个连续发布窗口：
提交 release-prep 文档/CHANGELOG/SECURITY → tag 该 `main` commit → workflow publish
immutable release → maintainer 手工创建/fast-forward `v1` → 在 fresh Linux/macOS/
Windows runner 真实调用 `majiayu000/argus@v1` 并上传 SARIF → 只读审计 release/ref；
完成前 GH-92 保持 open。`action_dogfood.yml` 仅 `workflow_dispatch`，发布前不运行。

## 备选方案

- `curl | sh` 安装：与项目检测的风险模式冲突且难以验证执行前内容，拒绝。
- Action 每次 `cargo install`：慢、依赖工具链且不能提供同一发布物 provenance，拒绝。
- 自动发布所有 cross-compiled target：未 smoke 的二进制不应宣称支持，拒绝。
- `argus/action@v1`：该语法会指向不存在的 `argus/action` repository；根 Action 必须
  使用 `majiayu000/argus@v1`。
- 可移动 `v1` tag：更新需要 force push 且与 immutable release/tag 语义冲突；使用
  只允许 fast-forward 的受保护 `v1` branch。
- checksum-only 下载：无法证明 builder/ref；必须同时验证 GitHub attestation。

## 风险

- Release compromise：最小权限、environment protection、固定 actions 与 attestation。
- Repository settings absent：immutable release、tag ruleset、environment 是明确的
  administrator human gate；workflow 只读检查，不能自行创建或降级。
- Major branch mutation：另需 `v1` ruleset 与人工授权，workflow 无 promotion
  credential；高保障用户 pin immutable SemVer tag 或完整 commit。
- Node bundle drift：CI 从锁文件重建并比较 `dist`。
- Exit ambiguity：对 exit 0/1/2 均强制完整格式解析并匹配 decision；任一
  不完整/矛盾 report 都是 operational error，永不放行。
- `gh` availability：GitHub-hosted runner 已预装；self-hosted runner 必须预装支持
  required flags 的 GitHub CLI，否则 fail closed。
- Consumer credentials：Action 从 public immutable Release 下载 bundle，并用
  `--bundle` 验证；不假设调用方 token 可访问生产 repository 的 Attestations API。
  `gh` 仍可访问 Sigstore/TUF trusted-root 网络，这不是 offline mode。
- Revocation：immutable tag/asset 与 pinned consumer 无法被静默改写；先 advisory，
  再发布已验证 patch 并人工 fast-forward `v1`，明确通知 pinned 用户。

## 测试计划

- [ ] Rust workspace 与每目标 native binary smoke。
- [ ] Python unit：deterministic payload、bundle semantic reuse、bounds、
  duplicate/missing/tamper。
- [ ] Node unit：input、platform、redirect、download verification、argv、exit/report mapping。
- [ ] Candidate mode：assets/checksum/attestation plan 端到端验证且零 external mutation。
- [ ] 实现阶段离线 Action fixture；发布授权后才运行 package/lockfile/agent/SARIF
  fresh-runner dogfood。
- [ ] Workflow policy：permissions、full-SHA actions、无 force、candidate/publish
  隔离、缺 immutable/ruleset/environment 时拒绝 publish。

## 回滚方案

不得重写、删除或覆盖既有 immutable tag/asset，也不得把 `v1` 倒退或指向未发布的
普通 remediation commit。确认问题后先发布 security advisory；修复 commit 必须作为
新 patch 通过全部门禁并 publish immutable release，新的明确人工授权之后才可
fast-forward `v1`。旧 SemVer/commit pin 无静默即时撤回，文档必须列出受影响版本与
安全替代；源码构建仍保留。任何真实 tag/release/ref 变更都需要新的明确人工授权。

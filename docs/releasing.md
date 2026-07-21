# Argus 发布操作手册

本手册描述 GH-92 的管理员边界。仓库内 workflow 可以构建、验证和发布，但不能替代
管理员对 repository settings、tag、release 和 `v1` promotion 的独立授权。

## 1. 首次发布前的管理员门禁

在创建任何 tag 前，由仓库管理员只读核对并配置：

1. 启用 immutable releases。
2. 创建 active SemVer tag ruleset，限制 `v*` 的 create/update/delete。
3. 创建 exact `refs/heads/v1` ruleset，禁止 delete 和 non-fast-forward update。
4. 创建 `release` environment，配置 required reviewer、prevent self-review 和只允许
   SemVer tag 的 deployment policy。
5. 确认 `.github/workflows/release.yml` 之外没有发布凭据或 promotion token。

任一项缺失时，publish job 必须 fail closed。不要临时删除检查、改用 checksum-only，
也不要从源码分支生成一个看似正式的 Release。

## 2. Candidate（无外部状态变更）

从 Actions 手工运行 `release` workflow，选择唯一的 `candidate` mode。该路径执行 Rust
门禁、五个 native target build/smoke、确定性 archive/manifest/checksum 校验，但没有
`contents: write`、`id-token: write`，不会创建 attestation、tag、Release 或更新 ref。

重跑 candidate 后，核对每个 target 都产生一个 raw binary 与一个 archive，且
`python3 scripts/verify_release_assets.py --asset-dir release-assets` 通过。

## 3. 连续发布窗口

真实发布需要一次新的、明确的人工授权，并按以下顺序连续完成：

1. 在 release-prep commit 中把 README、CHANGELOG、SECURITY 与 `action/release.json`
   更新为准确版本；不要提前声明不存在的下载或 `@v1`。
2. 确认该 commit 在 `main`，创建对应的 immutable `vX.Y.Z` tag。
3. tag workflow 重跑全部质量与 native smoke；publish job 进入 `release` environment
   等待独立 reviewer。
4. workflow 生成 canonical manifest/checksums，对 manifest 和五个 raw binary 分别生成
   provenance bundle，完整复验后才 publish immutable Release。
5. workflow 只输出 `v1` 的 old/new SHA 与 ancestor proof。受限 maintainer 在新的人工
   授权下手工创建或 fast-forward `v1`；workflow 不持有 ref mutation 能力。
6. 手工运行 `action-dogfood`，在 fresh Linux/macOS/Windows runner 上验证 package、
   lockfile、agent 与 SARIF；fork PR 的 SARIF upload 必须保持权限安全。
7. 最后只读审计 tag、Release assets/digests/attestations、`v1` ref 和 workflow checks。

发布窗口中断时，不得跳步。草稿可以在其现有 bytes 完全一致时继续；冲突、缺失或损坏
asset 必须停止并调查，不能覆盖。publish 失败不得移动 `v1`。

## 4. Action 使用与 pin

Release 真正完成前，根 Action 仅是未发布实现。发布后普通使用者可 pin 受保护 major
branch；高保障环境应 pin immutable SemVer tag 或完整 commit。输入闭集是 `scanType`、
`path`、`format`、`argusVersion`、`failOn`，没有任意 args。

GitHub-hosted runner 提供 `gh`。self-hosted runner 必须预装支持 `--bundle`、
`--signer-workflow`、`--source-ref`、`--source-digest`、
`--deny-self-hosted-runners` 的版本；缺失时 Action fail closed。local bundle 固定被验证
的 attestation，但 `gh` 仍可能访问 Sigstore/TUF public trusted-root 服务，因此不应称为
完全离线验证。

退出语义：`allow=0`、`block=1`、`allow-with-approval=2`；下载/校验/启动/报告错误是
operational error。`failOn=block` 保留 approval output 但不失败，`failOn=approval`
对 approval 也失败；operational error 永远失败且不会伪造 decision/report output。

## 5. 撤回

不得重写或删除 immutable release/tag，不得把 `v1` 回退或指向普通修复 commit。先发布
security advisory，再发布通过完整流程的新 patch；新的人工授权之后才能 fast-forward
`v1`。通知所有 immutable version/commit pin 用户受影响范围与替代版本。

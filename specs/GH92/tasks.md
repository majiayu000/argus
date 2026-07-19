# Task Plan

## Linked Issue

GH-92

## Spec Packet

- Product: `product.md`
- Tech: `tech.md`

## 实现任务

- [ ] `SP92-T1` 冻结 release/Action 双版本域、target/asset/manifest schema 与 CLI report 判定契约，并实现 deterministic Python packager/verifier。Covers: B-001, B-002, B-003, B-007. Owner: release contract worker. Dependencies: none. Done when: `v0.1.0`/Cargo/Action default 与 `>=0.1.0,<0.2.0` range、五 target/runner/name、raw/archive/manifest/checksum/bundle 闭集、canonical JSON/duplicate-key policy、固定 archive metadata、duplicate/missing/extra/tamper、size/摘要等号边界与 CLI text/JSON/SARIF approval/operational fixture 均产生唯一结果，且不创建任何 Git ref/release/attestation。Verify: `python3 -m unittest discover -s scripts/tests -p 'test_release_*.py'`; `cargo test -p argus-cli --test action_contract_cli`.
- [ ] `SP92-T2` 实现 root Node24 Action、锁定依赖与 committed dist：camelCase 公开 API、闭集输入、workspace realpath、immutable release 查询、bounded HTTPS/single redirect、REST/manifest digest、release bundle/`gh attestation verify` policy、raw binary version self-check、argv runner、report outputs 和 `failOn`。Covers: B-002, B-005, B-006, B-007, B-008. Owner: Action worker. Dependencies: SP92-T1. Done when: 只修改 `action.yml` 与 `action/**`；五平台 selector、package-directory/lockfile-regular-file、default/range/prerelease/latest/URL/repository override、empty/invalid/outside-workspace/symlink、REST Accept/API-version/content-type/missing immutable or digest、draft/prerelease/mutable/missing/duplicate asset/bundle、origin/redirect/no-token/status/timeout/size/invalid UTF-8、三重摘要、signer workflow/ref/commit/OIDC/GitHub-hosted runner、零/冲突 attestation、missing/old `gh`、Sigstore/TUF trusted-root failure、`--version` wrong/extra/nonzero/timeout、0/1/2 empty/malformed/mismatch/output-limit、early/late operational no-data-blank outputs 与 failOn 真值表全部通过，subprocess 不经 shell、不查询 Attestations API且不把 local bundle 误称 fully offline。Verify: `npm ci --prefix action`; `npm test --prefix action`; `npm run package --prefix action`; `git diff --exit-code -- action/dist/index.js`.
- [ ] `SP92-T3` 实现 candidate/tag release workflow：版本/ancestor/admin/environment gate、五 native build/smoke、汇聚/attest、draft idempotency、immutable publish 复验与只读 `v1` promotion plan。Covers: B-001, B-002, B-003, B-004, B-005, B-009. Owner: workflow worker. Dependencies: SP92-T1; SP92-T2 contract frozen. Done when: 只修改 `.github/workflows/action_dist.yml` 与 `.github/workflows/release.yml`；所有 external actions 为 full SHA、权限按 job 最小化，candidate fixture 证明零 attestation/ref/release mutation，tag mismatch/non-main/immutable disabled/missing SemVer-tag or v1 ruleset/missing reviewer or self-review/tag deployment policy/deterministic payload conflict/partial draft合法 bundle 原样复用/缺 bundle 补齐/invalid-or-conflicting bundle/missing-or-oversize bundle/publish failure/non-descendant proposed v1 均得到唯一 fail-closed 或恢复结果；publish workflow 只输出 old/new SHA 与 ancestor proof，不持有 promotion secret，不更新 ref，且无 `--clobber`/force push/delete tag。Verify: `python3 checks/check_workflow.py --repo . --all-specs`; `python3 scripts/tests/test_release_workflow.py`; `rg -n '(force|--clobber|delete.*tag|update-ref|git push)' .github/workflows/release.yml`.
- [ ] `SP92-T4` 串行接入 local-bundle Action fixture、manual-only dogfood 与发布运维文档：实现阶段 README 保持 pre-release/source install，release-prep 模板定义 SemVer/Action pin、self-hosted `gh`、fork-safe SARIF、SECURITY/CHANGELOG、管理员/人工 gate 与撤回契约。Covers: B-006, B-007, B-009, B-010. Owner: integration and documentation worker. Dependencies: SP92-T2, SP92-T3 writable owners stopped. Done when: `.github/workflows/action_dogfood.yml` 仅 `workflow_dispatch` 且发布前不运行；当前 README 不声称不存在的 `v0.1.0`/`@v1`，operator 文档明确连续 release-prep→tag→publish→人工 v1 fast-forward→fresh-runner dogfood→只读审计顺序；没有 `curl|sh`、浮动 binary latest、任意 args、未发布 remediation 或自动 v1 mutation。Verify: `npm test --prefix action`; `python3 scripts/tests/test_release_docs.py`; `rg -n 'Pre-release|pre-release|unreleased' README.md`; `python3 scripts/tests/test_release_workflow.py`.

## 文件所有权与顺序

- SP92-T1 独占 `release/manifest.schema.json`、`scripts/package_release.py`、`scripts/verify_release_assets.py`、`scripts/tests/test_release_contract.py` 与 `crates/argus-cli/tests/action_contract_cli.rs`，先冻结 schema/fixture，之后这些 contract 文件只读。
- T1 后 SP92-T2 独占 `action.yml`、`action/**`；SP92-T3 独占 `.github/workflows/action_dist.yml`、`.github/workflows/release.yml` 与 `scripts/tests/test_release_workflow.py`。二者可并行，不得修改彼此文件或 T1 contract；契约变化须停止并退回 T1。
- T2/T3 writable owners 停止后 SP92-T4 独占 `.github/workflows/action_dogfood.yml`、`README.md`、`CHANGELOG.md`、`SECURITY.md`、`docs/releasing.md` 与 `scripts/tests/test_release_docs.py`；verification owner 最后只读。

## 验证

- [ ] `SP92-T5` 运行 targeted/all-spec、Rust/Node/Python、candidate、coverage、文件大小与最终 diff 门禁。Covers: B-001, B-002, B-003, B-004, B-005, B-006, B-007, B-008, B-009, B-010. Owner: verification owner. Dependencies: SP92-T1, SP92-T2, SP92-T3, SP92-T4. Done when: fresh 输出绑定最终 head；新增 Python/Node 行覆盖率至少 80%，download/attestation/publish/error critical paths 100%；candidate 运行证明未创建 attestation/tag/release/ref，README 仍诚实为 pre-release。Verify: `python3 checks/check_workflow.py --repo . --spec-dir specs/GH92`; `python3 checks/check_workflow.py --repo . --all-specs`; `cargo fmt --all -- --check`; `cargo check --workspace --all-targets`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace --all-targets`; `cargo run --quiet -p argus-cli -- corpus test --corpus corpus`; `npm ci --prefix action`; `npm test --prefix action -- --coverage`; `python3 -m coverage run -m unittest discover -s scripts/tests`; `python3 -m coverage report --fail-under=80`; `git diff --check origin/main...HEAD`; `wc -l action/src/*.js scripts/*.py`.

Product invariant 集合
`{B-001,B-002,B-003,B-004,B-005,B-006,B-007,B-008,B-009,B-010}` 与任务
`Covers:` 并集一致。

## Human Release Gate

- 当前远程 immutable releases 未启用、rulesets 为空、`release` environment 不存在；启用 immutable releases，建立限制 create/update/delete 的 active SemVer-tag ruleset 与 exact `refs/heads/v1` creation/update/delete/non-fast-forward ruleset，并配置 required reviewer、self-review prevention 和 tag deployment policy，均是 administrator `human_decision`。
- 实现 PR 只能交付 workflow/Action/candidate 证据，禁止创建真实 tag、Release、Marketplace listing 或移动 `v1`。用户另行授权后，在连续发布窗口提交最终 README/CHANGELOG/SECURITY release-prep、tag 该 `main` commit、publish immutable release、由受限 maintainer 手工创建/fast-forward `v1`、运行三平台真实 Action/SARIF smoke 并只读审计。
- 上述真实 release/ref/smoke 全部完成前 GH-92 保持 open；实现 PR 和 spec PR 都只能使用 `Refs #92`，不得使用 closing keyword。

## Handoff Notes

- #109 是 spec/task PR；合并并重新采集 route/duplicate evidence 前不得实现。
- GitHub-hosted runners 预装 `gh`；self-hosted runner 若缺 required attestation flags 必须失败。Action 使用 release 内 bundle，不需要调用方 token，禁止 Attestations API/checksum-only fallback。
- `v1` 是 protected branch 而不是 tag，只允许独立人工授权后向已验证 immutable release commit fast-forward；撤回也必须先发布新 patch，任何普通 remediation commit/force push 都不在流程中存在。

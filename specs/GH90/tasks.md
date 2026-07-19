# Task Plan

## Linked Issue

GH-90

## Spec Packet

- Product: `product.md`
- Tech: `tech.md`

## 实现任务

- [ ] `SP90-T1` 在 `argus-core` 定义可序列化的 `Ecosystem`、`PackageCoordinate` 与 `IntelSnapshotStatus` 闭集，并让 npm、PyPI、crates.io、Go、NuGet、Maven、RubyGems 与 Composer adapter 按 tech table 提供保留原始显示值的规范化坐标。Covers: B-003, B-006, B-010. Owner: coordinate implementation worker. Dependencies: none. Done when: 八生态 ecosystem string、name/version comparator、scope/namespace/group/module、purl、跨生态同名、future imported_at 与 injected clock fixture 均冻结，未启用情报时新增 JSON 字段省略。Verify: `cargo test -p argus-core coordinate_matrix`; `cargo test -p argus-core intelligence_status`; `cargo test --workspace --all-targets`.
- [ ] `SP90-T2` scaffold `argus-intel` 并实现 canonical OpenSSF archive URL/full-SHA/单 redirect 契约、闭集 OSV schema、512 MiB compressed/2 GiB expanded/100,000 entry/100,000 record/2 MiB advisory/32-component 限制、safe-entry 校验、规范化排序、稳定 records digest、覆盖 metadata 与 records 的 per-import snapshot digest 及 file-fsync/rename/dir-fsync 原子导入。Covers: B-001, B-002, B-008, B-009. Owner: import implementation worker. Dependencies: none. Done when: 请求/final URL/root dir/revision 一致，相同 revision 的 records 区块与 digest 字节稳定；source/revision/schema/archive digest/imported_at/records 任一篡改都使 snapshot digest 校验失败；非法 source/SHA/redirect/path/type/duplicate、所有等号边界与超限一、malformed/schema 不兼容、symlink target、写入/fsync/中断均返回错误且不替换旧 snapshot，扫描路径测试证明零网络访问。Verify: `cargo test -p argus-intel import_source_contract`; `cargo test -p argus-intel deterministic_snapshot`; `cargo test -p argus-intel snapshot_integrity`; `cargo test -p argus-intel atomic_import`; `cargo test -p argus-intel import_limits`.
- [ ] `SP90-T3` 实现 snapshot fail-closed loader、唯一键只读索引与 tech table 指定的八生态 exact/SEMVER/ECOSYSTEM comparator，严格处理 introduced/fixed/last_affected/limit、多 affected、overlap、advisory aliases 与 withdrawn。Covers: B-004, B-005, B-007. Owner: matcher implementation worker. Dependencies: SP90-T1, SP90-T2. Done when: exact/range 取并集、邻近版本不命中、alias 仅作排序 evidence、withdrawn 不进入 active matcher；未知 range/GIT、倒序/冲突/未闭合 event、duplicate ID、active/withdrawn 冲突、缺失/摘要不符/损坏/不兼容 snapshot 均 operational error；命中为 Critical/block 并包含完整 evidence。Verify: `cargo test -p argus-intel osv_match_matrix`; `cargo test -p argus-intel malicious_finding`; `cargo test -p argus-intel malformed_matrix`.
- [ ] `SP90-T4` 接入 `intel import`、`intel status` 与各生态扫描的显式 `--malicious-db` post-processor，重新派生 block decision，并把 typed intelligence status 映射到 JSON `intelligence`、text 段和 SARIF run properties。Covers: B-005, B-006, B-007, B-010. Owner: CLI, renderer, and documentation worker. Dependencies: SP90-T1, SP90-T2, SP90-T3. Done when: 默认扫描行为和网络请求数不变；启用后八生态命中均 Critical/block，无命中仍输出 source/revision/imported_at/age_seconds/archive/records/snapshot digests/no_match，missing/corrupt/incompatible/future 数据在 renderer 前失败，malicious intel 文案与 GH-94 vulnerability 查询保持分离。Verify: `cargo test -p argus-cli --test intel_cli`; `cargo test -p argus-cli --test intel_cli no_match_scope`; `cargo test -p argus-cli --test intel_cli corrupt_db`; `cargo test -p argus-cli sarif_intelligence_properties`; `rg -n "known-malicious-package|malicious-db|snapshot|GH-94" README.md docs/supply-chain-attacks.md`.

## 并行拆分

- SP90-T1 独占 `crates/argus-core/src/lib.rs` 和八个 adapter 的 `src/lib.rs` 与
  core unit tests；SP90-T2 先独立 scaffold `argus-intel`，再独占其 import、
  normalize、OSV、snapshot 与 import tests，因此两者的验证不互相依赖，可在文件
  所有权明确的独立 worktree 并行。
- SP90-T3 与 SP90-T2 共用 `argus-intel` 文件，必须在 SP90-T2 稳定后由同一
  integration owner 串行完成。
- SP90-T4 独占 CLI、CLI integration tests 与文档，但必须等 SP90-T1/T2/T3
  的类型、错误和 rule ID 冻结后再写，禁止提前复制同义 coordinate 或 matcher。
- verification owner 在所有 writable lane 停止后串行运行完整 workspace gates。

## 验证

- [ ] `SP90-T5` 运行 targeted、workspace、SpecRail、corpus 与覆盖率门禁。Covers: B-001, B-002, B-003, B-004, B-005, B-006, B-007, B-008, B-009, B-010. Owner: verification owner. Dependencies: SP90-T1, SP90-T2, SP90-T3, SP90-T4. Done when: 八生态和 exact/range/withdrawn/alias/malformed 矩阵、text/JSON/SARIF、全部错误负例及既有测试通过；新代码行覆盖率至少 80%，fresh 输出绑定最终 head。Verify: `python3 checks/check_workflow.py --repo . --all-specs`; `cargo fmt --all -- --check`; `cargo check --workspace --all-targets`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace --all-targets`; `cargo run --quiet -p argus-cli -- corpus test --corpus corpus`; `cargo llvm-cov -p argus-intel --summary-only`.

Product invariant 集合
`{B-001,B-002,B-003,B-004,B-005,B-006,B-007,B-008,B-009,B-010}` 与上述任务
`Covers:` 并集一致。

## Handoff Notes

- #110 是 spec/task PR；合并并重新采集 duplicate-work/implement route 证据前，
  不得开始 GH-90 代码实现。
- GH-90 必须先落地共享 `PackageCoordinate`；GH-91 与 GH-94 实现只能复用该类型，
  禁止提交同义生态/坐标模型。
- import 是唯一联网路径，必须固定 OpenSSF 来源与 revision；普通扫描不得联网，
  也不得把未命中表述为安全证明。
- snapshot 损坏、缺失或不兼容是 operational error，不得返回空 finding 或沿用
  未验证的旧/部分数据。

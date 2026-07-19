# Task Plan

## Linked Issue

GH-91

## Spec Packet

- Product: `product.md`
- Tech: `tech.md`

## 实现任务

- [ ] `SP91-T1` 在 GH-90 `PackageCoordinate` 已进入 main 后 scaffold `argus-lockfile`，实现 64 MiB/100,000 records/64 nesting/1 MiB scalar/1,000,000 scalars 的 bounded reader、duplicate/YAML-complexity guards、`LockfileFormat` detection/version matrix、`NormalizedDependency`/coverage/error 闭集与稳定排序。Covers: B-001, B-002, B-003, B-008, B-009. Owner: model and detector worker. Dependencies: GH-90 implementation merged. Done when: 根/crate manifest、`Cargo.lock`、`lib.rs`、`parsers/mod.rs` 已一次性声明九 parser module、共享 API/trait 与全部依赖并用 compile-only stub 冻结；basename/signature/version 的正例、missing/conflict/ambiguous/unknown/new-version、所有等号/超限一、duplicate key、YAML alias/tag/merge、重复坐标/平台/condition/乱序 fixture 都产生技术规范规定的唯一结果，crate 无 transport/process dependency。Verify: `cargo test -p argus-lockfile detect_matrix`; `cargo test -p argus-lockfile normalized_records`; `cargo test -p argus-lockfile resource_limits`; `cargo tree -p argus-lockfile`.
- [ ] `SP91-T2` 实现 PackageLock 2/3、Yarn Classic 1/Berry 4/6/8 与 pnpm 5.4/6/9 parser，完整归一化 registry/url/git/link/workspace source、integrity、locator、condition 与 coverage count。Covers: B-002, B-003, B-006, B-007, B-008. Owner: JavaScript lockfile worker. Dependencies: SP91-T1. Done when: 只修改 `package_lock.rs`、`yarn.rs`、`pnpm.rs` 与 `js_formats.rs`，不修改 manifest/lockfile/public module；每种版本的 registry/git/local/duplicate/multi-version/clean/missing/weak/invalid/unsupported-section fixture 均通过，entry 总数与 recognized count 守恒，任一未理解 entry 返回 partial operational error。Verify: `cargo test -p argus-lockfile js_format_matrix`; `cargo test -p argus-lockfile js_integrity_matrix`.
- [ ] `SP91-T3` 实现 Poetry 1.1/2.0/2.1、uv 1、Cargo 3/4 与 go.sum grammar-v1 parser，按 per-format matrix 归一化 files/distributions/checksum、registry/git/path source、platform/marker 与 go module/go.mod 双记录。Covers: B-002, B-003, B-006, B-007, B-008. Owner: Python Rust Go lockfile worker. Dependencies: SP91-T1. Done when: 只修改 `poetry.rs`、`uv.rs`、`cargo.rs`、`go_sum.rs` 与 `python_rust_go_formats.rs`，不修改 manifest/lockfile/public module；四类格式的全部接受版本及邻近拒绝版本、strong/missing/invalid/unavailable、git commit/mutable、duplicate/condition/partial fixture 通过；Poetry 同 package 多 artifact 的 valid+invalid、valid+missing、valid+weak 组合逐 artifact 保留 locator/evidence，任一 sibling 不得被合法 hash 降级或隐藏。Verify: `cargo test -p argus-lockfile python_rust_go_format_matrix`; `cargo test -p argus-lockfile python_rust_go_integrity_matrix`.
- [ ] `SP91-T4` 实现 Bundler major 2/3/4 与 Composer schema-v1 parser，保留 GEM/GIT/PATH/CHECKSUMS、packages/packages-dev、dist/source、reference/shasum、dependency group 与原生 locator，并执行 coverage 守恒。Covers: B-002, B-003, B-006, B-007, B-008. Owner: Ruby Composer lockfile worker. Dependencies: SP91-T1. Done when: 只修改 `bundler.rs`、`composer.rs` 与 `ruby_composer_formats.rs`，不修改 manifest/lockfile/public module；Bundler 2.4 无 CHECKSUMS、2.5/2.6/3 有无 CHECKSUMS、4 有无 self-checksum、self-checksum 与 BUNDLED WITH version exact 匹配/错配/重复/非法 digest、platform lock-name、missing/unmatched/duplicate/mixed algorithm，以及 registry/git/path/source-only/dist、SHA-1 weak、empty shasum optional-absent、mutable/full commit、duplicate/group/unknown section fixture 均按 matrix 产出完整记录/finding 或 operational error。Verify: `cargo test -p argus-lockfile ruby_composer_format_matrix`; `cargo test -p argus-lockfile ruby_composer_integrity_matrix`.
- [ ] `SP91-T5` 实现 exact-host/user allowlist、HTTP/HTTPS/SSH/scp-like git、mutable VCS 与 integrity policy，接入 CLI/共享 decision、删除旧 npm-only parser，并更新 text/JSON/SARIF integration tests、README 与攻击目录。Covers: B-004, B-005, B-006, B-007, B-010. Owner: serial integration, policy, CLI and documentation worker. Dependencies: SP91-T2, SP91-T3, SP91-T4 writable owners stopped. Done when: 已串行接收 root/crate manifest、`Cargo.lock` 与 public integration 文件所有权；Critical/High blockers 优先、weak-only approval、unavailable Info 不改变 allow；HTTP 不可被 allowlist 放行，host exact/IDNA/invalid matrix通过；成功 report 保持 exit 0/1/2，unknown/ambiguous/new-version/partial/parse/limit 为 exit 2 + stderr + empty stdout，所有格式测试证明无 child process/loopback connection。Verify: `cargo test -p argus-lockfile source_policy`; `cargo test -p argus-lockfile vcs_refs`; `cargo test -p argus-lockfile integrity_matrix`; `cargo test -p argus-cli --test lockfile_cli`.

## 并行拆分

- SP91-T1 独占根 `Cargo.toml`、`Cargo.lock`、crate `Cargo.toml`、`lib.rs`、
  `parsers/mod.rs`、`bounds.rs`、`detect.rs`、`model.rs` 与 detection/resource tests；
  先声明全部 parser module/API/dependency 和 compile-only stub，再冻结 public 文件。
- SP91-T2 只写 `package_lock.rs`、`yarn.rs`、`pnpm.rs`、`js_formats.rs`；SP91-T3
  只写 `poetry.rs`、`uv.rs`、`cargo.rs`、`go_sum.rs`、
  `python_rust_go_formats.rs`；SP91-T4 只写 `bundler.rs`、`composer.rs`、
  `ruby_composer_formats.rs`。三者可并行且不得改 manifest、`Cargo.lock`、public module
  或彼此文件。
- 三个 parser owner 停止写入后，SP91-T5 串行接收 root/crate manifest、
  `Cargo.lock` 与 public integration 文件所有权，并独占 `policy.rs`、CLI、rules
  decision、CLI integration test 与文档；contract 变更必须先停 lane 并退回 T1。
- verification owner 在所有 writable owner 停止后只读运行 workspace gates。

## 验证

- [ ] `SP91-T6` 运行 targeted、workspace、SpecRail、corpus 与覆盖率门禁。Covers: B-001, B-002, B-003, B-004, B-005, B-006, B-007, B-008, B-009, B-010. Owner: verification owner. Dependencies: SP91-T1, SP91-T2, SP91-T3, SP91-T4, SP91-T5. Done when: 九格式版本/正负/partial/invalid/resource matrix、text/JSON/SARIF/exit、零 process/network、全部既有测试通过；新代码行覆盖率至少 80%，parser/policy/error critical paths 100%，fresh 输出绑定最终 head。Verify: `python3 checks/check_workflow.py --repo . --all-specs`; `cargo fmt --all -- --check`; `cargo check --workspace --all-targets`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace --all-targets`; `cargo run --quiet -p argus-cli -- corpus test --corpus corpus`; `cargo llvm-cov -p argus-lockfile --summary-only`.

Product invariant 集合
`{B-001,B-002,B-003,B-004,B-005,B-006,B-007,B-008,B-009,B-010}` 与上述任务
`Covers:` 并集一致。

## Handoff Notes

- #108 是 spec/task PR；合并后 GH-91 implementation 仍必须等待 GH-90 implementation
  合并并重新跑 duplicate-work/implement route gate，禁止临时复制
  `PackageCoordinate`。
- partial 是 operational error，不是 finding/approval report；不得为兼容旧草案恢复
  `lockfile-partial-analysis`。
- go.sum 与 Bundler 不提供 registry content hash 时使用
  `unavailable-by-format` Info，不得制造 missing/hash verified 结论。
- 用户 allowlist 只增加 exact host，不能放行 HTTP、URL parse failure 或 mutable VCS。

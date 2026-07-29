# Task Plan

## Linked Issue

GH-94

## Spec Packet

- Product: `product.md`
- Tech: `tech.md`

## 实现任务

- [x] `SP94-T1` 在 GH-90/GH-91 implementations 合并后建立共享契约与 `argus-osv` scaffold：复用 `PackageCoordinate`/`NormalizedDependency`/shared OSV comparator，把共享 schema 闭集补到官方 tags 1.0.0..1.8.0（排除不存在的 1.7.1），并实现 normalized advisory/severity/source/evidence model、数字 bounds 与稳定排序。Covers: B-001, B-002, B-004, B-005, B-009. Owner: shared model worker. Dependencies: GH-90 implementation merged; GH-91 implementation merged. Done when: 八生态 exact coordinate、local exclusion/external incomplete、absent=legacy-1.0.0/explicit-supported/null/不存在/unknown schema、affected block 中 exact-version 只保留真正命中 sibling range/interval、CVSS v2/v3/v4/Ubuntu/missing/invalid、1.8.0 NVD/CNA/SELF source、alias/withdrawn/duplicate locator fixture 均得到唯一结果，`argus-osv` 无 duplicate ecosystem/OSV/lockfile parser。Verify: `cargo test -p argus-osv model_contract`; `cargo test -p argus-osv severity_matrix`; `cargo test -p argus-intel osv_schema_versions`; `cargo tree -p argus-osv`.
- [x] `SP94-T2` 实现固定 OSV HTTPS client：1,000-query stable batches、per-coordinate page-token continuation、唯一 ID detail hydration、streaming byte/time/request/concurrency bounds、zero redirect 与 typed transport errors。Covers: B-003, B-004, B-006. Owner: transport worker. Dependencies: SP94-T1. Done when: result position/length、subset pagination、token repeat/page cap、summary duplicate/modified interval conflict、官方 6 位 batch/9 位 detail precision、0 位边界、区间外真实 race、详情 ID/affected mismatch、race retry once、HTTP/TLS/DNS/status/content-type/timeout/body-limit/detail-limit/total-limit fixture 全部 fail closed，测试 transport 是唯一可替换 endpoint。Verify: `cargo test -p argus-osv --test client`; `cargo test -p argus-osv batch_transport`; `cargo test -p argus-osv snapshot_consistency`.
- [x] `SP94-T3` 实现单 envelope cache transaction：handle-relative no-follow path adapter、shared/exclusive lock、generation merge、冻结字段/JCS digest 输入域、512 MiB/100,000-entry bounds、0600/0700、O_EXCL temp+fsync+renameat+directory-fsync，以及 fresh/offline/authorized-stale 状态机。Covers: B-006, B-007, B-008, B-010. Owner: cache worker. Dependencies: SP94-T1. Done when: hit/zero-hit/miss/stale/future/corrupt/oversize/permission/static symlink/symlink-swap/interrupted-write/concurrent non-conflict/conflicting same-time digest/raw-order-equivalent-response fixture 通过；平台无 race-free primitive 明确失败，网络失败未写任一新 entry，network mode 不回退 stale，输出无绝对路径。Verify: `cargo test -p argus-osv --test cache`; `cargo test -p argus-osv cache_contract`; `cargo test -p argus-osv cache_concurrency`.
- [x] `SP94-T4` 在 transport/cache owner 停止后实现 resolver/report：按 query key 选择 fresh cache 或完整网络 snapshot，严格复验详情，用 active/stale 成功状态与 typed failure 生成 per-coordinate advisory evidence 和独立 decision。Covers: B-004, B-005, B-006, B-008, B-009. Owner: resolver and report worker. Dependencies: SP94-T2, SP94-T3. Done when: affected/unaffected/aliased/malformed/unknown-severity、多坐标同 ID、同坐标多 ID、withdrawn 首轮重试/二轮失败、complete-no-match、network/cache/mixed/offline-fresh/offline-stale source mode、threshold 与 blocking-precedence fixture 通过；任何 partial path 在 cache commit/report renderer 前退出。Verify: `cargo test -p argus-osv --test resolver`; `cargo test -p argus-osv advisory_evidence`; `cargo test -p argus-osv result_states`; `cargo test -p argus-osv intel_separation`.
- [x] `SP94-T5` 串行拆出 `router.rs` 与 `sarif_vulns.rs`，接入无歧义 CLI、text/JSON/SARIF 和文档，更新 root/CLI manifests 与 `Cargo.lock`，保持 package/lockfile 两模式、错误 stdout 边界和 vulnerability/malicious/provenance/heuristic 文案隔离。Covers: B-001, B-002, B-006, B-008, B-009, B-010. Owner: serial CLI integration worker. Dependencies: SP94-T4; all prior writable owners stopped. Done when: package 八生态、九类 lockfile、required cache-dir、format default/enum、offline/allow-stale/max-age-seconds option constraints、exit 0/1/2、empty stdout on error、三 renderer 的 source-mode/cache-age 稳定快照、cache label、README distinction 和 no package-manager fixture 通过；`main.rs`/`sarif.rs` 均低于 800 行且无 duplicate renderer。Verify: `cargo test -p argus-cli --test vulns_cli`; `cargo test -p argus-cli vulns_help`; `wc -l crates/argus-cli/src/main.rs crates/argus-cli/src/sarif.rs`; `cargo tree -p argus-osv`.

## 文件所有权与顺序

- SP94-T1 独占 root/`argus-osv`/`argus-intel` scaffold manifests、`Cargo.lock`、core/shared OSV files、`lib.rs`、`model.rs`、`normalize.rs`、`severity.rs`，预声明所有 module/API/dependency 后冻结 public 文件。
- SP94-T2 只写 `client.rs`、`tests/client.rs`；SP94-T3 只写 `cache.rs`、`tests/cache.rs`，二者在 T1 后可并行且不得修改 manifest、`Cargo.lock`、public module 或彼此文件。
- T2/T3 writable owner 退出后，SP94-T4 独占 `resolver.rs`、`report.rs`、`tests/resolver.rs`；contract 变化须停止并退回 T1 重新冻结。
- SP94-T5 串行接收 root/CLI manifests 与 `Cargo.lock` ownership，并独占 CLI `main.rs`/`router.rs`/`vulns.rs`/`sarif.rs`/`sarif_vulns.rs`/tests/README/docs；SP94-T6 在所有 writable owner 退出后只读验证。

## 验证

- [x] `SP94-T6` 运行 SpecRail、targeted、workspace、corpus、资源/覆盖率和最终 diff 门禁。Covers: B-001, B-002, B-003, B-004, B-005, B-006, B-007, B-008, B-009, B-010. Owner: verification owner. Dependencies: SP94-T1, SP94-T2, SP94-T3, SP94-T4, SP94-T5. Done when: 所有 mock 网络/cache/renderer/decision fixture 与既有测试通过；新代码行覆盖率至少 80%，pagination/detail/consistency/cache-commit/error critical paths 100%，fresh 输出绑定最终 head。Verify: `python3 checks/check_workflow.py --repo . --spec-dir specs/GH94`; `python3 checks/check_workflow.py --repo . --all-specs`; `cargo fmt --all -- --check`; `cargo check --workspace --all-targets`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace --all-targets`; `cargo run --quiet -p argus-cli -- corpus test --corpus corpus`; `cargo llvm-cov -p argus-osv --summary-only`; `git diff --check origin/main...HEAD`.

Product invariant 集合 `{B-001,B-002,B-003,B-004,B-005,B-006,B-007,B-008,B-009,B-010}` 与任务 `Covers:` 并集一致。

## Handoff Notes

- #111 是 spec/task PR；GH-94 implementation 必须等待 GH-90 和 GH-91 implementation 都合并并 fresh rerun duplicate/route gates，禁止 stacked duplicate type/parser。
- querybatch summary 不是 advisory detail；所有 per-query page token 必须耗尽，再 hydrate/复验每个唯一 ID，最后才允许 no-match/cache/report。
- OSV schema 当前闭集到 1.8.0；新版本须先更新 shared parser/spec/fixture，禁止宽松 major fallback；POST query 不返回 withdrawn，意外 withdrawn detail 属于一致性失败。
- `--allow-stale` 只授权完整 offline stale snapshot，不授权 missing/corrupt/partial，也不授权网络失败 fallback。

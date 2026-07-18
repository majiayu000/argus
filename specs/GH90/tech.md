# Tech Spec

## Linked Issue

GH-90

## Product Spec

Link to `product.md`.

## Codebase Context

| Area | Verified anchor | Current behavior | Why relevant |
| --- | --- | --- | --- |
| shared report model | `crates/argus-core/src/lib.rs:53` | finding 可承载稳定 rule、detail 与 evidence | 情报命中可保持现有输出 schema |
| package report | `crates/argus-core/src/lib.rs:116` | report 只有可选 name/version，没有生态类型 | 需要建立共享、强类型 coordinate 契约 |
| npm fetch merge | `crates/argus-fetch/src/lib.rs:232` | 源码与 provenance findings 在 fetch 尾部合并 | 各生态应在统一 report 后执行情报匹配 |
| CLI command router | `crates/argus-cli/src/main.rs:56` | 顶层命令覆盖 scan/fetch/agent/corpus | 增加显式 intel import/status 与数据库参数 |
| output boundary | `crates/argus-cli/src/main.rs:566` | report 完成后才输出 | 数据库错误必须发生在 renderer 之前 |
| transport policy | `crates/argus-fetch/src/lib.rs:101` | npm 已有容量、host 与 redirect 策略 | 导入器沿用同类 fail-closed 边界 |

## Proposed Design

先在 `argus-core` 增加序列化的 `Ecosystem` 闭集与 `PackageCoordinate`，包含生态、
canonical name、exact version、可选 purl 和原始显示值。八个 fetch adapter 在构造
报告时提供该坐标；为避免破坏现有 JSON，坐标作为新增可选字段并在本功能路径要求
存在。GH-91 与 GH-94 后续复用该类型，不再定义第二套坐标模型。

新增 `argus-intel` crate，分为 `osv` 输入模型、`normalize`、`snapshot` 与 `matcher`。
快照采用版本化 JSON envelope 加按键排序的记录体与 SHA-256 摘要；`imported_at`
在 envelope 中，不参与记录体摘要。matcher 加载时验证 schema、摘要和唯一键，再
将 `(ecosystem, canonical_name)` 建为只读索引，按 exact/range/withdrawn 语义匹配。

CLI 增加 `intel import --source ... --revision ... --output ...` 与 `intel status`；
扫描命令通过统一 `--malicious-db <path>` 显式启用。import 仅允许配置的 OpenSSF
GitHub raw/archive 主机，限制总字节、文件数与单 advisory 大小，写同目录临时文件、
fsync 后 rename。扫描仅读取本地文件。

各生态 fetch 返回 report 后由 CLI 的共享 post-processor 匹配一次，将命中 finding
合并并重新派生 decision。rule ID 为 `known-malicious-package`；detail/evidence 保留
advisory、revision、range 与坐标。malicious 与 vulnerability 使用独立数据库参数、
rule family 和文案。

## Planned Changes Manifest

<!-- specrail-planned-changes
{"version":1,"issue":90,"complete":true,"paths":["Cargo.lock","Cargo.toml","README.md","crates/argus-cli/Cargo.toml","crates/argus-cli/src/intel.rs","crates/argus-cli/src/main.rs","crates/argus-cli/tests/intel_cli.rs","crates/argus-core/src/lib.rs","crates/argus-intel/Cargo.toml","crates/argus-intel/src/lib.rs","crates/argus-intel/src/matcher.rs","crates/argus-intel/src/normalize.rs","crates/argus-intel/src/osv.rs","crates/argus-intel/src/snapshot.rs","crates/argus-intel/tests/fixtures.rs","docs/supply-chain-attacks.md","specs/GH90/product.md","specs/GH90/tech.md"],"spec_refs":["specs/GH90/product.md","specs/GH90/tech.md"]}
-->

## Product-to-Test Mapping

| Behavior invariant | Implementation area | Verification |
| --- | --- | --- |
| B-001 | OSV importer + snapshot envelope | `cargo test -p argus-intel import_source_contract` |
| B-002 | normalized sorting + record digest | `cargo test -p argus-intel deterministic_snapshot` |
| B-003 | core coordinate + normalizer | `cargo test -p argus-intel ecosystem_name_matrix` |
| B-004 | matcher range/withdrawn logic | `cargo test -p argus-intel osv_match_matrix` |
| B-005 | finding builder + decision merge | `cargo test -p argus-intel malicious_finding` |
| B-006 | status/report metadata | `cargo test -p argus-cli --test intel_cli no_match_scope` |
| B-007 | snapshot loader + CLI error path | `cargo test -p argus-cli --test intel_cli corrupt_db` |
| B-008 | atomic importer | `cargo test -p argus-intel atomic_import` |
| B-009 | import transport policy + offline matcher | `cargo test -p argus-intel import_limits` |
| B-010 | ecosystem fixtures + renderers | `cargo test -p argus-cli --test intel_cli` |

## 数据流

显式 import 下载固定 revision，解析 OSV、规范化、排序并原子写快照。扫描时 CLI
从各生态 report 取得 `PackageCoordinate`，本地 matcher 查询只读索引，生成 findings
并重新派生 decision，最后交给既有 renderer。扫描过程没有网络边。

## 依赖与顺序

GH-90 首先建立 `argus-core::PackageCoordinate`。GH-91 的 lockfile normalized record
和 GH-94 的 OSV query 都必须复用它；若并行实现，后两者在合并前 rebase 到该公共
契约，禁止各自提交同义类型。

## 备选方案

- 扫描时直接查询 GitHub：破坏离线、可重复与可用性边界，拒绝。
- 仅按包名 hash set：无法处理生态、版本范围与 withdrawn，拒绝。
- 与 CVE 数据合并成一个 finding：证据语义和处置不同，拒绝。

## 风险

- Supply chain：情报源本身可被篡改；固定 revision、摘要与 provenance 元数据缓解。
- Compatibility：新增可选 report coordinate；现有字段与 renderer 保持兼容。
- Resource abuse：导入文件数/字节/记录数全部硬限制。
- Staleness：输出 snapshot age，不静默声称最新。

## 测试计划

- [ ] Unit：八生态 normalization、OSV range、withdrawn、alias 与 malformed。
- [ ] Integration：原子更新、中断、损坏快照与离线匹配。
- [ ] CLI：import/status、八生态命中、text/JSON/SARIF、退出码。
- [ ] Repository：workspace check/test 与 corpus test。

## 回滚方案

删除扫描 post-processor、intel CLI 和新 crate 即恢复原行为；可选 coordinate 字段可
保留供后续功能使用或一并回滚。快照是用户选择的独立文件，无仓库数据迁移。

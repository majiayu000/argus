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
| SARIF renderer | `crates/argus-cli/src/sarif.rs:14` | 从完成的 `ScanReport` 生成 SARIF run/results | 无命中时 snapshot metadata 必须位于 run properties |
| transport policy | `crates/argus-fetch/src/lib.rs:101` | npm 已有容量、host 与 redirect 策略 | 导入器沿用同类 fail-closed 边界 |

## Proposed Design

先在 `argus-core` 增加序列化的 `Ecosystem` 闭集与 `PackageCoordinate`，包含生态、
canonical name、exact version、派生 purl 和原始显示值；再增加可选
`IntelSnapshotStatus`，字段固定为 canonical source、revision、archive/records
SHA-256、snapshot SHA-256、imported_at RFC 3339 UTC、在 scan 起点用可注入时钟计算的非负整数
`age_seconds`，以及 `matched`/`no_match` 闭集状态。八个 fetch adapter 在构造 report
时提供坐标；启用情报时坐标/status 必须存在，未来时间、缺字段或无法规范化均为
operational error。未启用时两个新增字段省略，保持现有 JSON 兼容。GH-91 与 GH-94
后续复用这些类型，不再定义第二套坐标/情报状态模型。

新增 `argus-intel` crate，分为 `import`、`osv` 输入模型、`normalize`、`snapshot`
与 `matcher`。快照采用版本化 JSON envelope；其中 deterministic records 区按
advisory ID、ecosystem、canonical name 与 range key 排序并计算 SHA-256；
不进入 records digest 的 metadata 区保存 `imported_at` 与 archive SHA-256。因此
相同 revision 重导入时 records 字节与摘要相同，完整 envelope 只允许
`imported_at` 及其派生的 `snapshot_sha256` 不同。matcher 加载时先重算 records
SHA-256，再对除 `snapshot_sha256` 字段自身外的 envelope object 采用 RFC 8785
JSON Canonicalization Scheme（JCS）生成 UTF-8 bytes；该 object 包含 source、
revision、schema versions、archive/records digests、imported_at 与 records。
对这些 bytes 计算 per-import snapshot SHA-256；任一不符均失败。校验唯一键与
metadata 后才将 `(ecosystem, canonical_name)` 建为只读索引。

CLI 增加 `intel import --source
https://github.com/ossf/malicious-packages --revision <sha> --output <path>` 与
`intel status`；`--source` 只接受这一个无 userinfo/query/fragment 的 canonical
literal，revision 只接受 40 位小写十六进制 commit SHA。客户端自行构造
`https://github.com/ossf/malicious-packages/archive/<sha>.tar.gz`，最多接受一次
redirect，且目标必须精确为
`https://codeload.github.com/ossf/malicious-packages/tar.gz/<sha>`；任何其他
scheme/host/port/path 或再次 redirect 均失败。最终 URL、archive 唯一根目录
`malicious-packages-<sha>/` 与请求 SHA 必须一致，archive SHA-256 随 snapshot 保存。
只读取根目录下 `osv/malicious/**/*.json` 与 `osv/withdrawn/**/*.json`；其他普通文件
计入 archive bounds 但不进入 records。

### Import bounds 与 archive 安全

| 边界 | 固定值/行为 |
| --- | --- |
| compressed response | 最多 512 MiB；缺失/错误 Content-Length 仍以 streaming counter 强制 |
| expanded bytes | 所有 entry 合计最多 2 GiB |
| archive entries | 最多 100,000 |
| OSV records | 最多 100,000 |
| single advisory | 最多 2 MiB |
| relative path depth | 根目录以下最多 32 components；UTF-8 only |
| entry type | 只允许 regular file/directory；absolute、`.`/`..`、NUL、symlink、hardlink、device、FIFO 与 duplicate normalized path 全部拒绝 |
| redirect | 恰好零或一次；若发生只能是上述 github.com → codeload.github.com exact target |

import 在目标目录创建 mode `0600` 的唯一临时文件；校验完整 archive、records 与
snapshot 后依次 fsync 临时文件、rename 到目标、fsync 父目录。目标或任一父路径为
symlink、目标不是 regular file、rename/fsync 失败时返回错误；旧 snapshot 保持不变。
扫描命令通过统一 `--malicious-db <path>` 显式启用，只打开本地 regular file，
不调用 import transport。

### Coordinate 闭集

| Variant | OSV ecosystem | canonical name | version/range comparator | purl type |
| --- | --- | --- | --- | --- |
| Npm | `npm` | registry 返回的 `@scope/name`，ASCII lowercase，保留 `/` | SemVer；只接受 `SEMVER` range | `npm` |
| PyPI | `PyPI` | PEP 503：lowercase，连续 `[-_.]+` 归一为 `-` | PEP 440；只接受 `ECOSYSTEM` range | `pypi` |
| CratesIo | `crates.io` | ASCII lowercase，`-` 与 `_` 保持不同 | SemVer；只接受 `SEMVER` range | `cargo` |
| Go | `Go` | proxy 解码后的 module path，case-sensitive | Go semantic version（比较时规范化前导 `v`）；只接受 `SEMVER` range | `golang` |
| NuGet | `NuGet` | registry package ID 的 ASCII lowercase | NuGetVersion；只接受 `ECOSYSTEM` range | `nuget` |
| Maven | `Maven` | case-sensitive `group_id:artifact_id` | Maven 3.9.x ComparableVersion；只接受 `ECOSYSTEM` range | `maven` |
| RubyGems | `RubyGems` | registry canonical name，case-sensitive | Gem::Version；只接受 `ECOSYSTEM` range | `gem` |
| Packagist | `Packagist` | lowercase `vendor/package` | Composer normalized version；只接受 `ECOSYSTEM` range | `composer` |

所有 canonical name/version 只允许非空 UTF-8，禁止 control/NUL；原始 ecosystem、
name/version 另存用于 evidence。purl 按 Package URL percent-encoding 从 canonical
字段派生，不能反过来作为 identity 来源。跨 ecosystem 永不匹配。

### OSV 输入与匹配闭集

- `schema_version` 只接受
  `{1.0.0,1.1.0,1.2.0,1.3.0,1.4.0,1.5.0,1.6.0,1.7.0,1.7.1,1.7.2,1.7.3,1.7.4}`；
  新版本必须先更新 spec/parser/fixture，禁止按 major 版本宽松放行。
- 每个 record 必须有唯一非空 `id`、至少一个 `affected`、合法
  `affected[].package.ecosystem/name`；受支持生态的 malformed/unknown 字段语义使
  整次 import 失败。非支持生态完成通用 schema/size 校验后不进入 snapshot。
- 同一 affected block 的 `versions[]` exact 集合与 `ranges[]` 区间取并集；多个
  affected blocks 也取并集。range type 必须符合上表，`GIT` 或其他 type 在受支持
  生态中失败。
- range events 解析为一个或多个按版本严格递增的 interval：每段必须以
  `introduced` 开始，后接至多一个 `fixed`、`last_affected` 或 `limit`，闭合后才可
  再次 `introduced`；只有最后一段可以 open-ended。`introduced:"0"` 表示从最小版本
  开始，`fixed`/`limit` 为 exclusive，`last_affected` 为 inclusive。空事件、无法用
  该生态 comparator 解析、倒序、未先 introduced、同一段多种 closing event 或
  非尾段未闭合均使 import 失败。overlap 在规范化时合并，exact/range 命中只需任一
  成立。
- `aliases` 是排序去重后的 advisory ID evidence，永不修改 package identity/range；
  alias collision 不得抑制不同 primary ID，duplicate primary ID 失败。
- `withdrawn` 若存在必须是 RFC 3339 UTC；`osv/withdrawn` 下 record 必须带该字段。
  withdrawn records 保存在 status/counts 中但不进入 active matcher；同一 primary ID
  同时 active/withdrawn 或 path/state 不一致均使 import 失败。

各生态 fetch 返回 report 后由 CLI 的共享 post-processor 匹配一次，将命中 finding
合并并重新派生 decision。rule ID 为 `known-malicious-package`；detail/evidence 保留
advisory、aliases、revision、range 与坐标，severity 固定 Critical、decision 固定
block。无命中时 `IntelSnapshotStatus::NoMatch` 仍进入 JSON `intelligence` 字段、text
的 `malicious intelligence` 段和 SARIF `runs[0].properties.argusIntelligence`；
age 统一输出 `age_seconds` 整数，测试注入固定 scan clock。malicious 与
vulnerability 使用独立数据库参数、rule family 和文案。

## Planned Changes Manifest

<!-- specrail-planned-changes
{"version":1,"issue":90,"complete":true,"paths":["Cargo.lock","Cargo.toml","README.md","crates/argus-agent/src/judge.rs","crates/argus-agent/src/lib.rs","crates/argus-cli/Cargo.toml","crates/argus-cli/src/agent.rs","crates/argus-cli/src/intel.rs","crates/argus-cli/src/main.rs","crates/argus-cli/src/report.rs","crates/argus-cli/src/sarif.rs","crates/argus-cli/tests/intel_cli.rs","crates/argus-composer/src/lib.rs","crates/argus-composer/src/scan.rs","crates/argus-core/Cargo.toml","crates/argus-core/src/lib.rs","crates/argus-crates/src/lib.rs","crates/argus-crates/src/scan.rs","crates/argus-crates/tests/integration.rs","crates/argus-fetch/src/lib.rs","crates/argus-fetch/tests/integration.rs","crates/argus-go/src/lib.rs","crates/argus-intel/Cargo.toml","crates/argus-intel/src/atomic_unix.rs","crates/argus-intel/src/gem_version.rs","crates/argus-intel/src/go_version.rs","crates/argus-intel/src/import.rs","crates/argus-intel/src/lib.rs","crates/argus-intel/src/matcher.rs","crates/argus-intel/src/maven_version.rs","crates/argus-intel/src/normalize.rs","crates/argus-intel/src/osv.rs","crates/argus-intel/src/osv_profile.rs","crates/argus-intel/src/snapshot.rs","crates/argus-intel/src/version_number.rs","crates/argus-intel/tests/comparators.rs","crates/argus-intel/tests/fixtures.rs","crates/argus-intel/tests/import.rs","crates/argus-intel/tests/matcher.rs","crates/argus-intel/tests/osv_schema.rs","crates/argus-intel/tests/security.rs","crates/argus-maven/src/lib.rs","crates/argus-nuget/src/lib.rs","crates/argus-pypi/src/lib.rs","crates/argus-pypi/tests/integration.rs","crates/argus-rubygems/src/lib.rs","crates/argus-rules/src/lib.rs","crates/argus-rules/src/lockfile.rs","docs/supply-chain-attacks.md","specs/GH90/tasks.md","specs/GH90/tech.md"],"spec_refs":["specs/GH90/product.md","specs/GH90/tasks.md","specs/GH90/tech.md"]}
-->

## Product-to-Test Mapping

| Behavior invariant | Implementation area | Verification |
| --- | --- | --- |
| B-001 | OSV importer + snapshot envelope | `cargo test -p argus-intel import_source_contract` |
| B-002 | normalized sorting + record digest | `cargo test -p argus-intel deterministic_snapshot` |
| B-003 | core coordinate + normalizer | `cargo test -p argus-core coordinate_matrix` |
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

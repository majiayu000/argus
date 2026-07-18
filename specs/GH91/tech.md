# Tech Spec

## Linked Issue

GH-91

## Product Spec

Link to `product.md`.

## Codebase Context

| Area | Verified anchor | Current behavior | Why relevant |
| --- | --- | --- | --- |
| npm-only parser | `crates/argus-rules/src/lockfile.rs:1` | 声明只解析 package-lock v3-style tree | 多格式不应继续堆进 rules 单文件 |
| lock entry model | `crates/argus-rules/src/lockfile.rs:19` | 私有结构只有 resolved URL | 缺少生态、坐标、integrity 与 source kind |
| host policy | `crates/argus-rules/src/lockfile.rs:11` | npm 主机常量写死在 parser | 需要按生态集中策略与用户 allowlist |
| report model | `crates/argus-core/src/lib.rs:104` | ArtifactKind 已有 Lockfile | 可保留 report 外形，扩展共享 coordinate |
| CLI router | `crates/argus-cli/src/main.rs:56` | 现有 lockfile 命令调用 rules scanner | 切换到独立 crate 并传显式格式/allowlist |
| SARIF contract | `README.md:102` | lockfile 已支持统一 SARIF renderer | 新 findings 复用输出边界 |

## Proposed Design

新增 `argus-lockfile` crate，避免把 YAML/TOML/自定义 grammar 依赖塞进
`argus-rules`。入口先读受限字节并调用 `detect`；检测器结合 basename、格式版本与
结构 magic，返回闭集 `LockfileFormat`，不做“尝试所有 parser 取第一个成功”。

共享 `NormalizedDependency` 包含 GH-90 建立的 `PackageCoordinate`、source enum、
可选 immutable revision、integrity evidence、原生 locator 与 condition/platform。
parser 分为 npm/yarn/pnpm、python、cargo、go、ruby、composer 模块，每个返回记录、
recognized/unsupported entry 计数与 format version。所有 map 输出统一排序。

`policy` 模块只消费 normalized records：URL 交给共享 URL parser，按 ecosystem
policy 与 CLI `--allow-registry-host` 判断；git ref 分 mutable/commit；integrity
按 `required | optional | unavailable-by-format` 状态判断。finding detail 始终携带
lockfile locator，避免把“没有字段”与“parser 没看懂”混为一谈。

原 `argus_rules::scan_lockfile` 删除，CLI 改调新 crate。现有 npm rule IDs 保持，
新增 `lockfile-mutable-vcs-ref`、`lockfile-integrity-missing`、
`lockfile-integrity-weak`、`lockfile-partial-analysis`。partial 为 Medium 审批；解析
失败和 unknown format 在 report 前返回 error。

## Planned Changes Manifest

<!-- specrail-planned-changes
{"version":1,"issue":91,"complete":true,"paths":["Cargo.lock","Cargo.toml","README.md","crates/argus-cli/Cargo.toml","crates/argus-cli/src/main.rs","crates/argus-cli/tests/lockfile_cli.rs","crates/argus-core/src/lib.rs","crates/argus-lockfile/Cargo.toml","crates/argus-lockfile/src/detect.rs","crates/argus-lockfile/src/lib.rs","crates/argus-lockfile/src/model.rs","crates/argus-lockfile/src/parsers/cargo.rs","crates/argus-lockfile/src/parsers/composer.rs","crates/argus-lockfile/src/parsers/go.rs","crates/argus-lockfile/src/parsers/mod.rs","crates/argus-lockfile/src/parsers/npm.rs","crates/argus-lockfile/src/parsers/python.rs","crates/argus-lockfile/src/parsers/ruby.rs","crates/argus-lockfile/src/policy.rs","crates/argus-lockfile/tests/formats.rs","crates/argus-rules/src/lib.rs","crates/argus-rules/src/lockfile.rs","docs/supply-chain-attacks.md","specs/GH91/product.md","specs/GH91/tech.md"],"spec_refs":["specs/GH91/product.md","specs/GH91/tech.md"]}
-->

## Product-to-Test Mapping

| Behavior invariant | Implementation area | Verification |
| --- | --- | --- |
| B-001 | `detect.rs` | `cargo test -p argus-lockfile detect_matrix` |
| B-002 | `model.rs` + parser normalization | `cargo test -p argus-lockfile normalized_records` |
| B-003 | parser version gates | `cargo test -p argus-lockfile supported_versions` |
| B-004 | `policy.rs` URL/host rules | `cargo test -p argus-lockfile source_policy` |
| B-005 | git source normalization/policy | `cargo test -p argus-lockfile vcs_refs` |
| B-006 | integrity state machine | `cargo test -p argus-lockfile integrity_matrix` |
| B-007 | parser coverage accounting | `cargo test -p argus-lockfile partial_analysis` |
| B-008 | format fixtures/order tests | `cargo test -p argus-lockfile duplicate_platform_order` |
| B-009 | bounded reader + no-I/O boundary | `cargo test -p argus-lockfile resource_limits` |
| B-010 | CLI renderer/exit integration | `cargo test -p argus-cli --test lockfile_cli` |

## 数据流

CLI 只读打开文件并传入容量限制；detector 选择唯一 parser；parser 产生 normalized
records 与 coverage 统计；policy 生成 findings；report 使用 Lockfile artifact，最后
交给既有 renderer。整个图没有 transport 或 process executor。

## 依赖与顺序

本实现复用 GH-90 的 `argus-core::PackageCoordinate`。若 GH-91 先开发，可在分支上
临时基于该已批准 spec 实现，但合并前必须 rebase 并删除重复类型。GH-94 的批量
lockfile 查询消费本 crate 的 normalized records，不应重新解析九类格式。

## 备选方案

- 在现有 `lockfile.rs` 增加九个条件分支：文件会越过维护上限且耦合格式依赖，拒绝。
- 依次尝试所有 parser：损坏输入可能被错误格式接受，拒绝。
- 调用原生包管理器导出 JSON：会执行不受控程序并破坏静态边界，拒绝。

## 风险

- Format drift：严格版本门禁可能暂时拒绝新版本，但优于伪 clean。
- Precision：生态允许自建 registry；用户 allowlist 与独立 evidence 缓解。
- Complexity：九 parser 采用独立模块和共享 contract，避免重复 policy。
- Compatibility：保留两个现有 npm rule ID 与输出语义。

## 测试计划

- [ ] Unit：detect、model、policy 与资源上限。
- [ ] Fixture：九格式版本/正负/partial/invalid 矩阵。
- [ ] CLI：自动/显式格式、allowlist、text/JSON/SARIF 与退出码。
- [ ] Repository：workspace check/test、corpus test。

## 回滚方案

CLI 恢复调用 `argus_rules::scan_lockfile` 并移除新 crate，即可回到 npm-only 行为。
不修改 lockfile 本身，无数据迁移；失败 fixture 保留用于下一版设计。

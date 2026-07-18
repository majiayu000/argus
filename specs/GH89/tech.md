# Tech Spec

## Linked Issue

GH-89

## Product Spec

Link to `product.md`.

## Codebase Context

| Area | Verified anchor | Current behavior | Why relevant |
| --- | --- | --- | --- |
| packument 模型 | `crates/argus-fetch/src/packument.rs:12` | 只反序列化 name、dist-tags 与 versions，明确忽略 time/maintainers | 新规则的数据入口 |
| 版本解析 | `crates/argus-fetch/src/packument.rs:52` | 按 latest、精确版本、dist-tag 解析 | 异常评估必须使用最终解析版本 |
| fetch 选项 | `crates/argus-fetch/src/lib.rs:101` | 集中承载 registry、容量与 host 策略 | 放置显式窗口和开关，避免隐藏常量 |
| npm 数据流 | `crates/argus-fetch/src/lib.rs:155` | packument → 版本 → tarball → scan → provenance | 元数据 finding 在解析后、最终决策前合并 |
| 共享 finding | `crates/argus-core/src/lib.rs:53` | finding 已有稳定 rule/severity/detail/location | 无需扩展输出 schema |
| CLI 输出 | `crates/argus-cli/src/main.rs:566` | 完整 report 后统一输出 text/JSON/SARIF | 保持 operational error 不伪造 clean report |

## Proposed Design

在 `argus-fetch` 新增独立 `anomaly` 模块。`Packument` 扩展为可选 `time` 映射与
可选的版本发布主体快照，但解析层不把缺失值默认成空事件。模块先把可解析的稳定
SemVer 与 RFC3339 时间规范化成按 `(published_at, version)` 排序的事件，再执行
两个彼此独立的纯函数检测器。

版本形状检测以目标版本之前的稳定发布为基线，排除 prerelease，并把 backport
按发布时间而不是版本号顺序处理。阈值作为版本化策略常量记录在 finding 中；
fixture 固定策略边界。它只产生 Medium finding。

快速发布检测通过现有 registry host 上的有界元数据端点取得主体事件；主体字段
来源形成闭集枚举，未知来源不做身份合并。事件按 package/version/time 去重，截断
到固定 lookback 与最大事件数。新增请求继续走 `Transport`，使用独立 body cap 和
redirect host 校验。CLI 提供显式启用参数及窗口/计数上限；启用后缺失必需数据返回
错误，默认未启用时不增加网络请求。

两个检测器返回 `Vec<Finding>`，在源码扫描和 provenance findings 合并后统一调用
现有 decision derivation，确保只能升级而不能降级结果。

## Planned Changes Manifest

<!-- specrail-planned-changes
{"version":1,"issue":89,"complete":true,"paths":["Cargo.lock","Cargo.toml","README.md","crates/argus-cli/src/main.rs","crates/argus-cli/tests/npm_anomaly_cli.rs","crates/argus-fetch/Cargo.toml","crates/argus-fetch/src/anomaly.rs","crates/argus-fetch/src/lib.rs","crates/argus-fetch/src/packument.rs","crates/argus-fetch/tests/anomaly.rs","docs/supply-chain-attacks.md","specs/GH89/product.md","specs/GH89/tech.md"],"spec_refs":["specs/GH89/product.md","specs/GH89/tech.md"]}
-->

## Product-to-Test Mapping

| Behavior invariant | Implementation area | Verification |
| --- | --- | --- |
| B-001 | packument normalization + evaluator preconditions | `cargo test -p argus-fetch anomaly_insufficient` |
| B-002 | deterministic event normalization | `cargo test -p argus-fetch anomaly_ordering` |
| B-003 | version-shape policy | `cargo test -p argus-fetch version_shape_matrix` |
| B-004 | version finding builder | `cargo test -p argus-fetch version_shape_evidence` |
| B-005 | publisher source + bounded window | `cargo test -p argus-fetch rapid_publish_window` |
| B-006 | event dedup/order fixtures | `cargo test -p argus-fetch rapid_publish_benign` |
| B-007 | severity + decision merge | `cargo test -p argus-fetch anomaly_decision` |
| B-008 | enabled-mode error propagation | `cargo test -p argus-cli --test npm_anomaly_cli` |
| B-009 | mock transport caps/redirects | `cargo test -p argus-fetch anomaly_transport` |
| B-010 | CLI text/JSON/SARIF snapshots | `cargo test -p argus-cli --test npm_anomaly_cli` |

## 数据流

CLI 解析显式选项并构造 `FetchOptions`；现有 transport 获取 packument。版本解析后，
normalizer 生成不可变事件序列；启用发布窗口时，同一 transport 取得有界主体事件。
纯检测器生成 findings，与 package/provenance findings 合并，再由既有决策函数和
renderer 输出。任何必需元数据错误在 report 输出前向上传播。

## 备选方案

- 直接按版本字符串做正则：无法正确处理 prerelease/backport，拒绝。
- 单次异常直接 block：弱元数据证据误报成本过高，拒绝。
- 常驻抓取全 registry：偏离本地、安装前定位并引入无界状态，拒绝。

## 风险

- Precision：生态中存在合法跳版和批量发布；以审批级 severity 和正负矩阵控制。
- Registry drift：字段可能缺失或格式变化；启用时显式报错并固定 fixture。
- Privacy：不发送本地包内容，只访问用户选择的 registry 元数据。
- Performance：事件与 body 均有硬上限，排序复杂度受限。

## 测试计划

- [ ] Unit：SemVer/time 规范化与两类策略正负矩阵。
- [ ] Integration：mock transport、容量限制、错误传播与 decision 合并。
- [ ] CLI：text/JSON/SARIF 证据及退出码。
- [ ] Repository：`cargo check --workspace --all-targets`、`cargo test --workspace --all-targets`。

## 回滚方案

移除 CLI 开关与 `anomaly` 模块调用即可恢复原 npm fetch；packument 新增的可选字段
可同时回滚且没有持久化迁移。不得通过把错误改为 warning 或删除负例来回滚。

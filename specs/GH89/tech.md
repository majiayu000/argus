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
| 共享 finding | `crates/argus-core/src/lib.rs:53` | finding 已有稳定 rule/severity/detail/location | 用 Info finding 表达合法但历史不足的 unassessed，无需扩展输出 schema |
| CLI 输出 | `crates/argus-cli/src/main.rs:566` | 完整 report 后统一输出 text/JSON/SARIF | 保持 operational error 不伪造 clean report |

## Proposed Design

在 `argus-fetch` 新增独立 `anomaly` 模块。`Packument` 扩展为可选 `time` 映射与
版本对象中的 `_npmUser.name`，但解析层不把缺失值默认成空事件。模块先把可解析的
稳定 SemVer 与 RFC3339 时间规范化成按 `(published_at, version)` 排序的事件，再
执行两个彼此独立的纯函数检测器。策略参数集中为不可变的
`NpmAnomalyPolicy::V1`，finding 必须回显策略 ID 与命中的数值边界。

版本形状检测要求目标版本有 RFC3339 时间、至少 6 个更早稳定版本且历史跨度至少
30 天；不足时返回 `npm-version-shape-unassessed` Info finding。可评估时取时间
序列直接前驱：发布时间差必须在 `(0,72h]`，目标 SemVer 必须递增，且满足
`major_delta >= 2` 或 `major_delta == 0 && minor_delta >= 10`。此前最近 5 个
相邻稳定转换若已达到同类阈值，则该形状属于已有基线而不触发。prerelease 不参与
基线，backport、相同时间戳和晚补录导致的非递增版本不触发。命中只产生 Medium
`version-shape-anomaly` finding。

快速发布检测先从目标版本 `_npmUser.name` 取得唯一 publisher，不使用
maintainers、author 或 email 回退。随后在规范化的 registry base URL 下解析
`-/v1/search`，并再次校验结果 URL 同 origin 且仍位于 base path：
`GET <registry-base>/-/v1/search?text=<percent-encoded-publisher>&size=250&from=0`
`&quality=0&popularity=0&maintenance=1`。`text` 只用于官方 search API 的候选
发现，设计不假设未声明的 `maintainer:` 过滤语法或结果完整性。响应 schema 只接收
`total` 与 `objects[].package.{name,version,date,publisher.username}`；仅保留
publisher 完全相等、日期处于目标发布时间前 24 小时（含端点）的事件，先按
`(name,version,date,publisher)` 去重，再按不同 package name 计数，计数至少 5
产生 Medium `rapid-publish-window` finding。合法响应中计数不足 5 时产生 Info
`npm-rapid-publish-unassessed`，因为 search 不证明 publisher 活动完整；
`total > 250`、必需字段缺失或非法均返回 operational error，不能把截断页解释为
clean。

外部数据契约以 npm 官方
[`Public Registry API`](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md)
为准：只依赖文档声明的 `text`/`size`/`from` 参数与 search 响应中的
`package.name`、`package.version`、`package.date`、`package.publisher.username`；
不把 search 排序或全文匹配行为升级为完整性保证。

每次 scan 对同一 publisher 最多发出一次 search 请求。`FetchOptions` 增加显式
metadata anomaly 开关和可选 metadata cache 目录；CLI 对应参数默认关闭，因此默认
路径不增加网络。持久缓存 key 为规范化 `(registry origin,publisher,
npm-anomaly-v1)` 的 SHA-256，TTL 固定 15 分钟，内容包含抓取时间与原始响应。
缓存读写使用原子替换且拒绝 symlink；命中缓存后仍走相同 JSON schema、250 对象与
2 MiB body 校验。无缓存目录时只做单次调用内去重，不写磁盘。

错误分类闭集如下：结构合法但不足 6 个前驱或 30 天跨度，以及合法有界 search 中
不足 5 个精确 publisher package → Info unassessed；显式启用后缺少目标时间、
`_npmUser.name`、search 必需字段，或遇到损坏/超限/cache/transport 错误 →
operational error；未启用 → 不评估、不请求、不输出伪造状态。

两个检测器返回 `Vec<Finding>`，在源码扫描和 provenance findings 合并后统一调用
现有 decision derivation，确保只能升级而不能降级结果。

## Planned Changes Manifest

<!-- specrail-planned-changes
{"version":1,"issue":89,"complete":true,"paths":["Cargo.lock","Cargo.toml","README.md","crates/argus-cli/src/main.rs","crates/argus-cli/tests/npm_anomaly_cli.rs","crates/argus-fetch/Cargo.toml","crates/argus-fetch/src/anomaly.rs","crates/argus-fetch/src/lib.rs","crates/argus-fetch/src/packument.rs","crates/argus-fetch/tests/anomaly.rs","docs/supply-chain-attacks.md","specs/GH89/product.md","specs/GH89/tasks.md","specs/GH89/tech.md"],"spec_refs":["specs/GH89/product.md","specs/GH89/tech.md","specs/GH89/tasks.md"]}
-->

## Product-to-Test Mapping

| Behavior invariant | Implementation area | Verification |
| --- | --- | --- |
| B-001 | packument normalization + explicit Info unassessed result | `cargo test -p argus-fetch anomaly_insufficient` |
| B-002 | deterministic event normalization | `cargo test -p argus-fetch anomaly_ordering` |
| B-003 | versioned 72h / delta / five-transition policy | `cargo test -p argus-fetch version_shape_matrix` |
| B-004 | version finding builder | `cargo test -p argus-fetch version_shape_evidence` |
| B-005 | `_npmUser.name` source + 24h / five-package window | `cargo test -p argus-fetch rapid_publish_window` |
| B-006 | search schema, 250-object cap, event/package dedup + unassessed | `cargo test -p argus-fetch rapid_publish_benign` |
| B-007 | severity + decision merge | `cargo test -p argus-fetch anomaly_decision` |
| B-008 | closed error taxonomy and enabled-mode propagation | `cargo test -p argus-cli --test npm_anomaly_cli` |
| B-009 | exact-origin endpoint, mock transport caps/redirects/cache | `cargo test -p argus-fetch anomaly_transport` |
| B-010 | CLI text/JSON/SARIF snapshots | `cargo test -p argus-cli --test npm_anomaly_cli` |

## 数据流

CLI 解析显式开关与 cache 目录并构造 `FetchOptions`；现有 transport 获取完整
packument。版本解析后，normalizer 生成不可变事件序列；启用后从目标版本提取
publisher，并由同一 transport 取得一页 search 响应。纯检测器生成 anomaly 或
unassessed findings，与 package/provenance findings 合并，再由既有决策函数和
renderer 输出。任何必需元数据错误在 report 输出前向上传播。

## 备选方案

- 直接按版本字符串做正则：无法正确处理 prerelease/backport，拒绝。
- 单次异常直接 block：弱元数据证据误报成本过高，拒绝。
- 常驻抓取全 registry：偏离本地、安装前定位并引入无界状态，拒绝。
- 用顶层 maintainers 猜目标版本发布者：该字段不代表具体版本上传者，拒绝。

## 风险

- Precision：生态中存在合法跳版和批量发布；以审批级 severity 和正负矩阵控制。
- Registry drift：search 只提供每个包当前版本且索引可能滞后；finding 仅声称
  “有界响应中观测到”，文档明确此限制，缺失/截断时显式报错。
- Privacy：不发送本地包内容，只访问用户选择的 registry 元数据。
- Performance：事件与 body 均有硬上限，排序复杂度受限。

## 测试计划

- [ ] Unit：SemVer/time 规范化、72h/delta/五转换与 24h/五包边界矩阵。
- [ ] Integration：search schema、publisher 精确匹配、去重、250/2MiB 上限、
  15 分钟 cache、redirect 与错误传播。
- [ ] CLI：text/JSON/SARIF 证据及退出码。
- [ ] Docs：攻击目录链接两个 rule ID，并记录 search 仅见最新发布的限制。
- [ ] Repository：`cargo check --workspace --all-targets`、`cargo test --workspace --all-targets`。

## 回滚方案

移除 CLI 开关与 `anomaly` 模块调用即可恢复原 npm fetch；packument 新增的可选字段
可同时回滚且没有持久化迁移。不得通过把错误改为 warning 或删除负例来回滚。

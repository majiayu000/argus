# Tech Spec

## Linked Issue

GH-94

## Product Spec

Link to `product.md`.

## Codebase Context

| Area | Verified anchor | Current behavior | Why relevant |
| --- | --- | --- | --- |
| report coordinates | `crates/argus-core/src/lib.rs:116` | report 只有可选 package_name/version | 需复用 GH-90 的强类型 ecosystem coordinate |
| lockfile boundary | `crates/argus-rules/src/lockfile.rs:33` | 当前 parser 直接返回 report，未暴露 records | 批量模式依赖 GH-91 normalized record |
| CLI router | `crates/argus-cli/src/main.rs:56` | 尚无 vulnerability 子命令 | 新模式应显式，不隐式改变所有 scan |
| renderer | `crates/argus-cli/src/main.rs:566` | 完整 report 后统一输出 | query error 必须在输出前发生 |
| URL policy | `crates/argus-core/src/lib.rs:10` | core 暴露共享 URL 辅助模块 | OSV transport 复用 host/HTTPS 校验原则 |
| SARIF docs | `README.md:100` | finding 已统一映射到 SARIF | 漏洞结果可复用 renderer，无需第二输出栈 |

## Proposed Design

新增 `argus-osv` crate，复用 GH-90 的 `PackageCoordinate` 和 GH-91 的
`NormalizedDependency`。crate 分为 `client`、`model`、`normalize`、`cache` 与
`report`；不依赖 CLI，也不解析 lockfile。`client` 将去重后的坐标按固定上限切分到
OSV `/v1/querybatch`，请求中保留索引，响应严格验证数量与位置。

CLI 增加 `argus vulns package <ecosystem> <name>@<exact-version>` 与
`argus vulns lockfile <path>`。网络为默认显式子命令行为；`--offline` 只读 cache，
`--cache-dir` 与 `--max-age` 控制本地策略。cache envelope 记录 schema/API 版本、
coordinate、fetched_at、response digest 和 canonical response；同目录临时文件、
fsync、rename，损坏条目报错而不是 miss 后联网（offline 尤其如此）。

normalized advisory 将 OSV id、aliases、affected ranges、database_modified、references
与 severity 保留为结构化 evidence。由于现有 `Finding` 不适合承载多 advisory 字段，
在 `argus-core` 增加可选、版本化 `advisory` evidence 对象，JSON/SARIF renderer 显式
输出；text 使用稳定摘要。rule ID 为 `known-vulnerability`，decision 策略通过 CLI
`--fail-on-severity` 显式配置，默认只要求审批；unknown severity 不自动升级为 block。

命令在所有 batch 完整成功或所有离线 key 有效后才构造 report。任何部分失败不写
stdout，也不提交本轮新 cache；stale cache 只有用户显式 `--allow-stale` 才可使用，
并产生可见 Info/Medium evidence，不能静默降级。

## Planned Changes Manifest

<!-- specrail-planned-changes
{"version":1,"issue":94,"complete":true,"paths":["Cargo.lock","Cargo.toml","README.md","crates/argus-cli/Cargo.toml","crates/argus-cli/src/main.rs","crates/argus-cli/src/vulns.rs","crates/argus-cli/tests/vulns_cli.rs","crates/argus-core/src/lib.rs","crates/argus-osv/Cargo.toml","crates/argus-osv/src/cache.rs","crates/argus-osv/src/client.rs","crates/argus-osv/src/lib.rs","crates/argus-osv/src/model.rs","crates/argus-osv/src/normalize.rs","crates/argus-osv/src/report.rs","crates/argus-osv/tests/query.rs","specs/GH94/product.md","specs/GH94/tech.md"],"spec_refs":["specs/GH94/product.md","specs/GH94/tech.md"]}
-->

## Product-to-Test Mapping

| Behavior invariant | Implementation area | Verification |
| --- | --- | --- |
| B-001 | CLI coordinate parser + core normalization | `cargo test -p argus-cli --test vulns_cli invalid_coordinate` |
| B-002 | GH-91 record adapter + dedup | `cargo test -p argus-osv lockfile_coordinates` |
| B-003 | bounded batch client | `cargo test -p argus-osv batch_transport` |
| B-004 | response aligner/normalizer | `cargo test -p argus-osv response_contract` |
| B-005 | advisory evidence/report builder | `cargo test -p argus-osv advisory_evidence` |
| B-006 | completion state machine | `cargo test -p argus-cli --test vulns_cli result_states` |
| B-007 | versioned atomic cache | `cargo test -p argus-osv cache_contract` |
| B-008 | offline resolver | `cargo test -p argus-cli --test vulns_cli offline_matrix` |
| B-009 | independent rule/source model | `cargo test -p argus-osv intel_separation` |
| B-010 | text/JSON/SARIF integration | `cargo test -p argus-cli --test vulns_cli` |

## 数据流

CLI 将显式坐标或 GH-91 records 规范化、去重并保留 locator；resolver 先检查 cache，
网络模式批量补齐缺项并完整验证；所有结果齐备后规范化 advisories、构造 findings 与
report，最后统一渲染。cache commit 和 report 输出都位于全批成功之后。

## 依赖与顺序

实现依赖 GH-90 的 `PackageCoordinate` 与 GH-91 的 `NormalizedDependency` 公共契约。
因此 GH-94 spec 可独立审批，但 implementation PR 应在两者合并后开始或显式 stacked；
禁止在本 crate 复制 ecosystem normalization 或 lockfile parser。

## 备选方案

- 每次 package fetch 自动查询 OSV：改变默认离线行为并引入可用性风险，拒绝。
- shell 调用 `osv-scanner`：增加外部程序与版本契约，拒绝。
- 把 OSV 响应塞进 finding detail：机器消费者无法可靠读取，拒绝。

## 风险

- API availability：显式模式、cache 与全批 fail-closed 避免伪 clean。
- Data semantics：OSV severity 可能缺失；保留 unknown，不自行推算。
- Privacy：网络查询会暴露坐标；文档明确，offline 可完全禁止网络。
- Dependency ordering：通过 GH-90/GH-91 公共类型和 stacked gate 控制冲突。

## 测试计划

- [ ] Unit：coordinate、batch alignment、OSV normalize、cache state。
- [ ] Integration：mock server 的成功/部分失败/超限/重定向矩阵。
- [ ] CLI：package/九格式 lockfile、offline/stale、三种 renderer 与退出码。
- [ ] Repository：workspace check/test、corpus 与 SpecRail workflow check。

## 回滚方案

移除 `vulns` router、新 crate 和 advisory 可选字段即可恢复现状；cache 是用户选择的
独立目录，可安全保留或手动删除。回滚不得把查询错误改写为 zero advisories。

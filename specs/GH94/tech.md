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

新增 `argus-osv` transport/resolver crate，复用 GH-90 的
`argus_core::PackageCoordinate`、共享 `argus_intel::osv` schema/range comparator 和
GH-91 的 `NormalizedDependency`，不得复制 ecosystem normalization、OSV parser 或
lockfile parser。GH-94 将共享 parser 的闭集补到当前 OSV schema `1.8.0`；支持集合为
`{1.0.0,1.1.0,1.2.0,1.3.0,1.3.1,1.4.0,1.5.0,1.6.0,1.6.1,1.6.2,1.6.3,1.6.4,1.6.5,1.6.6,1.6.7,1.7.0,1.7.2,1.7.3,1.7.4,1.7.5,1.8.0}`；
不存在的 1.7.1 和其他 schema version typed error。1.8.0 severity `source` 只接受
`NVD | CNA | SELF` 并保留为 evidence。按官方兼容规则，字段完全缺失只表示 legacy
`1.0.0` 并只按 1.0.0 schema 校验；显式 `1.0.0` 同样接受，null/empty/invalid
SemVer、legacy schema 未声明字段或显式后续版本缺其必需字段均失败，禁止把任意缺失
版本解释为 latest。

CLI 使用无歧义参数：

```text
argus vulns package --ecosystem <enum> --name <name> --version <exact>
argus vulns lockfile <path> [--lockfile-format <enum>]
```

公共选项为 `--offline`、`--cache-dir`、`--max-age-seconds`（默认 86,400，范围
0..=2,592,000）、`--allow-stale` 和
`--fail-on-severity <low|medium|high|critical>`，以及
`--format <text|json|sarif>`（默认 text）。`--cache-dir <DIR>` 在 package/lockfile、
online/offline 都必填，不存在隐式平台目录或无 cache 模式；`--allow-stale` 必须与
`--offline` 同时使用，offline cache 文件缺失仍 operational error。package 模式支持
GH-90 八生态闭集；lockfile 模式只消费 GH-91 records。明确 local 的
root/path/workspace record 不查询但计数；其他 record 必须有完整 coordinate。name
最多 4 KiB UTF-8、version 最多 1 KiB，均禁止 control/NUL；最多 10,000 个去重坐标、
每坐标 10,000 个 locator，所有 finding/evidence RFC 8785 canonical JSON 合计最多
64 MiB，不允许截断，超限在网络或 renderer 前失败。

### 两阶段 OSV snapshot 协议

生产 endpoint 只允许 `https://api.osv.dev`，POST 路径固定
`/v1/querybatch`，详情 GET 路径为
`/v1/vulns/{percent-encoded-primary-id}`。不能由 CLI、环境变量或配置替换 endpoint；
测试通过 trait 注入内存/mock transport。只接受 HTTP 200 和 JSON content type，
redirect 上限 0，不发送 credential/cookie，不访问 advisory references。

| Resource | Hard bound |
| --- | --- |
| unique coordinates | 10,000 |
| queries per querybatch request | 1,000（官方上限） |
| page-token bytes / pages per coordinate | 4 KiB / 16 |
| summary `(coordinate,id)` associations | 100,000 |
| unique advisory IDs | 20,000 |
| total HTTP requests / detail concurrency | 25,000 / 8 |
| encoded request / decoded query response | 4 MiB / 32 MiB |
| decoded detail response / total decoded bytes | 2 MiB / 512 MiB |
| connect / per-request / whole-operation timeout | 5 s / 30 s / 300 s |

响应以 streaming decoded-byte counter 强制上限，等号允许、超限一失败；自动网络
retry 为 0，429/非 200/timeout/DNS/TLS/body/read/JSON error 都是 operational error。
唯一例外是下述 snapshot race 可整轮重试一次，故最多两轮。
primary/alias ID 必须为 1..=512 UTF-8 bytes 且无 control/NUL，reference URL 最多
8 KiB；任何 scalar/bounds failure 都不得通过截断或略过降级。

初始 query 按 canonical coordinate 稳定排序后每 1,000 项切 batch；每个响应的
`results.len` 必须等于请求 query 数且位置对应。每个 result 只接受排序去重前的
`{id,modified}` summary 与可选 `next_page_token`。带 token 的 coordinate 组成下一次
subset batch，并在原全局索引上累积；空 token、重复 token、重复
`(coordinate,id)`、同 ID 的 modified precision interval 不相交、页数/association/
request 上限或结果错位都失败。直到所有 coordinate token 为空前，任何“无 advisory”
都不是 complete。

分页耗尽后按 primary ID 排序并最多 8 并发调用详情 endpoint。每个详情必须：

- response `id` byte-exact 等于 URL ID；batch/detail `modified` 均须为 RFC 3339 UTC
  且 fractional precision 为 0..=9。batch summary 定义由其小数位数决定的
  `[timestamp, timestamp + 10^-precision second)` interval，detail instant 必须落在
  该 ID 的每个 summary interval 内；原始 summary/detail 字符串都保留为 evidence；
- 通过上述共享 OSV version 闭集 parser，并至少有一个 affected block 经 GH-90 同一
  ecosystem/name/version comparator 复验每个关联 coordinate；
- 不用 alias 合并 primary record；同一 ID 可跨 coordinate 复用一次详情，但每个
  coordinate 的关联独立保留；
- references 只保存 schema type 与可解析 HTTP/HTTPS URL，canonical source 始终为
  固定详情 URL，因此 references 缺失不伪造第三方 source。

该 precision interval 规则适配官方 batch microsecond 与 detail nanosecond 的正常
差异，禁止先 round；例如 `.682352Z` 接受 `.682352320Z`，但拒绝 `.682353000Z`。
OSV 官方 POST query 排除 withdrawn record。详情 `modified` 落在任一 summary
interval 外、出现 `withdrawn` 或 detail 已不再匹配 coordinate 都视为读时 race：
丢弃全轮结果、不写 cache/report，并从 querybatch 整轮重试一次；第二次仍不一致则
operational error。其他 malformed 响应不重试。只有所有详情和所有 coordinate
通过后才形成一个 `CompleteSnapshot`。

### Advisory normalization 与 decision

每个 active `(coordinate, primary_id)` 生成一条 `known-vulnerability` finding 并
合并该 coordinate 的全部稳定排序 locator。aliases 排序去重但不合并 primary ID；
每个 affected block 内只输出 comparator-equal 的 exact `versions[]` item，以及实际
包含 queried exact version 的 sibling range 和其中命中的 normalized interval；同
block 未命中的 versions/ranges/intervals 不得被标为命中 evidence。`withdrawn` 必须
为 RFC 3339 UTC，但 query hydration 中出现即执行上述 race 路径，不产生
finding/cache entry。withdrawn fixture 必须证明首次出现会整轮重试，第二轮仍出现则
operational error，绝不能形成 active、withdrawn-only 或 complete-no-match 成功
report。

matching affected-level severity 优先；若任何 affected-level severity 存在则
top-level severity 必须为空。CVSS_V2/V3/V4 vector 用对应标准 parser 求 base score，
取所有 matching block 的最大值并映射 `low=0.1..3.9`、`medium=4.0..6.9`、
`high=7.0..8.9`、`critical=9.0..10.0`，0.0 为 `none`；缺失、Ubuntu 或不可比较
type 为 `unknown`，保留 raw type/score，不猜等级。已知 CVSS type 的非法 vector 是
malformed operational error。

默认 active finding 为 Argus Medium / allow-with-approval。指定
`--fail-on-severity` 后，normalized level ≥ threshold 的 active finding 升为
Argus High/block；低于阈值和 unknown 保持 approval。withdrawn/complete-no-match
不改变 decision。blocking finding 始终优先于 approval/info，且本 family 不改写
malicious/provenance/integrity/heuristic finding。

### Cache transaction 与结果状态

cache directory 内只有版本化 `cache-v1.json` 与 `.lock`。新目录权限 0700、cache/temp
文件 0600；路径 adapter 从可信 root 逐段以 handle-relative no-follow 打开并保持
directory handles，Unix 使用 `openat(O_NOFOLLOW|O_DIRECTORY)` 与
`renameat`/dir-fd `fsync`，其他平台必须使用等价 reparse-safe primitive；无等价能力
则 operational error，禁止先 `lstat` 后按字符串路径打开。lock/target/temp 都相对
最终 directory handle 以 no-follow/O_EXCL 打开。目录、lock、target 或父链为
symlink，target 非 regular file，权限/lock/read/write/fsync/rename/directory-fsync
失败均 typed error。

envelope 最多 512 MiB、100,000 entries，字段固定为
`{version,generation,api_version,schema_set_id,entries,content_sha256}`；`api_version`
固定 `osv-v1`，`schema_set_id` 固定 `argus-osv-schema-2026-07-09-v1`。entry 固定为
`{coordinate,fetched_at,query_summaries,advisories,response_sha256}`。`response_sha256`
等于 `{query_summaries,advisories}` 经稳定排序、RFC 8785 canonicalize 后的 SHA-256，
不是 raw/compressed HTTP bytes，也不包含自身、coordinate 或 fetched_at；
`content_sha256` 等于删除 envelope 自身该字段后对其余完整对象做 RFC 8785
canonicalize 的 SHA-256。key 为 API/schema-set 前缀加完整 canonical coordinate；
读取时必须从 entry coordinate 重算 key 并复验每个 advisory 与该 coordinate 的
affected 绑定；zero-result 也必须有显式空 summaries/advisories、fetched_at 和两个
可复算 digest。

读取时先在 shared lock 下验证整个 envelope/digest。网络在锁外完成；提交前在
exclusive lock 下重读最新 generation，把本轮完整 entries 合并到最新 map；同 key
以较新 fetched_at 胜出，同 timestamp 同 digest 幂等、同 timestamp 不同 digest
失败；随后用同目录 O_EXCL temp 写 canonical bytes、fsync temp、rename、fsync
directory。这样并发 writer 不丢更新；任一网络/validation 失败不进入提交阶段，旧
cache 完整保留。

安全测试必须在 parent/final-dir/lock/target 验证与 open/rename 之间注入
symlink/reparse-point swap，证明 handle-relative target 不逃逸；只测静态 symlink
不足以满足该 contract。

网络模式只使用 age ≤ max-age 的 fresh entry，stale/missing entry 必须重新查询；
刷新失败绝不回退 stale。offline 要求全部 query key 完整且 fresh；显式
`--offline --allow-stale` 可接受完整 stale set，生成
`vulnerability-data-stale` Medium/approval finding。future fetched_at、missing、
损坏、部分 entry 或未授权 stale 均 operational error。

在 `argus-core` 增加版本化 `VulnerabilityQueryEvidence`，状态闭集为
`complete_no_match | complete_with_findings | complete_stale`；source mode 闭集为
`network | cache | mixed | offline_fresh | offline_stale`：online 全 miss/全 fresh
hit/两者并存分别为前三者，offline 全 fresh 为 `offline_fresh`，任一授权 stale 为
`offline_stale` 且状态必须 `complete_stale`。对象记录
queried/excluded/active counts、oldest/newest fetched_at、maximum age 与
advisory evidence；混用 fresh cache 和本轮网络结果时不得伪造单一 queried_at。
成功 text/JSON/SARIF 都从同一对象渲染；错误在 renderer 前返回 exit 2、stderr、
empty stdout/no SARIF。成功 no-match exit 0；active/stale approval exit 2；
threshold block exit 1。任何输出只显示稳定 `<argus-osv-cache>` label，不显示绝对
cache path。

## Planned Changes Manifest

<!-- specrail-planned-changes
{"version":1,"issue":94,"complete":true,"paths":["Cargo.lock","Cargo.toml","README.md","crates/argus-cli/Cargo.toml","crates/argus-cli/src/main.rs","crates/argus-cli/src/router.rs","crates/argus-cli/src/sarif.rs","crates/argus-cli/src/sarif_vulns.rs","crates/argus-cli/src/vulns.rs","crates/argus-cli/tests/vulns_cli.rs","crates/argus-core/src/lib.rs","crates/argus-intel/Cargo.toml","crates/argus-intel/src/lib.rs","crates/argus-intel/src/osv.rs","crates/argus-intel/tests/fixtures.rs","crates/argus-osv/Cargo.toml","crates/argus-osv/src/cache.rs","crates/argus-osv/src/client.rs","crates/argus-osv/src/lib.rs","crates/argus-osv/src/model.rs","crates/argus-osv/src/normalize.rs","crates/argus-osv/src/report.rs","crates/argus-osv/src/resolver.rs","crates/argus-osv/src/severity.rs","crates/argus-osv/tests/cache.rs","crates/argus-osv/tests/client.rs","crates/argus-osv/tests/resolver.rs","docs/supply-chain-attacks.md","specs/GH94/product.md","specs/GH94/tasks.md","specs/GH94/tech.md"],"spec_refs":["specs/GH94/product.md","specs/GH94/tasks.md","specs/GH94/tech.md"]}
-->

## Product-to-Test Mapping

| Behavior invariant | Implementation area | Verification |
| --- | --- | --- |
| B-001 | CLI coordinate parser + core normalization | `cargo test -p argus-cli --test vulns_cli invalid_coordinate` |
| B-002 | GH-91 record adapter + dedup | `cargo test -p argus-osv lockfile_coordinates` |
| B-003 | paginated batch + detail client | `cargo test -p argus-osv batch_transport` |
| B-004 | snapshot resolver/normalizer | `cargo test -p argus-osv snapshot_consistency` |
| B-005 | advisory evidence/report builder | `cargo test -p argus-osv advisory_evidence` |
| B-006 | completion state machine | `cargo test -p argus-cli --test vulns_cli result_states` |
| B-007 | locked versioned atomic cache | `cargo test -p argus-osv cache_contract` |
| B-008 | offline resolver | `cargo test -p argus-cli --test vulns_cli offline_matrix` |
| B-009 | independent rule/source model | `cargo test -p argus-osv intel_separation` |
| B-010 | text/JSON/SARIF integration | `cargo test -p argus-cli --test vulns_cli` |

## 数据流

CLI 将显式坐标或 GH-91 records 规范化、去重并保留 locator；resolver 验证 cache，
对缺项依次耗尽 query pages、hydrate 唯一 ID、复验 modified/affected，所有结果齐备
后才提交 cache、构造 findings/report 并统一渲染。任何中间状态均不可观察为 report。

## 依赖与顺序

实现硬依赖 GH-90 implementation 的 `PackageCoordinate`/共享 OSV parser 与 GH-91
implementation 的 `NormalizedDependency`。两者未合并前 route gate 必须阻止
SP94-T1，不允许 stacked 临时副本。GH-94 将共享 parser 增补 schema 1.8.0，但不得在
`argus-osv` 再实现 comparator/schema。

## 备选方案

- 每次 package fetch 自动查询 OSV：改变默认离线行为并引入可用性风险，拒绝。
- shell 调用 `osv-scanner`：增加外部程序与版本契约，拒绝。
- 把 OSV 响应塞进 finding detail：机器消费者无法可靠读取，拒绝。

## 风险

- API availability：显式模式、cache 与全批 fail-closed 避免伪 clean。
- Data semantics：OSV severity 可能缺失/不可比较；保留 unknown，不自行推算。
- Snapshot race：summary/detail modified 必须一致，整轮最多重试一次后 fail closed。
- Privacy：网络查询会暴露坐标；文档明确，offline 可完全禁止网络。
- Dependency ordering：通过 GH-90/GH-91 公共类型和 stacked gate 控制冲突。

## 测试计划

- [ ] Unit：coordinate、batch alignment、OSV normalize、cache state。
- [ ] Integration：mock server 的分页、detail hydration、race、部分失败、超限、
  重定向和 response-body streaming 矩阵。
- [ ] CLI：package/九格式 lockfile、offline/stale、三种 renderer 与退出码。
- [ ] Repository：workspace check/test、corpus 与 SpecRail workflow check。

## 回滚方案

移除 `vulns` router、新 crate 和 advisory 可选字段即可恢复现状；cache 是用户选择的
独立目录，可安全保留或手动删除。回滚不得把查询错误改写为 zero advisories。

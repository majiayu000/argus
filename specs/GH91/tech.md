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

### Format detection 与版本闭集

| Basename | `LockfileFormat` | Required signature | Accepted versions |
| --- | --- | --- | --- |
| `package-lock.json` | PackageLock | JSON object、numeric `lockfileVersion`、`packages` object | 2, 3 |
| `yarn.lock` | YarnClassic | first nonblank line `# yarn lockfile v1`，且无 `__metadata` | 1 |
| `yarn.lock` | YarnBerry | YAML root `__metadata.version`，且无 classic header | 4, 6, 8 |
| `pnpm-lock.yaml` | Pnpm | YAML root `lockfileVersion` | canonical 5.4, 6.0, 9.0 |
| `poetry.lock` | Poetry | TOML `[metadata].lock-version` 与 `[[package]]` | 1.1, 2.0, 2.1 |
| `uv.lock` | Uv | TOML top-level integer `version` 与 `[[package]]` | 1 |
| `Cargo.lock` | Cargo | TOML top-level integer `version` 与 `[[package]]` | 3, 4 |
| `go.sum` | GoSum | 每个非空行严格为 `module version[/go.mod] h1:base64` 三字段 | grammar-v1 |
| `Gemfile.lock` | Bundler | `DEPENDENCIES`、完整 `BUNDLED WITH` SemVer 和至少一个 `GEM`/`GIT`/`PATH` section | Bundler major 2, 3, 4；`CHECKSUMS` 仅允许 version ≥2.5 |
| `composer.lock` | Composer | JSON object、string `content-hash`、`packages`/`packages-dev` arrays | schema-v1 |

basename 与 signature/version 必须同时命中同一行；缺 basename、空文件、多个候选、
classic/Berry 双 signature、unknown version、duplicate key 或已知 root 中出现
未声明 section 都是 typed operational error。显式 `--lockfile-format` 只能消除
basename 缺失，仍必须验证对应 signature/version，不能强制错误 parser。

共享 `NormalizedDependency` 包含 GH-90 实现提供的 `PackageCoordinate`、format、
source enum、可选 immutable revision、integrity state/evidence、原生 locator、
condition/platform 与 deterministic occurrence index。source 闭集为
`registry | url | git | path | workspace | unavailable-by-format`；integrity 闭集为
`required-present | required-missing | optional-present | optional-absent |
unavailable-by-format | invalid`。parser 按上表拆为九个独立模块，每个返回 records、
recognized entry 数、unsupported entry 数与 format version。输入 entry 总数必须等于
recognized 数且 unsupported 为 0，否则在 policy/report 前返回 partial operational
error。registry/url/git record 必须有完整 coordinate；只有缺少 name/version 的
root/path/workspace record 允许 `coordinate=None`，同时保留 raw name/version 与
locator 并计入 coverage，且不得送入 GH-90/GH-94 matcher。重复坐标保留为不同
occurrence，最终按 ecosystem、optional canonical name/version、source、locator、
occurrence index 稳定排序。

### Coverage 守恒矩阵

所有声明的 map/object 使用 deny-unknown 语义；表中 metadata 可读取/校验但不生成
record，表外 root/section/nested dependency key 令 unsupported+1 并最终
operational error。`total_units = record_units + traversed_non_record_units`，
`recognized_units` 必须逐项递增并与 total 相等，禁止 parser 用自身输出反推 total。

| Format | Record units | 必须遍历的 non-record units | 合法 metadata（不计 unit） |
| --- | --- | --- | --- |
| PackageLock 2/3 | `packages` 每个 entry（含 root/link/workspace） | v2 `dependencies` compatibility tree 的每个 node，须与 packages 坐标交叉校验 | name, version, lockfileVersion, requires |
| Yarn Classic 1 | 每个 selector descriptor（逗号组拆开） | 每 block 的 dependencies/optionalDependencies 子项 | comments/header |
| Yarn Berry 4/6/8 | 除 `__metadata` 外每个 descriptor（多 descriptor key 拆开） | dependencies, peerDependencies, dependenciesMeta, peerDependenciesMeta 子项 | `__metadata` 的 version/cacheKey |
| pnpm 5.4/6/9 | packages/snapshots 的每个 package key | importers 的 dependencies/devDependencies/optionalDependencies 与 package dependency edges，每个 ref 必须解析或显式 local | lockfileVersion, settings, overrides, patchedDependencies, time |
| Poetry 1.1/2.0/2.1 | 每个 `[[package]]` | package dependencies/extras 子项及每个 file artifact | metadata lock-version/python-versions/content-hash |
| uv 1 | 每个 `[[package]]` | dependencies/optional-dependencies/dev-dependencies 子项及每个 sdist/wheel artifact | version, revision, resolution-markers, options, manifest |
| Cargo 3/4 | 每个 `[[package]]` | package dependencies 每个 locator | version, metadata |
| GoSum grammar-v1 | 每个非空 line | none | none；comment/blank line 不允许 |
| Bundler 2/3/4 | GEM/GIT/PATH 各 specs entry；version ≥2.5 时可选 `CHECKSUMS` 每个 lock-name 行；Bundler 4 可另有最多一条 self-checksum | 每个 spec dependency、DEPENDENCIES entry；普通 CHECKSUMS line 须按 name/version/platform exact 关联一个 spec，self-checksum 须 exact 匹配 BUNDLED WITH version | PLATFORMS, RUBY VERSION, BUNDLED WITH, section remote/revision/glob |
| Composer schema-v1 | packages/packages-dev 每个 package | require, require-dev, conflict, provide, replace, suggest 每个 edge | `_readme`, content-hash, aliases, minimum-stability, stability-flags, prefer-stable, prefer-lowest, platform, platform-dev, plugin-api-version |

known section 内的未知 nested entry、整个合法 section 被跳过、edge 无法关联、计数
不守恒都必须由 fixture 证明 exit 2、stderr、empty stdout。

### Per-format source/integrity matrix

| Format | Registry/download evidence | Required integrity | Legitimate unavailable cases |
| --- | --- | --- | --- |
| PackageLock 2/3 | entry `resolved` URL；`link`/root 单独分类 | 非 root/link/workspace 且有 registry/url source 时要求合法 SRI | root、link、workspace |
| Yarn Classic 1 | `resolved` URL/git locator | registry/url 要求 `integrity` 或 resolved fragment；fragment SHA-1 记 weak | workspace/link |
| Yarn Berry 4/6/8 | resolution protocol + locator | npm/http archive 要求 `checksum` | workspace/portal/link/patch 本地基底 |
| pnpm 5.4/6/9 | resolution tarball/git/path | registry/tarball 要求 `integrity` | link/workspace/file |
| Poetry 1.1/2.0/2.1 | source type/url + package files | registry package 的每个列出 file artifact 都要求独立合法 hash；任一 mixed invalid/missing 失败 | directory/path；git 由 revision 判定 |
| uv 1 | source registry/url/git/path + sdist/wheels | registry/url 的每个列出 distribution 要求 hash | editable/path；git 由 revision 判定 |
| Cargo 3/4 | `registry+`/`git+` source | registry package 要求 checksum | path package；git 由 source revision 判定 |
| GoSum grammar-v1 | 格式不携带 host；module/version 仅作坐标 | 每行必须合法 `h1:`（SHA-256） | source location 固定 unavailable-by-format |
| Bundler 2/3/4 | section remote/git/path；version ≥2.5 可选 `CHECKSUMS` 的 `name (version[-platform]) algorithm=digest[,algorithm=digest...]` | 有 CHECKSUMS 时每个 registry GEM spec 必须有 exact lock-name 行及至少一个合法 checksum；GIT 要求 immutable revision | 整个 CHECKSUMS 缺失时 GEM integrity unavailable-by-format；PATH unavailable；CHECKSUMS 内 GIT/PATH 行可无 checksum |
| Composer schema-v1 | dist/source URL + reference | 非空 dist shasum 校验；空/缺 shasum 为 optional-absent | source-only/path；空 shasum 不冒充 verified |

integrity algorithm/value 必须完整解析并规范化：SHA-256/384/512、SRI SHA-256/384/512
与 Go `h1:` 为 strong；SHA-1、MD5、Yarn SHA-1 fragment 与 Composer SHA-1 shasum
为 weak；未知 algorithm、错误 base64/hex 长度或同一字段冲突为 invalid。VCS revision
只接受 40/64 位小写 hex commit，branch、tag、`HEAD`、短 SHA、refname 与缺失 revision
均为 mutable，不作为内容 integrity。

Bundler `CHECKSUMS` 使用完整 lock-name（含 version/platform）关联 GEM/GIT/PATH spec，
禁止仅按 name 合并。section 缺失时保持上述 unavailable 语义；section 存在时，
unmatched/duplicate lock-name、缺少任一 spec 行、同 algorithm 冲突或无法解析的行均
不得跳过。registry GEM 的空 checksum 行为 required-missing；每个逗号分隔 checksum
独立保留 locator/evidence，任一 invalid 产生 invalid，weak-only 产生 weak，至少一个
strong 且其余均为合法 weak/strong 时为 strong。合法 sibling 不得掩盖另一个
artifact 的 missing/invalid；2.5 以下出现 CHECKSUMS 是 version/section operational
error。Bundler 4 另允许最多一条 `bundler (<version>) <checksums>` self-checksum：
version 必须与完整 `BUNDLED WITH` version byte-for-byte 相等；它计入 coverage 并作为
lockfile metadata integrity evidence 保留，但不生成 dependency record，也不送入
GH-90/GH-94 matcher。self-checksum 可缺失；重复或 version 错配是 operational error，
digest 非法则产生 invalid/block。fixture 覆盖 Bundler 2.4 无 section、2.5/2.6/3
有无 section、4 有无 self-checksum，以及 platform variant、unmatched、missing、
duplicate、version mismatch、invalid self-checksum 与 mixed algorithm。

### Source host policy、bounds 与 I/O boundary

| Ecosystem/format | Default exact hosts |
| --- | --- |
| npm/Yarn/pnpm | `registry.npmjs.org`, `registry.yarnpkg.com`, `npm.pkg.github.com` |
| Poetry/uv | `pypi.org`, `files.pythonhosted.org` |
| Cargo | `github.com`, `index.crates.io`, `static.crates.io` |
| Bundler | `rubygems.org`, `index.rubygems.org` |
| Composer | `repo.packagist.org`, `api.github.com`, `github.com`, `codeload.github.com` |
| go.sum | none；格式没有 source URL |

所有 URL/SSH/scp-like git locator 交给共享 parser；parse failure operational error。
HTTP 永远 Critical/block，不能被 allowlist 放行。HTTPS/SSH host 规范化为 IDNA ASCII
lowercase 后必须 exact 命中该行或重复的 CLI `--allow-registry-host <host>`；用户值
只接受单一 host（无 scheme、port、path、userinfo、wildcard 或 IP literal），排序
去重并记录为 evidence。

bounded reader 在 parser 前强制：input bytes ≤64 MiB、records ≤100,000、nesting
≤64、single scalar UTF-8 bytes ≤1 MiB、total scalar count ≤1,000,000；等号允许，
超限一失败。JSON/TOML/YAML duplicate map key 拒绝，YAML alias、anchor、tag、merge
key 与非-string map key 拒绝。`argus-lockfile` 不依赖 transport/process crate，
只接受调用者传入的 bytes/path label；测试用 trap PATH 和 loopback sentinel 证明
不启动进程/网络。finding/evidence 的 RFC 8785 canonical JSON 合计 ≤64 MiB；
`lockfile-integrity-unavailable` 按 format+state 聚合为一条并包含总数及最多 20 个
稳定排序 locator，其他 finding 不截断；合计超限时 operational error。

`policy` 模块只消费 normalized records：URL 交给共享 URL parser，按 ecosystem
policy 与 CLI `--allow-registry-host` 判断；git ref 分 mutable/commit；integrity
按 `required | optional | unavailable-by-format` 状态判断。finding detail 始终携带
lockfile locator，避免把“没有字段”与“parser 没看懂”混为一谈。

原 `argus_rules::scan_lockfile` 删除，CLI 改调新 crate。现有 npm rule IDs 保持，
新增 `lockfile-mutable-vcs-ref`、`lockfile-integrity-missing`、
`lockfile-integrity-invalid`、`lockfile-integrity-weak` 与
`lockfile-integrity-unavailable`。decision 闭集为：HTTP、untrusted host、mutable
VCS、missing required 或 invalid integrity => block；仅 weak integrity =>
allow-with-approval；unavailable-by-format Info 不改变 allow；任一 blocking finding
优先于 approval/info。unknown/ambiguous/new-version/partial/parse/limit error 在
report renderer 前返回 exit 2、stderr 与空 stdout。

## Planned Changes Manifest

<!-- specrail-planned-changes
{"version":1,"issue":91,"complete":true,"paths":["Cargo.lock","Cargo.toml","README.md","crates/argus-cli/Cargo.toml","crates/argus-cli/src/main.rs","crates/argus-cli/tests/lockfile_cli.rs","crates/argus-lockfile/Cargo.toml","crates/argus-lockfile/src/bounds.rs","crates/argus-lockfile/src/detect.rs","crates/argus-lockfile/src/lib.rs","crates/argus-lockfile/src/model.rs","crates/argus-lockfile/src/parsers/bundler.rs","crates/argus-lockfile/src/parsers/cargo.rs","crates/argus-lockfile/src/parsers/composer.rs","crates/argus-lockfile/src/parsers/go_sum.rs","crates/argus-lockfile/src/parsers/mod.rs","crates/argus-lockfile/src/parsers/package_lock.rs","crates/argus-lockfile/src/parsers/pnpm.rs","crates/argus-lockfile/src/parsers/poetry.rs","crates/argus-lockfile/src/parsers/uv.rs","crates/argus-lockfile/src/parsers/yarn.rs","crates/argus-lockfile/src/policy.rs","crates/argus-lockfile/tests/detection.rs","crates/argus-lockfile/tests/js_formats.rs","crates/argus-lockfile/tests/policy.rs","crates/argus-lockfile/tests/python_rust_go_formats.rs","crates/argus-lockfile/tests/resource_limits.rs","crates/argus-lockfile/tests/ruby_composer_formats.rs","crates/argus-rules/src/decision.rs","crates/argus-rules/src/lib.rs","crates/argus-rules/src/lockfile.rs","docs/supply-chain-attacks.md","specs/GH91/product.md","specs/GH91/tasks.md","specs/GH91/tech.md"],"spec_refs":["specs/GH91/product.md","specs/GH91/tasks.md","specs/GH91/tech.md"]}
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
records 与 coverage 统计。任何 detection/parse/coverage/bound error 在 report 前
失败；只有完整 analysis 才交给 policy 生成 findings 和 Lockfile report，再进入
既有 renderer。整个图没有 transport 或 process executor。

## 依赖与顺序

本实现复用 GH-90 的 `argus-core::PackageCoordinate`；GH-90 implementation 合并是
SP91-T1 的硬依赖，之前不得创建临时同义类型或启动 GH-91 implementation。GH-94 的
批量 lockfile 查询消费本 crate 的 normalized records，不应重新解析九类格式。

并行实现采用显式文件所有权与串行交接：

- SP91-T1 独占根 `Cargo.toml`、`Cargo.lock`、`crates/argus-lockfile/Cargo.toml`、
  `src/lib.rs`、`src/parsers/mod.rs`、`bounds.rs`、`detect.rs`、`model.rs` 以及
  detection/resource tests。T1 必须一次性声明全部九个 parser module、共享 trait/API
  与依赖并通过 compile-only stub 冻结边界；完成后这些 public/scaffold 文件冻结。
- SP91-T2 仅写 PackageLock/Yarn/pnpm parser 与 `js_formats.rs`；SP91-T3 仅写
  Poetry/uv/Cargo/go.sum parser 与 `python_rust_go_formats.rs`；SP91-T4 仅写
  Bundler/Composer parser 与 `ruby_composer_formats.rs`。三个 lane 不得修改
  `Cargo.toml`、`Cargo.lock`、`lib.rs`、`parsers/mod.rs` 或彼此文件。
- T2/T3/T4 全部停止写入后，SP91-T5 串行接收 root/crate manifest、`Cargo.lock` 与
  public integration 文件所有权，完成 `policy.rs`、CLI/rules/文档接线；如 parser
  contract 需变更，退回 T1 重新冻结并停止并行 lane，禁止各 lane 竞写 public 文件。
- SP91-T6 在所有 writable owner 退出后只执行验证，不修改实现或测试。

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
- [ ] Fixture：九格式版本/正负/partial-operational-error/invalid 矩阵。
- [ ] CLI：自动/显式格式、allowlist、text/JSON/SARIF 与退出码。
- [ ] Repository：workspace check/test、corpus test。

## 回滚方案

CLI 恢复调用 `argus_rules::scan_lockfile` 并移除新 crate，即可回到 npm-only 行为。
不修改 lockfile 本身，无数据迁移；失败 fixture 保留用于下一版设计。

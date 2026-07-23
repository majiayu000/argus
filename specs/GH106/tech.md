# Tech Spec

## Linked Issue

GH-106

## Product Spec

Link to `product.md`.

## Codebase Context

| Area | Files | Current behavior | Why relevant |
| --- | --- | --- | --- |
| surface 分类 | `crates/argus-agent/src/surface.rs:21` | `classify` 是语义扫描的路径形状入口；当前覆盖 instruction、MCP config 与 hook/skill script，但不覆盖 `.cursorrules` 或任意 `.claude/**` 条目 | AGT-04 membership 必须复用并扩展这个入口，不能在 snapshot 模块维护第二名单 |
| 收集顺序与 symlink | `crates/argus-agent/src/lib.rs:152`, `crates/argus-agent/src/lib.rs:255` | `collect_surface_files` 先收集再分类；受保护 surface 为 symlink 时在 `classify_candidates` hard error | snapshot 必须在不 follow symlink 的前提下先完成 inventory，随后仍保留语义 hard error，且不能丢已生成 diff |
| AGT-02 schema/hash | `crates/argus-agent/src/baseline.rs:41`, `crates/argus-agent/src/baseline.rs:133` | baseline 是版本号加排序 map；描述 SHA-256 hash，不保存明文 | 可复用确定性与隐私范式，但 AGT-04 粒度是完整成员而不是 description locator |
| enum exhaustive consumers | `crates/argus-agent/src/baseline.rs:137`, `crates/argus-agent/src/injection.rs:38` | 两处对 `SurfaceKind` 做 exhaustive match；新增 variant 必须显式 no-op 才能编译并保持语义 | planned changes 必须包含这两处；`capability.rs`、`config.rs`、`judge.rs` 经搜索均为 equality filter，不需修改 |
| AGT-02 原子写入 | `crates/argus-agent/src/baseline.rs:68` | 同目录 tempfile → write → flush → `sync_all` → persist；目前只为 `Baseline` 服务，失败注入覆盖不完整 | AGT-04 与 AGT-02 应共享原子字节写入器，五阶段注入仅放在 writer 私有 unit tests |
| agent scan 编排 | `crates/argus-agent/src/lib.rs:94` | 收集失败直接返回 `Err`；成功后依次运行 injection、capability、config、baseline，再 derive decision | 需要在默认路径不变的前提下表达“已完成 inventory finding + 后续 operational error” |
| Clap 参数 | `crates/argus-cli/src/main.rs:278`, `crates/argus-cli/src/main.rs:479` | `AgentOp::Scan` 定义并转发 `--baseline/--update-baseline`，没有 AGT-04 参数 | 新 flag 必须在 `main.rs` 声明并接入 `agent.rs`，不能只改 handler |
| CLI 守卫/退出 | `crates/argus-cli/src/agent.rs:32`, `crates/argus-cli/src/agent.rs:45` | baseline flag 互斥且只允许一个 path；update 强制 exit 0 | snapshot 使用相同单树守卫，但 update 不得压掉同次语义 finding |
| 决策 | `crates/argus-agent/src/decision.rs:7` | Medium → `allow-with-approval`，High/Critical → block | 五类 AGT-04 finding 固定为 Medium 即可进入批准流 |
| SARIF | `crates/argus-cli/src/sarif.rs:14`, `crates/argus-cli/src/sarif.rs:57` | 任意 AGT rule 可泛化渲染，但 invocation 总写 `executionSuccessful: true` | partial finding + operational error 时需保留 results 并标记执行失败 |
| 高上下文证据 | `README.md:329`, `docs/supply-chain-attacks.md:28` | 现有规则/文档列出 `.cursorrules`、`.claude/*`、`.aider.conf.yml`、`.continuerules`、`.codexrules`、`.windsurfrules`；GH-106 明确要求 `.claude/**` | 这些是扩展 `surface::classify` 的有仓库证据路径，不是 snapshot 私有猜测 |

## 设计方案

### 1. 严格 snapshot schema

新增 `crates/argus-agent/src/snapshot.rs`。持久格式固定为 JSON version 1，
尾部一个换行，`entries` 为按逻辑路径排序的 map：

```json
{
  "version": 1,
  "entries": {
    ".claude/settings.json": {
      "kind": "file",
      "digest": "64-lowercase-hex"
    },
    "AGENTS.md": {
      "kind": "symlink",
      "link_target_digest": "64-lowercase-hex"
    },
    ".claude/rules": {
      "kind": "directory"
    }
  }
}
```

root 与 entry 均 `deny_unknown_fields`，并在 deserialize 后做完整 validation：

- `version` 必须恰为 `1`；`entries: {}` 是合法且可 round-trip 的完整空
  inventory；
- key 必须是非空 UTF-8、相对、forward-slash 路径；禁止 `\`、空 segment、
  `.`、`..`、root/prefix component 与尾随 `/`；
- `kind` 是 `file | directory | symlink` 闭集；
- file 仅接受且必须有 `digest`，directory 两种 digest 都禁止，symlink 仅接受
  且必须有 `link_target_digest`；
- digest 必须是恰好 64 个小写十六进制字符。

不使用 `#[serde(default)]` 修复缺字段，不允许 unknown field 被忽略。合法旧
version 只有 v1；未来 schema 变更必须提升 version 并显式迁移，不能宽松读取。

### 2. inventory、路径与全字节 hash

discovery 按 `SnapshotMode` 分流。`None`（包括无 snapshot flag 与任意
AGT-02-only 模式）原样调用 legacy collector，继续用现有 `filter_entry` prune
`.git`/`node_modules`，不得为了 AGT-04 改变其 reachability、error 或输出。
只有 `Check/Update` 使用 complete inventory walker：沿用 root symlink 拒绝与
`follow_links(false)`，但不按 `.git`、`node_modules` 或其他 ancestor basename
剪掉 subtree，遍历每个非 symlink directory。

complete discovery 的内部记录冻结为正交字段：

```text
DiscoveredEntry {
  logical_path: String,
  absolute_path: PathBuf,
  entry_type: File | Directory | Symlink,
  surface_kind: Option<SurfaceKind>,
}
```

`entry_type` 只来自 `symlink_metadata`，`surface_kind` 只来自
`surface::classify`；两者不得互相推断或合并成一个 enum。对 complete discovery
看到的每个 entry：

1. 用严格 UTF-8 conversion 生成 `/` 分隔的逻辑相对路径；禁止
   `to_string_lossy`。无法转换时 operational error。
2. 将路径和完整 discovery 得到的 `skill_dirs` 交给唯一 membership API
   `surface::classify`，把结果写入 `surface_kind`。snapshot 模块不出现文件名、
   扩展名或目录形状常量。
3. `surface_kind == Some(_)` 的 directory 按 filesystem `entry_type` 记录
   `kind=directory`；classified file 用固定大小 buffer 循环
   `read` 到 EOF，把每个返回字节喂给 SHA-256，不复用语义扫描的
   `TEXT_MAX_BYTES`、UTF-8 或 binary 限制。
4. classified symlink 调用 `read_link`，只 hash 未经 string conversion 的目标表示：
   Unix 使用 `OsStrExt::as_bytes()`；Windows 使用 `encode_wide()` 的 u16 序列
   按 little-endian 字节序列化。只保留 `link_target_digest`，error/debug 信息
   也不得打印 target。
5. classified entry hash/read 前后各取 `symlink_metadata`；若 kind、length、mtime 或可用的
   file identity 变化，或 walker/read 任一步失败，整个 inventory
   operational failure，不能提交 partial snapshot。

完整遍历得到空 inventory 时，update 原子写入合法的 `entries: {}`。check 的
集合比较不把空集合当错误，但继续执行下节 symlink-first 优先级：

- empty approved → current file/directory：`AGT-04-entry-added`；
- empty approved → current symlink：`AGT-04-symlink-changed`；
- approved file/directory → empty current：`AGT-04-entry-removed`；
- approved symlink → empty current：`AGT-04-symlink-changed`。

empty ↔ empty 为 clean。只有无法证明遍历完整、snapshot 缺失/损坏或
schema/path 非法才 fail closed。

`--check-snapshot/--update-snapshot` 的 self-exclusion 必须经过 fail-closed
preflight：

1. 规范化 root 与 snapshot parent identity（不 follow 最终 snapshot symlink），
   用 path component 判断 snapshot target 是否位于 root 内。
2. 先完成不排除 snapshot target 的 complete discovery 与 `skill_dirs` 计算。
   若 target 在 root 内，以严格 UTF-8 logical relative path 调用同一个
   `surface::classify`；即使 update target 尚不存在也按其计划路径分类。
3. `classify == Some(_)`（含 `InventoryOnly`）时，check/update 在 snapshot load、
   inventory/semantic exclusion、stdout render 与 write 前返回 operational error；
   不得覆盖或隐藏该 surface。
4. 只有 target 在 root 外或 root 内且 `classify == None` 时，才把声明的 exact
   path 从 inventory 与 semantic collector 排除。不同 symlink alias 仍不排除。

### 3. canonical membership 只有 `surface::classify`

`surface.rs` 在同一个 enum 增加唯一类别 `SurfaceKind::InventoryOnly`；不得
另建 snapshot allowlist。对原 walker 可到达且已有语义分析的 shape，原有更具体
kind 优先；仅为 inventory 新纳入或位于 legacy-pruned ancestor（任一祖先
segment 为 `.git`/`node_modules`）后的受支持成员返回 `InventoryOnly`，从而
默认 semantic scan 不扩张而 AGT-04 仍完整覆盖。`classify` 的完整受支持形状
冻结为：

- 任意层级 basename `AGENTS.md`、`CLAUDE.md`、`SKILL.md`；
- `.mcp.json`、`mcp.json`、`.claude.json`；
- 任意名为 `.claude` 的 path segment 及其全部后代 entry（包括 directory、
  无扩展名、binary 与 symlink）；其中 markdown、settings JSON、hook script
  仍返回原有更具体 kind；
- root `hooks/`、`.claude/**/hooks/` 和带 `SKILL.md` tree 中现有支持扩展名的
  scripts；
- 任意层级 basename `.cursorrules`、`.aider.conf.yml`、`.continuerules`、
  `.codexrules`、`.windsurfrules`。

AGT-04 inventory 对 complete discovery 中所有
`surface_kind == Some(_)` 的 file、directory、symlink 按正交
`entry_type` 做 kind/digest 收集。`SnapshotMode::None` 不构造 complete
`DiscoveredEntry` 集合，继续走 legacy pruned collector；该 collector 在现有
classification 阶段遇到 `InventoryOnly` 时须在 state/body/symlink validation
前 no-op，但不改变 traversal 或其他 legacy 行为。

`Check/Update` 的 semantic projection 固定按以下顺序处理同一
`DiscoveredEntry` 集合：

1. `entry_type == Directory`：先跳过，不创建 `SurfaceFile`，无论
   `surface_kind` 为何；
2. file/symlink 且 `surface_kind == Some(InventoryOnly)`：在
   `read_limited`、正文读取、binary/UTF-8/size validation 与 symlink hard-error
   前跳过；
3. file/symlink 且 `surface_kind == None`：跳过；
4. symlink 且为既有 semantic kind：保留现有 protected symlink hard error；
5. file 且为既有 semantic kind：执行现有读取、validation 与 rule。

这样 `.claude/**`、`.cursorrules` 等仅为 AGT-04 新纳入的 binary、oversized、
symlink 不扩大 semantic 行为，原有 `Instruction/McpConfig/Script` file/symlink
语义不变。complete discovery 对 `.git`/`node_modules` 下钻，分类完成后才让
inventory 丢弃 `None`。因此
`.claude/node_modules/**`、`.claude/.git/**`、`node_modules/pkg/AGENTS.md`
等 protected descendants 可进入 AGT-04；普通 `.git/config`、package source 等
`classify == None` 的 entry 不进入 inventory。任何 descendant walk error 仍使
Check/Update inventory fail closed。`SnapshotMode::None` 仍在 legacy prune
处停止，不观察这些 descendant 或其 walk error。

`baseline.rs` 与 `injection.rs` 的 exhaustive match 显式增加
`SurfaceKind::InventoryOnly => {}`；`capability.rs`、`config.rs`、`judge.rs`
现有 equality filter 自然跳过该类别，搜索确认无需代码改动。以后扩展 path shape
只能改 `surface::classify` 及其 tests，snapshot 立即继承。

### 4. 五类 rule、优先级与 evidence

固定常量与 Medium severity：

| Rule ID | `change=` 字面值 | 触发 |
| --- | --- | --- |
| `AGT-04-symlink-changed` | `symlink_changed` | 任一侧 kind 为 symlink，且另一侧缺失或 kind/digest 不同 |
| `AGT-04-entry-added` | `entry_added` | 非 symlink entry 仅在 current |
| `AGT-04-entry-removed` | `entry_removed` | 非 symlink entry 仅在 approved |
| `AGT-04-entry-type-changed` | `entry_type_changed` | 两侧均非 symlink，file/directory 不同 |
| `AGT-04-content-modified` | `content_modified` | 两侧均为 file 且 digest 不同 |

比较先按 path 排序；同 path 只产生一个 rule，按表中优先级判定。`Finding.location`
是逻辑路径，`evidence` 固定为一个不含空格、无需 escaping 的分号 grammar：

```text
change=<kind>;old_kind=<kind|null>;new_kind=<kind|null>;old_digest=<hex|null>;new_digest=<hex|null>
```

`change` 只能是表中五个 snake_case 字面值，并与同一行 rule 一一映射；
`old_kind/new_kind` 是 `file|directory|symlink|null`，digest 是 64 位小写 hex
或 `null`。因此值中不允许分号、等号、空白或自定义字符串，也不存在 escaping
分支。symlink 的 `old_digest/new_digest` 填 link-target digest。detail 只复述
变化类型，不含正文或 target。这样 text、JSON、SARIF 复用既有 Finding，无需
修改 `argus-core` schema。

### 5. CLI flag 与 AGT-02 组合矩阵

在现有 `AgentOp::Scan` 增加两个 `Option<PathBuf>`：

- `--check-snapshot <FILE>`：AGT-04 Check；
- `--update-snapshot <FILE>`：AGT-04 Create/Update，missing 时创建、existing 时
  原子替换并表示显式批准。

Clap 与 handler 同时防御非法组合，避免只靠 parser 的内部调用绕过：

| 组合 | 结果 |
| --- | --- |
| `--check-snapshot S` | 允许，单个 PATH |
| `--update-snapshot S` | 允许，单个 PATH |
| `--baseline B --check-snapshot S` | 允许；两个只读比较合并到同一 report |
| snapshot check + snapshot update | Clap 拒绝 |
| 任一 update flag + 另外三个 persistence flag | Clap 拒绝 |
| 任一 persistence flag + 多个 PATH | handler operational error |
| 无 persistence flag | 完全保持当前行为 |

snapshot check/update 可与 `--llm-judge` 成对 flags 共存；judge operational
error 遵循下节 partial outcome。update 只有在 inventory、语义扫描与 judge
都完整执行后才写文件；写成功后 stderr 固定输出
`snapshot written: <N> entries`，但最终 exit 仍由同次语义 findings 派生，不能
像当前 AGT-02 update 一样无条件改成 0。

### 6. inventory 与语义扫描的顺序、partial outcome

新增内部 `SnapshotMode::{None, Check, Update}` 与不序列化的
`AgentScanOutcome { report, operational_error }`。`SnapshotMode::None` 无论
`BaselineMode` 为何都直接复用 legacy `.git`/`node_modules` pruning collector，
不执行 complete discovery、inventory 或 snapshot semantic projection。

启用 snapshot 的 `Check/Update` 顺序固定：

1. 规范化 root/snapshot identity；执行不按 ancestor basename 剪枝的
   complete discovery，计算 `skill_dirs`，生成正交
   `DiscoveredEntry { entry_type, surface_kind, ... }`，并对 root 内 snapshot
   target 执行 canonical membership guard。classified target 立即 operational
   reject。
2. check load + validate approved snapshot；完整构建 current inventory，只排除
   preflight 已证明在 root 外或 `classify == None` 的 exact snapshot path。
3. check 立即完成 compare 并保留排序后的 AGT-04 findings；update 暂存待写
   snapshot，但此时不写。
4. 从同一 discovery 按 directory → InventoryOnly file/symlink → unclassified
   → legacy semantic symlink/file 的固定顺序 projection，再运行 injection →
   capability → config → AGT-02 → judge；
   现有语义 finding 顺序不变，成功时把 AGT-04 findings 追加在其后，并只在
   内存构建 report/normal decision。
5. check 可进入正常 renderer；update 必须先执行原子 persist。persist 成功后
   才调用正常 text/JSON/SARIF renderer、输出 `snapshot written` 并返回 normal
   decision。normal output/exit 不得先于 persist。

若步骤 1-3 失败，比较没有完成，返回现有风格 operational error：stdout 空，
stderr diagnostic，不能渲染 clean report。若 inventory 已完成后，步骤 4 因
protected symlink/judge 失败，或步骤 5 的 CreateTemp/Write/Flush/FileSync/
Persist 任一阶段失败，统一进入 AGT-04 partial operational path：

- outcome 保留全部已完成 finding（check 的 AGT-04 diff 与 update 的既有语义
  finding），`report.decision` 强制为 `block`，
  不伪装成 allow/clean；
- text stdout 使用专用 partial renderer，固定含 `execution: incomplete` 与
  `decision: block`，保留 findings，但不得调用会输出 clean/allow 的正常
  renderer；stderr 输出 `argus: error: agent scan incomplete: ...`；进程使用
  现有 operational error exit code 2；
- JSON stdout 只在这个 partial case 使用以下专用 camelCase envelope，字段
  不可增删、改名或输出 `null` 替代对象；`message` 是不含正文/symlink target
  的 sanitized 单行字符串，`report` 是未改 schema 的既有 `ScanReport`：

```json
{
  "schemaVersion": 1,
  "executionSuccessful": false,
  "operationalError": {
    "kind": "agent_scan_incomplete",
    "message": "<sanitized>"
  },
  "report": "<existing ScanReport with decision=block and retained findings>"
}
```

- 完整 snapshot check/update 与无 snapshot scan 的 JSON stdout 仍直接序列化
  bare `ScanReport`（多 path 时仍是既有 report array），不使用 envelope；
- SARIF 保留 results，设置
  `runs[0].invocations[0].executionSuccessful=false`，并加入不含敏感内容的
  `toolExecutionNotifications` array；该 array 至少包含一个 sanitized error
  notification object
  `{"level":"error","message":{"text":"<sanitized>"}}`；result decision 为
  `block`；
- finding 只渲染一次，不能先打印后因 `?` 丢失或再跑一次比较。

无 snapshot flag 的 error/output 继续走现有路径；这套 partial 语义只解决
AGT-04 inventory 已完成后与 semantic/judge/persist error 的组合边界。update
persist failure 时 report 即使没有 finding 也必须在 partial text/JSON/SARIF
中标为 incomplete/block，不能退回 bare clean/allow report。

### 7. update persist-before-render 状态机

CLI handler 不得先调用现有 renderer 再执行 save。状态机固定为：

```text
inventory complete
  → semantic/judge complete
  → report + normal decision ready in memory
  → atomic persist attempt
      ├─ success → normal render → "snapshot written" → normal exit
      └─ error   → force report decision=block → partial render
                   → sanitized stderr → exit 2
```

CLI integration test 不注入 writer/scan seam。它通过
`env!("CARGO_BIN_EXE_argus")` 启动 production binary，把扫描 root 外一个含
sentinel file 的 non-empty directory 作为 `--update-snapshot` destination；
同目录 tempfile 的 production `Persist` 必须因不能替换 non-empty directory
而失败。text/JSON/SARIF 各自断言 exit 2、partial output、无 normal
clean/allow/report、无 `snapshot written`、sanitized stderr，且 sentinel
bytes/mtime 与目录内容不变。另用 root 外普通 file destination 做 success
control，证明 persist 成功后才出现 bare normal report 与成功消息。

不得为 CLI 测试增加 Cargo feature、公开或隐藏 fault API、隐藏 CLI flag、测试
环境变量或任何 production bypass。

### 8. shared atomic persistence 与故障注入

新增 `crates/argus-agent/src/atomic_write.rs`，接收最终序列化 bytes，并让
`baseline.rs` 与 `snapshot.rs` 共同调用。production 实现维持同目录 tempfile
流程；仅该 module 内部的私有 `#[cfg(test)]` writer/fault enum 精确覆盖：

`CreateTemp`、`Write`、`Flush`、`FileSync`、`Persist`。

每个 fault point 的测试都先写入 sentinel snapshot，记录 bytes/mtime，注入单点
失败后断言 error、旧 bytes/mtime 相同且无 `.argus-*-` 临时文件。不存在旧文件
时同样断言 destination 不存在。AGT-02 baseline 的既有序列化与行为不变，并有
回归测试证明 refactor 未改变 bytes。fault enum/seam 不得导出 crate，不得供
`argus-cli` 使用，也不得通过 feature、flag 或 env 暴露。

## 影响面与计划变更清单

- `crates/argus-agent/src/atomic_write.rs`：共享原子 byte writer；五阶段 fault
  seam 只存在于 module 私有 unit tests。
- `crates/argus-agent/src/baseline.rs`：改用共享 writer，并为 exhaustive match
  增加 InventoryOnly no-op，不改变 AGT-02 契约。
- `crates/argus-agent/src/injection.rs`：exhaustive match 增加 InventoryOnly
  no-op，不扩大 AGT-01 内容扫描。
- `crates/argus-agent/src/snapshot.rs`：strict schema、inventory/hash、compare/rules。
- `crates/argus-agent/src/surface.rs`：唯一 membership 扩展与 inventory-only kind。
- `crates/argus-agent/src/lib.rs`：SnapshotMode 分流、legacy collector 的
  InventoryOnly no-op、complete `DiscoveredEntry` inventory/semantic projection、
  persist-before-render 顺序与 partial outcome。
- `crates/argus-cli/src/main.rs`：Clap flags、conflict 矩阵及参数转发。
- `crates/argus-cli/src/agent.rs`：单路径守卫、partial JSON envelope、
  输出/exit/update 编排。
- `crates/argus-cli/src/sarif.rs`：incomplete invocation 的 SARIF 表达。
- `crates/argus-agent/tests/gh106_snapshot.rs` 与固定 fixture：schema、hash、
  mode-split discovery、正交 projection、InventoryOnly 默认行为、五类 rule 与
  fail-closed；atomic 五阶段矩阵留在 writer module unit tests。
- `crates/argus-cli/tests/agent_snapshot_cli.rs`：help/互斥、共存、三种输出、
  production directory-destination Persist failure、ordering、sentinel、
  partial envelope 与完整 JSON 回归。
- `README.md`：AGT-04 workflow、rule、批准边界与限制。

<!-- specrail-planned-changes
{"version":1,"issue":106,"complete":true,"paths":["specs/GH106/product.md","specs/GH106/tech.md","specs/GH106/tasks.md","crates/argus-agent/src/atomic_write.rs","crates/argus-agent/src/baseline.rs","crates/argus-agent/src/injection.rs","crates/argus-agent/src/snapshot.rs","crates/argus-agent/src/surface.rs","crates/argus-agent/src/lib.rs","crates/argus-agent/tests/gh106_snapshot.rs","crates/argus-agent/tests/fixtures/agt04-snapshot-base/AGENTS.md","crates/argus-agent/tests/fixtures/agt04-snapshot-base/.claude/settings.json","crates/argus-agent/tests/fixtures/agt04-snapshot-base/.claude/rules/policy.txt","crates/argus-agent/tests/fixtures/agt04-snapshot-base/.cursorrules","crates/argus-cli/src/main.rs","crates/argus-cli/src/agent.rs","crates/argus-cli/src/sarif.rs","crates/argus-cli/tests/agent_snapshot_cli.rs","README.md"],"spec_refs":["specs/GH106/product.md","specs/GH106/tech.md","specs/GH106/tasks.md"]}
-->

现有 manifest 已包含实现专用 envelope 所需的 `main.rs`（flag/参数转发）、
`agent.rs`（JSON serialization/exit）与 `agent_snapshot_cli.rs`（shape 与兼容
回归）；因为 envelope 嵌入现有 `ScanReport` 而不改其 schema，不新增
`argus-core` 路径。

## Product-to-Test Mapping

| Behavior invariant | Implementation area | Verification |
| --- | --- | --- |
| B-001 | inventory、streaming SHA-256、排序与 guarded self-exclusion | `cargo test -p argus-agent --test gh106_snapshot snapshot_path_membership_guard` |
| B-002 | strict v1 deserialize/validation | `cargo test -p argus-agent --test gh106_snapshot strict_schema_matrix` |
| B-003 | compare 优先级、五个 rule 常量与 canonical evidence | `cargo test -p argus-agent --test gh106_snapshot five_change_rules_are_medium` |
| B-004 | `lib.rs` 顺序/partial outcome、CLI bytes/mtime 与专用 JSON envelope | `cargo test -p argus-cli --test agent_snapshot_cli partial_json_envelope_is_exact_and_complete_json_is_unchanged` |
| B-005 | path/UTF-8/race/read/hash、classified snapshot target fail-closed 与空集合 transition | `cargo test -p argus-agent --test gh106_snapshot snapshot_path_membership_guard` |
| B-006 | 私有 atomic unit fault matrix + production CLI persist-before-render failure | `cargo test -p argus-agent atomic_write_fault_matrix && cargo test -p argus-cli --test agent_snapshot_cli production_persist_failure_is_partial` |
| B-007 | `main.rs` Clap contract + `agent.rs` defensive guard | `cargo test -p argus-cli --test agent_snapshot_cli flag_contract_matrix` |
| B-008 | symlink raw-byte digest 与 all-format leak negatives | `cargo test -p argus-cli --test agent_snapshot_cli symlink_digest_never_leaks_target` |
| B-009 | Medium decision、update approval、finding/exit preservation | `cargo test -p argus-cli --test agent_snapshot_cli approval_and_update_exit_contract` |
| B-010 | mode-split discovery、正交 `DiscoveredEntry` 与 semantic projection | `cargo test -p argus-agent --test gh106_snapshot snapshot_modes_split_discovery` |

## 数据流

共同前缀只有 `PATH + SnapshotMode + BaselineMode` → strict identity/path
validation，随后按 mode 分流：

```text
SnapshotMode::None (including AGT-02-only)
  → legacy .git/node_modules-pruned collector
  → InventoryOnly no-op before legacy validation
  → existing semantic rules/AGT-02/judge
  → existing report/output/error path

SnapshotMode::Check | Update
  → complete non-pruning discovery + skill_dirs
  → DiscoveredEntry(entry_type, surface_kind)
  → root-contained snapshot target membership guard
  → permitted exact self-exclusion
  → check: load and validate approved v1 snapshot
  → inventory projection of every classified file/directory/symlink
  → check: compare approved/current and retain sorted findings
  → semantic projection: directory → InventoryOnly → unclassified
                         → legacy semantic symlink/file
  → existing semantic rules/AGT-02/judge
  → report/decision ready in memory
```

classified snapshot target 在 snapshot guard 处直接 operational failure，不进入
exclusion/load/render/write。snapshot report ready 后只能进入以下互斥分支：

```text
check success
  → report in memory
  → normal text/JSON/SARIF renderer
  → normal exit

update success
  → report in memory
  → atomic snapshot persist success
  → normal text/JSON/SARIF renderer
  → "snapshot written"
  → normal exit

semantic / judge / persist error after inventory completion
  → retained in-memory report with decision=block
  → partial operational text/JSON/SARIF renderer
  → sanitized stderr
  → exit 2
```

error 分支绝不调用 normal renderer，persist error 也不得在失败前输出 bare
report、`snapshot written` 或 normal exit。

没有网络调用、子进程或被扫描代码执行；仅显式 LLM judge 保持现有 opt-in 行为。

## 备选方案

- 在 `snapshot.rs` 维护独立高上下文文件名列表：拒绝，会与 AGT-01/03/05
  coverage 漂移，违反 B-010。
- 在 AGT-04 Check/Update classification 前 prune `.git`/`node_modules`：拒绝，
  会遗漏受支持 high-context descendant；snapshot mode 必须先遍历/分类。
  反向把 complete discovery 用于 `SnapshotMode::None` 也拒绝；legacy pruning
  是默认 scan 与 AGT-02-only 的兼容契约。
- 无条件排除 snapshot path：拒绝，classified target 可借此绕过 inventory 与
  AGT-01/05。只有 canonical classifier 返回 `None` 才允许 root 内 self-exclusion。
- 保存 symlink target 字符串：拒绝，会泄露用户目录、秘密挂载名或注入文本。
- 复用语义 collector 的 `SurfaceFile.content` 做 digest：拒绝，其 UTF-8、
  binary 与 size 限制无法证明“全部原始字节”。
- 在 semantic hard error 后丢弃已完成 diff：拒绝，用户会失去最关键的 symlink
  变化证据。将 partial report 标记为成功同样拒绝。
- 同一命令同时 update AGT-02 与 AGT-04：拒绝，两个文件无法组成一个原子批准
  transaction；保留 check+check 是最小且安全的共存面。

## 风险

- Security: snapshot 是信任锚点；README 必须要求放在安装脚本不可写位置或由
  独立版本控制保护。仅 preflight 允许的 exact self-exclusion 不能扩展成 alias
  排除；classified target 永不排除。
- Security: error、debug、SARIF notification 同样不得包含正文或 symlink target。
- Compatibility: 默认 scan 与 AGT-02-only 行为不变；snapshot schema v1 严格，
  跨平台搬迁可能因 symlink 原始表示不同而需要在目标平台显式 update。
- Performance: file hash 读取全部字节且无语义 size cap；固定 buffer 保持 O(1)
  额外内存，walker 和 compare 为 O(n log n)。只有 Check/Update 为发现
  protected descendants 而不 prune `.git`/`node_modules`；只 hash classified
  entries，但大型 tree 的 metadata walk 成本必须由 benchmark/文档如实说明。
  None/AGT-02-only 保留 legacy pruning，不承担该新增成本。
- Concurrency: snapshot 是观察到的稳定 inventory，不是 filesystem transaction；
  前后 metadata 变化会 fail closed，但不可观察的同 metadata 并发写仍是文件系统
  固有限制，需在 README 说明安装过程结束后再 check。
- Maintenance: `surface.rs`、`agent.rs` 已较大；snapshot/atomic/tests 使用新文件，
  不把 `integration.rs` 推过 800 行 hard ceiling。

## 测试计划

- [ ] Unit/integration: strict schema 全字段组合、规范路径、未知 version/field、
      合法空 snapshot round-trip、非 UTF-8 member path。
- [ ] Hash/privacy: multi-chunk binary file、尾块变化、guarded snapshot
  self-exclusion、
      非 UTF-8 symlink target、明文负断言。
- [ ] Snapshot path guard: root 内 existing/missing `AGENTS.md`、
      `.claude/settings.json`、`.cursorrules` 与 skill script 在 check/update 都于
      exclusion/load/render/write 前失败且 bytes/mtime 不变；root 内
      `classify == None` 与 root 外 target 成功，symlink alias 仍纳入 inventory。
- [ ] Diff/decision: clean + 五类 rule/优先级/Medium/稳定顺序；空集合四项矩阵
      分别断言 file/directory added、symlink added→symlink-changed、
      file/directory removed、symlink removed→symlink-changed；empty↔empty
      clean。
- [ ] Atomic: 五个 fault point，existing/missing destination，bytes/mtime/temp cleanup；
      AGT-02 serialized bytes 回归；fault seam 保持 `argus-agent` module 私有。
- [ ] Persist ordering: `CARGO_BIN_EXE_argus` 以 root 外 non-empty directory
      destination 触发真实 production Persist failure，断言 normal renderer/exit
      未调用、JSON/SARIF/text 走 partial、stderr sanitized、exit 2、sentinel
      bytes/mtime 不变；普通 file destination success control 断言 persist
      happens-before normal render。无 feature、公开/隐藏 API、hidden flag/env。
- [ ] CLI: help、conflict 矩阵、单路径、baseline check + snapshot check、update 不压
      finding/exit、check bytes/mtime。
- [ ] Mode compatibility: SnapshotMode None 的无 snapshot 与 AGT-02-only
      check/update 都保持 legacy `.git`/`node_modules` pruning、finding/error 与
      输出；Check/Update 才 complete-discover 相同 tree。
- [ ] Projection/completeness: `DiscoveredEntry.entry_type` 与 `surface_kind`
      正交；Check/Update 中 classified file/directory/symlink 全部进入 inventory，
      semantic projection 依次跳过 directory、InventoryOnly file/symlink、
      unclassified，并保留既有 semantic symlink hard error 与 file validation。
      `.claude/node_modules/**`、`.claude/.git/**`、
      `node_modules/pkg/AGENTS.md` 与 `.git/**/.cursorrules` 仅在 snapshot
      complete discovery 到达 classifier；普通 unclassified descendant 不进入
      inventory，深层 walk error fail closed。
- [ ] Output: partial JSON 精确 camelCase envelope 与 sanitized error；完整
      snapshot/无 snapshot JSON 保持 bare report；SARIF
      `executionSuccessful=false`、findings 不丢不重复、stderr 无敏感内容。
- [ ] Repository: fmt/check/clippy/workspace tests、agent corpus、SpecRail targeted/all。
- [ ] Coverage: `cargo llvm-cov -p argus-agent -p argus-cli --summary-only` 新代码行
      至少 80%，schema/hash/atomic/fail-closed 关键分支 100%。

## 回滚方案

AGT-04 是 opt-in。回滚实现 commit 即恢复默认行为，无数据库迁移；已生成 v1
snapshot 不再读取，可由用户保留。不得以放宽 schema、跳过 unreadable member、
截断 hash、把 operational failure 改为 clean 或保存 target 明文作为回滚。
若只回滚 shared writer，必须先证明 AGT-02 baseline bytes 与原子失败语义未退化。

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
| AGT-02 原子写入 | `crates/argus-agent/src/baseline.rs:68` | 同目录 tempfile → write → flush → `sync_all` → persist；目前只为 `Baseline` 服务，失败注入覆盖不完整 | AGT-04 与 AGT-02 应共享一个可故障注入的原子字节写入器 |
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

inventory walker 沿用现有 root 规则：root symlink 拒绝，`follow_links(false)`，
`.git`/`node_modules` 使用同一共享遍历排除策略。对 walker 看到的每个 entry：

1. 用严格 UTF-8 conversion 生成 `/` 分隔的逻辑相对路径；禁止
   `to_string_lossy`。无法转换时 operational error。
2. 将路径和已发现的 `skill_dirs` 交给唯一 membership API
   `surface::classify`。snapshot 模块不出现文件名、扩展名或目录形状常量。
3. 对 classified directory 记录 kind；对 file 用固定大小 buffer 循环
   `read` 到 EOF，把每个返回字节喂给 SHA-256，不复用语义扫描的
   `TEXT_MAX_BYTES`、UTF-8 或 binary 限制。
4. 对 symlink 调用 `read_link`，只 hash 未经 string conversion 的目标表示：
   Unix 使用 `OsStrExt::as_bytes()`；Windows 使用 `encode_wide()` 的 u16 序列
   按 little-endian 字节序列化。只保留 `link_target_digest`，error/debug 信息
   也不得打印 target。
5. entry hash/read 前后各取 `symlink_metadata`；若 kind、length、mtime 或可用的
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
`--check-snapshot/--update-snapshot` 指定的 snapshot 路径先做规范化 identity，
并从 walker 与语义 collector 都排除；只排除这个显式路径，不排除指向它的其他
symlink alias。

### 3. canonical membership 只有 `surface::classify`

`surface.rs` 在同一个 enum 增加唯一类别 `SurfaceKind::InventoryOnly`；不得
另建 snapshot allowlist。原有更具体 kind 优先，无法参加现有语义规则的高上下文
成员才返回 `InventoryOnly`。`classify` 的完整受支持形状冻结为：

- 任意层级 basename `AGENTS.md`、`CLAUDE.md`、`SKILL.md`；
- `.mcp.json`、`mcp.json`、`.claude.json`；
- 任意名为 `.claude` 的 path segment 及其全部后代 entry（包括 directory、
  无扩展名、binary 与 symlink）；其中 markdown、settings JSON、hook script
  仍返回原有更具体 kind；
- root `hooks/`、`.claude/**/hooks/` 和带 `SKILL.md` tree 中现有支持扩展名的
  scripts；
- 任意层级 basename `.cursorrules`、`.aider.conf.yml`、`.continuerules`、
  `.codexrules`、`.windsurfrules`。

AGT-04 inventory 对所有 `classify(...) == Some(_)` 的 entry 做 kind/digest
收集。普通 semantic collector 改成 metadata-only discovery → 计算
`skill_dirs` → `surface::classify` 两阶段流程；遇到 `InventoryOnly` 必须在
`read_limited`、正文读取、binary/UTF-8/size validation 与 protected symlink
hard-error 之前跳过。这样 `.claude/**`、`.cursorrules` 等仅为 AGT-04 新纳入的
binary、oversized、symlink 不会改变无 snapshot flag 的默认 scan；原先返回
`Instruction/McpConfig/Script` 的 shape 继续走现有读取、validation 与 rule，
其 hard-error 语义不变。

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
`AgentScanOutcome { report, operational_error }`。启用 snapshot 时顺序固定：

1. 规范化 root/snapshot identity；load + validate approved snapshot（check）。
2. 完整构建 current inventory，排除 snapshot 自身。
3. check 立即完成 compare 并保留排序后的 AGT-04 findings；update 暂存待写
   snapshot，但此时不写。
4. 运行现有语义收集与 injection → capability → config → AGT-02 → judge；
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
  error `toolExecutionNotification`；result decision 为 `block`；
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

FileSync/Persist 及其他 fault point 的 CLI test 使用 test-only injected writer/
scan seam，设置一个原有 sentinel snapshot 并记录 bytes/mtime。每个 fault 都断言
normal renderer 和 normal exit 尚未调用、sentinel 不变、临时文件清理；随后分别
验证 JSON envelope、SARIF `executionSuccessful=false`、text 含
`execution: incomplete` 且不含 clean/allow。success control 断言 persist 完成
后才出现 bare report 与正常 exit。

### 8. shared atomic persistence 与故障注入

新增 `crates/argus-agent/src/atomic_write.rs`，接收最终序列化 bytes，并让
`baseline.rs` 与 `snapshot.rs` 共同调用。production 实现维持同目录 tempfile
流程；test-only writer/fault enum 精确覆盖：

`CreateTemp`、`Write`、`Flush`、`FileSync`、`Persist`。

每个 fault point 的测试都先写入 sentinel snapshot，记录 bytes/mtime，注入单点
失败后断言 error、旧 bytes/mtime 相同且无 `.argus-*-` 临时文件。不存在旧文件
时同样断言 destination 不存在。AGT-02 baseline 的既有序列化与行为不变，并有
回归测试证明 refactor 未改变 bytes。

## 影响面与计划变更清单

- `crates/argus-agent/src/atomic_write.rs`：共享、可故障注入的原子 byte writer。
- `crates/argus-agent/src/baseline.rs`：改用共享 writer，并为 exhaustive match
  增加 InventoryOnly no-op，不改变 AGT-02 契约。
- `crates/argus-agent/src/injection.rs`：exhaustive match 增加 InventoryOnly
  no-op，不扩大 AGT-01 内容扫描。
- `crates/argus-agent/src/snapshot.rs`：strict schema、inventory/hash、compare/rules。
- `crates/argus-agent/src/surface.rs`：唯一 membership 扩展与 inventory-only kind。
- `crates/argus-agent/src/lib.rs`：两阶段 semantic collector、SnapshotMode、
  persist-before-render 顺序与 partial outcome。
- `crates/argus-cli/src/main.rs`：Clap flags、conflict 矩阵及参数转发。
- `crates/argus-cli/src/agent.rs`：单路径守卫、partial JSON envelope、
  输出/exit/update 编排。
- `crates/argus-cli/src/sarif.rs`：incomplete invocation 的 SARIF 表达。
- `crates/argus-agent/tests/gh106_snapshot.rs` 与固定 fixture：schema、hash、
  membership、InventoryOnly 默认行为、五类 rule、atomic/fail-closed。
- `crates/argus-cli/tests/agent_snapshot_cli.rs`：help/互斥、共存、三种输出、
  persist fault ordering、bytes/mtime、partial envelope 与完整 JSON 回归。
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
| B-001 | `snapshot.rs` inventory、streaming SHA-256、排序与 self-exclusion | `cargo test -p argus-agent --test gh106_snapshot deterministic_full_byte_inventory` |
| B-002 | strict v1 deserialize/validation | `cargo test -p argus-agent --test gh106_snapshot strict_schema_matrix` |
| B-003 | compare 优先级、五个 rule 常量与 canonical evidence | `cargo test -p argus-agent --test gh106_snapshot five_change_rules_are_medium` |
| B-004 | `lib.rs` 顺序/partial outcome、CLI bytes/mtime 与专用 JSON envelope | `cargo test -p argus-cli --test agent_snapshot_cli partial_json_envelope_is_exact_and_complete_json_is_unchanged` |
| B-005 | path/UTF-8/race/read/hash fail-closed 与合法空集合 transition | `cargo test -p argus-agent --test gh106_snapshot empty_inventory_transition_matrix` |
| B-006 | atomic fault matrix + CLI persist-before-render state machine | `cargo test -p argus-cli --test agent_snapshot_cli persist_fault_never_renders_normal_report` |
| B-007 | `main.rs` Clap contract + `agent.rs` defensive guard | `cargo test -p argus-cli --test agent_snapshot_cli flag_contract_matrix` |
| B-008 | symlink raw-byte digest 与 all-format leak negatives | `cargo test -p argus-cli --test agent_snapshot_cli symlink_digest_never_leaks_target` |
| B-009 | Medium decision、update approval、finding/exit preservation | `cargo test -p argus-cli --test agent_snapshot_cli approval_and_update_exit_contract` |
| B-010 | `surface::classify`/InventoryOnly 与两阶段 semantic collector | `cargo test -p argus-agent --test gh106_snapshot inventory_only_preserves_default_scan` |

## 数据流

`PATH + SnapshotMode + BaselineMode` → strict identity/path validation →
non-following inventory walker → full-byte/file-or-link hash → optional v1 snapshot
load/compare → sorted AGT-04 findings → existing semantic rules/AGT-02/judge →
merged report or retained partial report → text/JSON/SARIF renderer → optional
atomic snapshot persist（仅 update 且前序完整）。

没有网络调用、子进程或被扫描代码执行；仅显式 LLM judge 保持现有 opt-in 行为。

## 备选方案

- 在 `snapshot.rs` 维护独立高上下文文件名列表：拒绝，会与 AGT-01/03/05
  coverage 漂移，违反 B-010。
- 保存 symlink target 字符串：拒绝，会泄露用户目录、秘密挂载名或注入文本。
- 复用语义 collector 的 `SurfaceFile.content` 做 digest：拒绝，其 UTF-8、
  binary 与 size 限制无法证明“全部原始字节”。
- 在 semantic hard error 后丢弃已完成 diff：拒绝，用户会失去最关键的 symlink
  变化证据。将 partial report 标记为成功同样拒绝。
- 同一命令同时 update AGT-02 与 AGT-04：拒绝，两个文件无法组成一个原子批准
  transaction；保留 check+check 是最小且安全的共存面。

## 风险

- Security: snapshot 是信任锚点；README 必须要求放在安装脚本不可写位置或由
  独立版本控制保护。snapshot 自身排除不能扩展成 alias 排除。
- Security: error、debug、SARIF notification 同样不得包含正文或 symlink target。
- Compatibility: 默认 scan 与 AGT-02-only 行为不变；snapshot schema v1 严格，
  跨平台搬迁可能因 symlink 原始表示不同而需要在目标平台显式 update。
- Performance: file hash 读取全部字节且无语义 size cap；固定 buffer 保持 O(1)
  额外内存，walker 和 compare 为 O(n log n)。
- Concurrency: snapshot 是观察到的稳定 inventory，不是 filesystem transaction；
  前后 metadata 变化会 fail closed，但不可观察的同 metadata 并发写仍是文件系统
  固有限制，需在 README 说明安装过程结束后再 check。
- Maintenance: `surface.rs`、`agent.rs` 已较大；snapshot/atomic/tests 使用新文件，
  不把 `integration.rs` 推过 800 行 hard ceiling。

## 测试计划

- [ ] Unit/integration: strict schema 全字段组合、规范路径、未知 version/field、
      合法空 snapshot round-trip、非 UTF-8 member path。
- [ ] Hash/privacy: multi-chunk binary file、尾块变化、snapshot self-exclusion、
      非 UTF-8 symlink target、明文负断言。
- [ ] Diff/decision: clean + 五类 rule/优先级/Medium/稳定顺序；空集合四项矩阵
      分别断言 file/directory added、symlink added→symlink-changed、
      file/directory removed、symlink removed→symlink-changed；empty↔empty
      clean。
- [ ] Atomic: 五个 fault point，existing/missing destination，bytes/mtime/temp cleanup；
      AGT-02 serialized bytes 回归。
- [ ] Persist ordering: FileSync/Persist 及其余 fault point 在 CLI seam 注入失败，
      断言 normal renderer/exit 未调用、JSON/SARIF/text 走 partial、stderr
      sanitized、exit 2、旧 snapshot bytes/mtime 不变；success control 断言
      persist happens-before normal render。
- [ ] CLI: help、conflict 矩阵、单路径、baseline check + snapshot check、update 不压
      finding/exit、check bytes/mtime。
- [ ] Default compatibility: 无 snapshot flag 分别扫描 inventory-only binary、
      oversized 与 symlink fixtures，不新增 finding/error；相同 fixtures 在
      snapshot mode 全部进入 inventory。既有 Instruction/McpConfig/Script 的
      binary/UTF-8/size/symlink hard-error regression 保持。
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

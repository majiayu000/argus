# Tech Spec

## Linked Issue

GH-106

## Product Spec

Link to `product.md`.

## Codebase Context

| Area | Files | Current behavior | Why relevant |
| --- | --- | --- | --- |
| surface 分类 | `crates/argus-agent/src/surface.rs:21` | `classify` 按文件名与目录形状返回 `Instruction` / `McpConfig` / `Script` | AGT-04 的路径集合必须复用同一分类，不另立清单 |
| AGT-02 baseline 结构 | `crates/argus-agent/src/baseline.rs:43` | `Baseline { version, entries: BTreeMap<String,String> }`，键为 `"<rel>#<locator>"` 的描述条目 | 版本化 + 确定性排序的既有范式，但键粒度是描述条目而非文件 |
| baseline 读取 | `crates/argus-agent/src/baseline.rs:60` | `load` 对缺失或损坏返回 `Err`，由调用方转成 finding | AGT-04 的失败语义必须比这更严格：不得降级为 clean |
| baseline 原子写入 | `crates/argus-agent/src/baseline.rs:72` | 写临时文件 → `write_all` / `flush` / `sync_all` → `persist` 原子替换，每个失败阶段都清理临时文件 | AGT-04 的 update 直接复用该写入范式 |
| 描述条目抽取 | `crates/argus-agent/src/baseline.rs:134` | `extract_entries` 从 `SurfaceFile` 抽取描述类条目 | AGT-04 需要的是文件级 digest，与之并列而非替换 |
| 漂移比较 | `crates/argus-agent/src/baseline.rs:155` | `check_drift` 只比较条目 hash，缺失条目不产生新增/删除语义 | AGT-04 需要集合差异（增/删/类型/symlink），是新逻辑 |
| CLI baseline 模式 | `crates/argus-cli/src/agent.rs:35` | `BaselineMode::{Check,Update,None}`，check/update 互斥，且 baseline 模式拒绝多路径 | AGT-04 的模式开关与多路径约束沿用同一形状 |
| 多路径守卫 | `crates/argus-cli/src/agent.rs:45` | baseline 模式下 `paths.len() > 1` 直接报错，避免静默丢失保护 | snapshot 同样是“单一已批准树”，必须复用该守卫 |

## 设计方案

### 1. snapshot 数据结构

新增 `crates/argus-agent/src/snapshot.rs`，与 `baseline.rs` 并列而不是改写它
（AGT-02 的键粒度是描述条目，AGT-04 的键粒度是文件，二者不可合并）。

```
Snapshot {
    version: u32,                      // 版本化 schema，见 B-002
    entries: BTreeMap<String, Entry>,  // 逻辑相对路径 → 条目，确定性排序
}

Entry {
    kind: EntryKind,                   // File | Directory | Symlink
    digest: Option<String>,            // 内容 digest；仅 File 有
    link_target: Option<String>,       // 仅 Symlink 有
}
```

`BTreeMap` 保证序列化顺序确定；`version` 在读取时严格校验，未知版本直接
`Err`，不按当前版本解释（B-002）。`Entry` 只含路径、类型、digest 与
symlink 目标，不含正文（B-008）。

### 2. 路径集合来自既有 surface 分类

snapshot 的成员由 `surface::classify` 决定，加上 issue 明确列出的
`.cursorrules` 等高上下文路径。新增路径形状必须扩展 `surface.rs` 的分类，
不得在 AGT-04 内维护第二份清单（B-010）。

### 3. 三种模式

- `snapshot`：遍历目标树，生成条目集合，原子写入。
- `check`：读取 snapshot，与当前树比较，产生 finding。严格只读（B-004、B-007）。
- `update`：等价于 snapshot，但语义上表示“人工批准当前状态”（B-007、B-009）。

check 与 update 互斥，且沿用 `agent.rs:45` 的多路径守卫：snapshot 表达单一
已批准树，多路径会让后写覆盖先写，静默丢失保护。

### 4. 集合比较产生五类变化

比较是 snapshot 条目集合与当前条目集合的双向差集：

| 情况 | 变化类型 |
| --- | --- |
| 仅在当前树 | `added` |
| 仅在 snapshot | `removed` |
| 两侧均有，`kind` 不同 | `type-changed` |
| 两侧均为 Symlink，`link_target` 不同 | `symlink-target-changed` |
| 两侧均为 File，`digest` 不同 | `modified` |

每类产生独立 rule id，finding 携带逻辑路径、变化类型与旧/新 digest。
symlink 变化必须与内容修改区分：把 `AGENTS.md` 替换为指向他处的 symlink
不改变“读到的内容”，但改变了信任边界。

### 5. 失败必须显式，不得降级为 clean

以下每一项都产生 operational error 结论而非 clean（B-005）：

- snapshot 文件缺失
- snapshot 解析失败
- snapshot 版本不受支持
- 目标路径不可读（含遍历中任一条目不可读）
- 遍历未能完整覆盖声明范围

这比 `baseline.rs:60` 现有语义更严格：AGT-02 把缺失 baseline 转成 info
finding 是可接受的，因为它是可选增强；AGT-04 的整个价值就是“这次安装改了
什么”，一次不完整的比较等价于没有答案，报告 clean 会构成静默降级。

### 6. update 的原子性

update 直接复用 `baseline::save` 的写入范式：临时文件 → `write_all` →
`flush` → `sync_all` → `persist` 原子替换，任一阶段失败都清理临时文件并
返回错误，原 snapshot 保持不变（B-006）。

## 影响面

- `crates/argus-agent/src/snapshot.rs`：新增数据结构、load/save、比较逻辑。
- `crates/argus-agent/src/lib.rs`：模式入口与扫描集成。
- `crates/argus-agent/src/surface.rs`：扩展高上下文路径形状。
- `crates/argus-cli/src/agent.rs`：CLI 模式开关与多路径守卫。
- `crates/argus-cli/src/sarif.rs`：AGT-04 finding 的 SARIF 映射。
- `README.md`：审批边界、推荐流程与限制。

<!-- specrail-planned-changes
{"version":1,"issue":106,"complete":true,"paths":["specs/GH106/product.md","specs/GH106/tech.md","specs/GH106/tasks.md","crates/argus-agent/src/snapshot.rs","crates/argus-agent/src/lib.rs","crates/argus-agent/src/surface.rs","crates/argus-cli/src/agent.rs","crates/argus-cli/src/sarif.rs","README.md"],"spec_refs":["specs/GH106/product.md","specs/GH106/tech.md","specs/GH106/tasks.md"]}
-->

## Product-to-Test Mapping

| Behavior invariant | Implementation area | Verification |
| --- | --- | --- |
| B-001 | `snapshot.rs` 条目生成与确定性序列化 | `cargo test -p argus-agent snapshot_deterministic` |
| B-002 | `snapshot::load` 版本校验 | `cargo test -p argus-agent snapshot_version` |
| B-003 | 集合比较的五类变化 | `cargo test -p argus-agent snapshot_change_kinds` |
| B-004 | check 模式只读与幂等 | `cargo test -p argus-agent snapshot_check_readonly` |
| B-005 | 失败路径显式化 | `cargo test -p argus-agent snapshot_fail_closed` |
| B-006 | 原子替换与失败保留 | `cargo test -p argus-agent snapshot_atomic_update` |
| B-007 | check/update 分离 | `cargo test -p argus-cli agt04` |
| B-008 | 输出不含明文 | `cargo test -p argus-agent snapshot_no_plaintext` |
| B-009 | 批准边界 | `cargo test -p argus-cli agt04_approval` |
| B-010 | 复用 surface 分类 | `cargo test -p argus-agent surface` |

## 风险

- Security: snapshot 本身成为信任锚点。若 snapshot 可被安装脚本写入，
  保护失效；因此 update 必须是显式人工动作，且文档需说明 snapshot 应存放
  在被扫描树之外或受保护位置。
- Security: digest 算法选择需与既有 baseline 一致，避免出现两套强度不同的
  完整性保证。
- Compatibility: 不带 AGT-04 参数的扫描行为完全不变。
- Performance: 一次遍历 + digest 计算，与现有 surface 扫描同数量级。
- Maintenance: 路径集合必须单一来源（`surface.rs`），否则 AGT-01 与 AGT-04
  会随时间漂移出不同的覆盖面。

## 测试计划

- [ ] Unit tests: 版本校验、确定性序列化、五类变化、原子写入失败路径。
- [ ] Integration tests: 离线 fixture 覆盖创建、无变化、增、删、改、
      类型变化、symlink 变化。
- [ ] Fail-closed tests: 缺失、损坏、版本不支持、不可读、不完整遍历。
- [ ] Regression: `cargo test --workspace --all-targets`。
- [ ] Repository checks: `python3 checks/check_workflow.py --repo . --spec-dir specs/GH106`。

## 回滚方案

AGT-04 是新增的可选模式，默认不启用。回滚实现 PR 即可完全恢复现有行为，
不涉及数据迁移。已生成的 snapshot 文件在回滚后不再被读取，可安全保留或
删除。禁止以“放宽失败语义为 clean”作为回滚或降噪手段。

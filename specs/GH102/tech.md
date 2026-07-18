# Tech Spec

## Linked Issue

GH-102

## Product Spec

Link to `product.md`.

## Codebase Context

| Area | Files | Current behavior | Why relevant |
| --- | --- | --- | --- |
| 敏感来源分类 | `crates/argus-agent/src/capability/classify.rs:97` | assignment/network facts 只扫描 `executable_reference` | 混合引用的字面路径后缀丢失后无法命中敏感路径 |
| agent 配置端点 | `crates/argus-agent/src/capability/classify.rs:118` | `writes_agent_config` 只接收单个 `write_target` | `mv`/`cp` 的源端没有进入统一配置路径判定 |
| 求值器与命令字符串 | `crates/argus-agent/src/capability/classify.rs:205` | `is_exec_fact` 识别 `eval`/`iex`，但 `is_remote_shell_pipeline_fact` 只接受 exec wrapper | 求值器被 execution fact 提前分类，字符串未进已有有界解析 |
| 有界管道解析 | `crates/argus-agent/src/capability/classify.rs:251` | 一层拆分并验证网络源与 shell sink | 可复用于求值器，不需要递归解释 |
| 引用提取 | `crates/argus-agent/src/capability/syntax/reference.rs:15` | 非 Bash 字面片段被过滤；Bash 扩展只保留扩展文本 | 需要在不把纯字面文本当作执行来源的前提下保留混合来源顺序 |
| 静态值构造 | `crates/argus-agent/src/capability/syntax.rs:586` | `StaticValue` 保存 raw、resolved、executable_reference | 是 fact 与 classifier 之间的结构化边界 |
| 分类回归测试 | `crates/argus-agent/src/capability/tests.rs:311` | 已覆盖 exec wrapper 的字符串管道和关键负例 | 可扩展求值器、端点矩阵与分类负例 |
| 端到端决策测试 | `crates/argus-agent/tests/gh87_capability.rs:28` | 已覆盖凭证 provenance、配置 writer 与最终 decision | 用于证明三类 finding 最终阻断且误报边界不退化 |

## 设计方案

### 1. 统一“字符串执行器”形状

在 `Fact` 上保留解析时已知的 `ScriptLanguage`，再用结构化谓词区分两类事实：
通用 execution fact，以及首个字符串参数可由现有
`remote_shell_command_string` 检查的 string executor。exec wrapper 保持
现有跨语言行为；裸 `eval` 与 `iex` 只有在 fact 明确来自 shell command
语义时才进入同一有界路径。Python/JavaScript/TypeScript 的同名求值函数不得
被当成 shell 管道；`function` 等不执行首参 shell 字符串的构造器也不纳入。
解析仍只进行一次，不递归处理嵌套求值。

### 2. 将单个写目标改为配置敏感端点迭代

把返回单个 `Option<&StaticValue>` 的目标选择改为基于操作形状的端点检查：
`mv`/`cp` 检查去除选项后的有效源端与末端目标；其他 writer 保持 receiver、
首参或末参的现有形状。所有端点继续复用 `static_value_is_agent_config`，
避免把 payload 或选项文本当作路径。

### 3. 保留混合 assignment provenance

在 syntax 层为 `StaticValue` 生成有序、受限的 provenance 表示：只有表达式
包含可执行引用时，才把与该引用直接组成同一静态字符串的字面片段保留下来；
纯字面表达式仍没有 executable provenance。Bash 的变量扩展与相邻字面片段
按源码顺序组合；无法静态确定的动态片段保留为未解析，不猜测内容。
classifier 继续只读取 provenance 字段，不退回对全部 raw 文本做敏感匹配。
capability 聚合层同时保留 assignment/local-use 的既有 credential-access
manifest，但只有直接读取、网络参数或相连网络管道中的结构化来源可参与
secret-exfil 的网络相关性判定，避免“本地使用 + 无关联网”被错误合并。
管道 fact 保存网络 sink 之前每个 stage 的 callee/arguments 与 sink
arguments；只有 sink 具有 stdin 消费语义时才关联上游来源。stage 输出形状
有界为 `echo`/`printf` 的直接 secret 与 `cat` 的位置文件参数，禁止把
`cp`、`source` 或 grep pattern 推测为 stdout 内容。网络参数中的敏感路径
按 client 语义判定：curl 的 `@`/upload-file、受支持语言的显式 `open(path)`
可作为文件读取上下文；非 curl 的 `@path` 与普通路径文本不得被视为凭证
文件内容，`nc -z` 也不得视为 stdin 传输。

## 计划变更清单

<!-- specrail-planned-changes
{"version":1,"issue":102,"complete":true,"paths":["specs/GH102/product.md","specs/GH102/tech.md","specs/GH102/tasks.md","crates/argus-agent/src/capability.rs","crates/argus-agent/src/capability/classify.rs","crates/argus-agent/src/capability/syntax.rs","crates/argus-agent/src/capability/syntax/reference.rs","crates/argus-agent/src/capability/syntax/tests.rs","crates/argus-agent/src/capability/tests.rs","crates/argus-agent/tests/gh87_capability.rs"],"spec_refs":["specs/GH102/product.md","specs/GH102/tech.md","specs/GH102/tasks.md"]}
-->

## Product-to-Test Mapping

| Behavior invariant | Implementation area | Verification |
| --- | --- | --- |
| B-001 | `syntax.rs` language provenance + `classify.rs` string-executor predicate | `cargo test -p argus-agent gh102_eval` |
| B-002 | `remote_shell_command_string` caller boundary | `cargo test -p argus-agent gh102_eval` |
| B-003 | execution/remote-execution separation | `cargo test -p argus-agent gh102_eval` |
| B-004 | `classify.rs` config-sensitive endpoint iterator | `cargo test -p argus-agent gh102_config_endpoint` |
| B-005 | endpoint raw/resolved and negative matrix | `cargo test -p argus-agent gh102_config_endpoint` |
| B-006 | `syntax/reference.rs` mixed assignment provenance + structured pipeline/file-read context | `cargo test -p argus-agent gh102_assignment_provenance` |
| B-007 | provenance negative matrix | `cargo test -p argus-agent gh102_assignment_provenance` |
| B-008 | shared predicates and fact/static-value boundaries | `cargo test -p argus-agent capability` |
| B-009 | existing negative decision tests | `cargo test -p argus-agent --test gh87_capability` |
| B-010 | unresolved/parse-failure behavior | `cargo test -p argus-agent capability` |

## 数据流

脚本文本由 tree-sitter 生成 syntax fact；每个参数形成 `StaticValue`，其中 raw、
resolved 与受限 provenance 分离。classifier 只根据 fact kind、callee shape、
结构化参数/端点与 provenance 产生既有 capability evidence。decision 层继续
使用现有 finding/severity 规则，不新增持久化、网络调用或外部数据。

## 备选方案

- 恢复 PR #101 前的全文件 regex 扫描：会重新引入注释、文档与非执行文本误报，
  拒绝。
- 在 `is_remote_shell_pipeline_fact`、`writes_agent_config` 和
  `sensitive_read` 中逐条追加 payload 特判：无法覆盖同形输入且会继续产生
  相邻绕过，拒绝。
- 对 assignment 的全部 raw 文本做敏感匹配：会破坏纯字面凭证字段名负例，
  拒绝。

## 风险

- Security: provenance 过宽会把仅提及凭证名的文本升级为 exfil；必须以正负矩阵
  约束。
- Compatibility: `cp` 源端被定义为配置敏感操作，可能新增 finding；这是
  GH-102 明确要求的保守安全语义。
- Performance: 只遍历现有参数并做一次有界字符串拆分，复杂度保持线性。
- Maintenance: string executor 必须同时受 language provenance 与集中谓词约束，
  端点形状也必须集中定义，禁止分散 callee 特判。

## 测试计划

- [ ] Unit tests: evaluator、端点与 mixed provenance 正负矩阵。
- [ ] Integration tests: 三类输入都产生预期 finding/decision。
- [ ] Regression: `cargo test -p argus-agent`。
- [ ] Repository checks: `cargo check --workspace --all-targets`、
  `python3 checks/check_workflow.py --repo . --spec-dir specs/GH102`。

## 回滚方案

该变更不改数据格式。若出现不可接受的误报，回滚单个实现 PR 即可恢复 PR #101
行为；保留 GH102 spec 与失败测试证据，重新设计 fact/provenance 边界，禁止用
删除负例或放宽断言作为回滚手段。

# Tech Spec

## Linked Issue

GH-112

## Product Spec

Link to `product.md`.

## Codebase Context

| Area | Files | Current behavior | Why relevant |
| --- | --- | --- | --- |
| 网络调用识别 | `crates/argus-agent/src/capability/classify.rs:51` | exec wrapper 的 `Argv` 分支只取 argv token 0 作为客户端 | wrapper 包装的实际客户端丢失 |
| 有界 wrapper 解码 | `crates/argus-agent/src/capability/syntax/normalize.rs:42` | `shell_wrapper_invocation` 已处理嵌套 `sudo`/`env` 与一次性 `-S` 预算 | command-string 形态已复用，argv 形态未复用 |
| 重定向解析 | `crates/argus-agent/src/capability/syntax/bash.rs:462` | 只保留 `destination` 的 `StaticValue`，操作符被丢弃 | fd 与方向缺失，无法区分读写 |
| 重定向消费 | `crates/argus-agent/src/capability/classify.rs:319` | 任何重定向都被当作写目标 | 输入重定向被误判为配置写入 |
| curl 来源关联 | `crates/argus-agent/src/capability/classify.rs:197` | 只遍历 curl 自身 operand | fd0 进入的内容没有关联点 |
| stdin 消费语义 | `crates/argus-agent/src/capability/classify.rs:166` | `pipeline_sink_is_network` 已判定 curl/nc 的 stdin 语义 | 管道与输入重定向共享同一判据 |
| 文件读取来源 | `crates/argus-agent/src/capability/syntax/reference.rs:138` | 只有 Python `open(...)` 产生结构化来源 | 接收者式读取无来源 |
| 分类回归测试 | `crates/argus-agent/src/capability/tests/gh102.rs` | 已覆盖 wrapper、curl operand 与来源矩阵 | 新增 gh112 模块沿用同一风格 |

## 设计方案

### 1. argv 形态复用有界 wrapper 解码器

`network_invocation` 的 `ArgumentShape::Argv` 分支在取得 argv token 0 的
basename 后，若该 token 是受支持 shell wrapper，则把其余 argv 交给既有的
`shell_wrapper_invocation`，取回真实客户端与 operand。该函数已经实现嵌套
wrapper 展开、assignment token 跳过、option arity 表与一次性 split-string
预算，因此不新增解析路径，也不新增预算。argv 的 `StaticValue` 形状被原样
传递，curl 的 raw byte-boundary map 与来源属性保持可用。

### 2. 重定向升级为类型化来源

新增 `capability/syntax/redirect.rs`，定义 `Redirect { fd, direction, target }`
与 `RedirectDirection { Input, Output }`，并提供 `redirect_direction` 与
`redirect_fd`。`Fact.redirect` 由 `Option<StaticValue>` 改为
`Option<Redirect>`。

方向由重定向操作符判定：`<`、`<<`、`<<<`、`<&` 为输入，其余（含 `>`、`>>`、
`&>`、`<>` 与本解析器未建模的形态）保守归为输出，从而保留既有写入检测行为
而不是让未知形态静默退出写入面。描述符优先取操作符前缀数字，其次取
`descriptor` 字段；缺失时由方向决定隐式描述符。目标缺失时返回 `None`，
避免未建模形态伪装成已解析目标。

### 3. 输入重定向按客户端语义关联

把 `pipeline_sink_is_network` 中的 stdin 语义判定提取为
`client_consumes_stdin(client, arguments)`，管道与输入重定向共用。
`network_sensitive_match` 在遍历完 operand 后，若 fact 带有 stdin 输入重定向
且该客户端确实消费 stdin，则把重定向目标的 raw / resolved / provenance 作为
文件内容来源参与敏感匹配。非 stdin 描述符、输出方向、不消费 stdin 的客户端
（含 `nc -z`）都不参与。

`writes_agent_config` 只接受输出方向的重定向，修正“输入重定向被计为配置
写入”的既有误报。

### 4. 接收者式文件读取归一为同一来源

`reference.rs` 的 call 分支引入 `file_read_path`：参数式读取
（Python `open`、JS `readFileSync`/`readFile`）取第一个字面参数；接收者式读取
（`.read_text` / `.read_bytes`）取接收者上的字面路径，支持 `Path("…")` /
`pathlib.Path("…")` 构造器与字面接收者。两种形态都归一输出既有的
`open(<path>)` 来源表示，因此分类层的文件内容判定保持单一表示，不新增
针对样本的分支。仅字面路径被接受；动态路径返回 `None`，保持非阻断。

## 影响面

- `crates/argus-agent/src/capability/classify.rs`：argv wrapper 解码、
  stdin 语义提取、重定向关联、写入判定。
- `crates/argus-agent/src/capability/syntax.rs`：`Fact.redirect` 类型与模块声明。
- `crates/argus-agent/src/capability/syntax/redirect.rs`：新增类型与单元测试。
- `crates/argus-agent/src/capability/syntax/bash.rs`：`typed_redirect` 构造。
- `crates/argus-agent/src/capability/syntax/reference.rs`：`file_read_path`。
- `crates/argus-agent/src/capability/tests/gh112.rs`：正负矩阵。

<!-- specrail-planned-changes
{"version":1,"issue":112,"complete":true,"paths":["specs/GH112/product.md","specs/GH112/tech.md","specs/GH112/tasks.md","crates/argus-agent/src/capability/classify.rs","crates/argus-agent/src/capability/syntax.rs","crates/argus-agent/src/capability/syntax/redirect.rs","crates/argus-agent/src/capability/syntax/bash.rs","crates/argus-agent/src/capability/syntax/reference.rs","crates/argus-agent/src/capability/tests.rs","crates/argus-agent/src/capability/tests/gh112.rs"],"spec_refs":["specs/GH112/product.md","specs/GH112/tech.md","specs/GH112/tasks.md"]}
-->

## Product-to-Test Mapping

| Behavior invariant | Implementation area | Verification |
| --- | --- | --- |
| B-001 | `classify.rs` argv wrapper 解码 | `cargo test -p argus-agent gh112_exec_argv_wrapper` |
| B-002 | `shell_wrapper_invocation` 预算复用 | `cargo test -p argus-agent gh112_exec_argv_wrapper_keeps` |
| B-003 | 网络客户端判定 | `cargo test -p argus-agent gh112_exec_argv_wrapper_keeps` |
| B-004 | `syntax/redirect.rs` 方向与描述符 | `cargo test -p argus-agent redirect` |
| B-005 | `client_consumes_stdin` + 重定向关联 | `cargo test -p argus-agent gh112_stdin_redirect` |
| B-006 | `writes_agent_config` 输出方向限定 | `cargo test -p argus-agent gh112_input_redirect_is_not` |
| B-007 | `reference.rs` `file_read_path` | `cargo test -p argus-agent gh112_receiver_file_read` |
| B-008 | 接收者负例矩阵 | `cargo test -p argus-agent gh112_receiver_file_read_keeps` |
| B-009 | 共享抽象与既有负例 | `cargo test -p argus-agent capability` |
| B-010 | 未解析/解析失败行为 | `cargo test -p argus-agent capability` |

## 风险

- Security: 重定向关联过宽会把仅被读取而未发送的文件升级为 exfil；因此关联
  以客户端 stdin 语义为前置条件，并由负例矩阵约束。
- Compatibility: 输入重定向不再计为 agent 配置写入，属于修正既有误报；
  输出重定向行为不变，并有测试锁定。
- Performance: 三处改动都在既有单次遍历内完成，未新增解析轮次。
- Maintenance: 未建模的重定向操作符保守归为输出，避免新增语法时静默退出
  写入检测面。

## 测试计划

- [ ] Unit tests: `redirect.rs` 方向、描述符与 stdin 判定。
- [ ] Integration tests: 三条反例阻断，相邻良性输入非阻断。
- [ ] Regression: `cargo test -p argus-agent`。
- [ ] Repository checks: `cargo test --workspace --all-targets`、
  `python3 checks/check_workflow.py --repo . --spec-dir specs/GH112`。

## 回滚方案

该变更不改数据格式。若出现不可接受的误报，回滚本实现 PR 即可恢复 PR #105
行为；必须保留 GH112 spec 与失败证据重新设计来源边界，禁止以删除负例或
放宽断言作为回滚手段。

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
shell 的裸字面 word 只有在 AST 节点不含 expansion/substitution 且字符集合
安全时才形成静态值；`eval`/`iex` 只有全部参数均为静态值时才按顺序组合，
任一动态参数都使整条命令保持 unknown。
受支持语言的 quoted string 必须按 AST 字面量节点求值，Python/JavaScript/
TypeScript 的 `+` 拼接则递归求值左右 AST 子节点，避免把 URL 等字面内容
中的 `+` 误当作拼接操作符；不得用 raw 字符串 fallback 绕过静态值边界。

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
通过规范化 invocation 判定：shell wrapper 同时剥离 wrapper 元数据并保留
内层参数；exec wrapper 显式区分 `CommandString` 与 `Argv`，前者复用有界
首命令解析并保留 host/capability，后者的 list/tuple/array 由 AST 元素构造，
而 Bash builtin `exec` 直接形成 `Argv`；禁止在 classifier 中拆 raw 列表。
Python subprocess 按 positional/`args=` 签名选择 command，JavaScript spawn
只有 array 形状进入 argv，options metadata 不得混入。结构化 shell wrapper
与 command-string wrapper 共用按 wrapper 分表的 assignment、flag 与
option-value arity 解码；API canonical callee 保留原拼写，但 wrapper
shape 匹配统一使用去除 `node:` 前缀的 lowercase key，覆盖
`Popen`/`spawnSync`/`execSync`。`env -S`/`--split-string` 的静态 operand
是命令承载字段，由共享、引号感知的一次有界 token 解析取得内层命令；
carrier 可位于 assignment、flag 或带值选项元数据之后；不递归解释第二层
command string，动态、缺失 operand 或未闭合引号不得猜测。嵌套
`sudo`/`env` 由同一 target 状态解码器逐层展开；`--` 终止当前 wrapper
的选项语义，其后的 `-S` 只能作为直接 command，不得重新解释为 carrier。
`sudo` 与 `env` 的前置 assignment 均作为元数据跳过；split carrier 产出
`command + owned arguments`，保留内层 file/stdin operand 与外层剩余参数，
且 structured 与 command-string 分类路径消费同一 bounded invocation 与
一次性 split budget。wrapper identity 使用 lowercase basename，支持绝对
路径与嵌套路径；assignment 必须满足标识符语法，`./tool=prod` 仍是 command。
tokenizer 保留空 quoted operand，避免删除空参数后改变 curl option 邻接关系。
显式空 token 若位于 command discovery 位置则直接 fail-closed；`--` 只
终止 option/carrier 语义，后续合法 assignment 仍作为 env 元数据跳过。
非 wrapper 的 leading dash token 是实际 command，不能作为 option 跳过。
remote-shell pipeline 在切段前使用共享的引号/转义感知 scanner；单引号内
反斜杠保持字面量，双引号只处理 shell 允许的有限转义字符。未引用的
command-list 操作符或 token 边界 comment 超出单 pipeline 边界，直接
fail-closed，禁止把独立网络命令与后续/注释中的 shell sink 相关联。
scanner 按完整 operator 区分 `|`/`|&` 管道、`>&`/`&>` fd 重定向及
`>|` noclobber 重定向。command-string 中未引用的 `$()`/backtick
substitution 超出一次非递归边界，直接 fail-closed；direct AST pipeline
由 syntax 层使用 Tree-sitter 的 expansion/substitution/process-substitution
精确 byte spans 生成独立 `pipeline_scan_text`，将这些 span 替换为 opaque
argument 并保留原始 `text`；opaque token 的词法形状不能成为
io-number、shell identifier 或 operator。scanner 不再解析 substitution 内部 Bash
语法，只统一计算外层 operator、fd route 与 edge，
禁止回退到丢失重定向语义的 stage-only 判断。未引用及双引号内的反斜杠
换行按 shell line-continuation 语义删除，避免把真实 client 拆成错误
token。shell blank/token/comment boundary 仅接受 Bash 的 ASCII space/tab，
newline/CR 单独拒绝；Unicode whitespace 保持普通 word 字符。comment
word-boundary 包含重定向 operator；scanner 用 operator/operand 与 io-number 状态验证每个
segment，dangling `<`/`>`/`<&`/`>&`/`>|` 均 fail-closed。按顺序维护任意
宽度 fd 的 `IncomingPipe`/`OutgoingPipe`/`Other` 路由，支持 `<>` 与
`n>&m`/`n<&m` 的复制、self-dup 和恢复；每条相邻 pipeline edge 都必须保持
左侧 fd1→OutgoingPipe 与右侧 fd0→IncomingPipe。`2>&1 | sh` 等未切断
edge 的管道仍保留。io-number 必须与 operator 紧邻，去除前导零后作为同一
fd key；`{var}` 仅接受严格 shell identifier；dup operand 必须在数字或
move `-` 后结束 word。dup 前的水平空白与 line-continuation 可按 shell
tokenization 任意交错，source-fd 数字及 move suffix 可跨合法
line-continuation；literal newline/CR 不能完成 operand，紧邻 `#` 不是
comment boundary。分类在任意连续 edge 区间寻找 network→shell；direct
AST pipeline 的 command/redirected-statement stage 统一抽取，支持
tabs、绝对 sink、`|&` 与 pipeline 外层 redirection，同时 remote-shell
判断仍只消费上述共享 scanner 的 edge 结果。
curl argv 只遍历一次，并按 option arity 消费 separate operand；被前一
option 消费的 option-like token 不得再次解释。arity 来自 curl 8.7.1
generated-help 的完整 value-option schema（含 proxy/preproxy/proxy1.0）；
short option cluster 逐项解码，遇到
data/form/upload 或其他带值 option 后由余下 token/下一 argv 提供 operand。
decoder 再按选项族生成可组合的 File/Stdin 来源标志：
data/data-ascii/data-binary/json 只接受前导 `@`，data-urlencode 只接受
`@file` 与不含 `=` 的 `name@file`。form 按 curl 8.7.1 parser 语义切分
第一个 `name=`（允许空 name）：`@` 使用逗号 source list 且每个 source
携带自身属性，`<` 只接受单 source；word 只识别双引号及其中的 `\\`/`\"`
转义。`headers=@file` 与 `headers=<file` 作为额外文件来源，
`type`/`filename` 等其他属性保持 metadata。decoder 保存真实 file-source
字符串与独立 stdin 标志；classifier 只扫描这些 source，不得因同 token
存在安全文件而扫描 `filename=` 等 metadata。普通 data/urlencode/upload
路径不得套用 form word 解码，其中的字面引号属于文件名本身，不能被剥除后
误判为 stdin 或规范敏感路径。form word 仅在首个非空白字符为双引号时进入
quoted 模式，未闭合引号按 curl 8.7.1 `get_param_word` 回退为 unquoted
扫描。动态 source 只关联 syntax 层中与该 curl file-source byte span
直接相交的 argument-relative raw-reference→canonical-reference fragment，
禁止 substring identity 或 argument 级聚合 provenance。upload-file 保持
path/`-` 语义。
`--data-raw` 与 `--form-string` 明确不具备文件读取语义。受支持语言的显式
`open(path)` 可作为文件读取上下文；非 curl 的 `@path` 与普通路径文本不得
被视为凭证文件内容，`nc -z` 也不得视为 stdin 传输。
direct Bash argv 必须另存 shell-normalized text 与 argument-relative raw
byte-boundary map：去除 quote syntax，并按
`\\$`/``\\` ``/`\\\"`/`\\\\`/反斜杠换行规则处理转义，再进入 curl form
grammar；即使同一 word 含未解析变量也不得丢失已知词法结构。curl 解析出的
source span 经 boundary map 映回 raw 后，仍只与真实 expansion fragment
相交；单引号或 `\\$` 抑制的 `$` 来源不参与直接敏感扫描。command/process/
arithmetic substitution 保持 dynamic，不得从 substitution 文本猜文件来源。
assignment constants 同时保留可传递的 suppressed-origin，禁止直接、别名链或
混合常量展开后的 `$NAME` 再激活单引号或 escaped-dollar 内容；精确 source
constant 若为 `-`，则仅在该 curl option/source 允许 stdin 时提升 stdin
标志。ANSI-C `$'…'` argv 按 Bash escape/octal/hex/Unicode/control 语义解码
并生成同类 boundary map，且 word 前缀、后缀及相邻 ANSI-C 片段均参与组合；
locale-translated `$"…"` 在 standalone 或 word 拼接位置都保持 dynamic。

## 计划变更清单

<!-- specrail-planned-changes
{"version":1,"issue":102,"complete":true,"paths":["specs/GH102/product.md","specs/GH102/tech.md","specs/GH102/tasks.md","crates/argus-agent/src/capability.rs","crates/argus-agent/src/capability/classify.rs","crates/argus-agent/src/capability/classify/curl.rs","crates/argus-agent/src/capability/syntax.rs","crates/argus-agent/src/capability/syntax/bash.rs","crates/argus-agent/src/capability/syntax/normalize.rs","crates/argus-agent/src/capability/syntax/shell.rs","crates/argus-agent/src/capability/syntax/reference.rs","crates/argus-agent/src/capability/syntax/tests.rs","crates/argus-agent/src/capability/tests.rs","crates/argus-agent/src/capability/tests/gh102.rs","crates/argus-agent/src/capability/tests/gh102_curl.rs","crates/argus-agent/tests/gh87_capability.rs"],"spec_refs":["specs/GH102/product.md","specs/GH102/tech.md","specs/GH102/tasks.md"]}
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

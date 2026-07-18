# Task Plan

## Linked Issue

GH-102

## Spec Packet

- Product: `product.md`
- Tech: `tech.md`

## 实现任务

- [x] `SP102-T1` 在 `Fact` 上保留 `ScriptLanguage`，统一 exec wrapper 与 shell command 语义下 `eval`/`iex` 的有序静态参数字符串执行形状；安全裸字面 word 与已解析引用共用 syntax 静态值边界，并复用一次有界管道解析。Covers: B-001, B-002, B-003, B-008, B-010. Owner: implementation worker. Dependencies: none. Done when: shell 求值器单参、多参及裸 word 正例产生现有 remote-execution finding，Python/JavaScript/TypeScript 同名求值函数及任一参数动态、良性、嵌套负例不升级。Verify: `cargo test -p argus-agent gh102_eval`.
- [x] `SP102-T2` 将配置写入的单目标选择收敛为按命令形状选择配置敏感端点，覆盖 `mv`/`cp` 的有效源端和目标端，并排除选项/payload。Covers: B-004, B-005, B-008, B-009. Owner: implementation worker. Dependencies: none. Done when: source/destination、raw/resolved 与非敏感矩阵全部通过。Verify: `cargo test -p argus-agent gh102_config_endpoint`.
- [x] `SP102-T3` 在 syntax/static-value 边界保留“可执行引用 + 相邻字面片段”的有序 assignment provenance，显式区分 exec wrapper 的 `CommandString` 与 signature/case-aware AST-derived `Argv`，并用统一 invocation 形状保存全部上游 stage、按 wrapper-specific option-arity 解码剥离 shell wrapper 元数据及表达 sink 输入语义；capability 聚合层按 client/stage shape 与集中 curl operand decoder 区分文件内容、stdin、直接 secret 和仅需保留 manifest 的本地引用，纯字面与动态片段不得被猜测。Covers: B-006, B-007, B-008, B-010. Owner: implementation worker. Dependencies: none. Done when: curl attached/separate 文件选项、Bash `exec`/跨语言 exec argv、`Popen`/`spawnSync`/`execSync` 与 alias（含 `node:` 模块前缀）、Python reordered `args=`、普通 exec command-string 与 sudo/env separated option values/valid assignments、绝对路径/嵌套 `sudo`/`env`、前置 metadata 后 `env -S`/`--split-string` 静态命令与内层 argv 的 network host/capability/file/stdin provenance、显式 `open(path)` 与真正消费 stdin 的多段管道可还原来源，assignment-only credential-access 仍可见；非 curl `@path`、JavaScript spawn options metadata、空 quoted operand、wrapper option metadata、`--` 后 `-S`、双层 split carrier、`env -S` 良性/动态/缺失/未闭合命令、非 assignment 的 `=` command、`--form-string`、`nc -z`、非输出 stage、普通路径文本、纯字面以及“本地使用 + 无关联网”负例保持非阻断。Verify: `cargo test -p argus-agent gh102_assignment_provenance`.
- [x] `SP102-T4` 增加端到端 decision 回归并运行完整验证。Covers: B-001, B-003, B-004, B-005, B-006, B-007, B-009, B-010. Owner: verification owner. Dependencies: SP102-T1, SP102-T2, SP102-T3. Done when: 三个原始 P1 场景阻断、关键负例不阻断，工作流检查与完整 crate 测试通过。Verify: `cargo test -p argus-agent --test gh87_capability && cargo test -p argus-agent && cargo check --workspace --all-targets && python3 checks/check_workflow.py --repo . --spec-dir specs/GH102`.

## 并行拆分

- SP102-T1 拥有 `crates/argus-agent/src/capability/syntax.rs` 与
  `syntax/bash.rs` 中的 Fact/language/pipeline provenance、对应 syntax tests，以及
  `crates/argus-agent/src/capability/classify.rs` 中的 string-executor 区域
  与 evaluator tests。
- SP102-T2 也修改 `classify.rs`，与 SP102-T1 文件重叠，因此必须串行提交，
  不得与 SP102-T1 并行写。
- SP102-T3 拥有 syntax provenance 文件与 syntax tests，可在独立 worktree
  中研究；其 capability 聚合相关性改动由同一实现 owner 串行修改
  `crates/argus-agent/src/capability.rs`，最终集成依赖 SP102-T1/T2 的稳定 head。
- SP102-T4 为串行 verification owner，不与任何写入任务并发运行 Cargo。

## 验证

Product invariant 集合
`{B-001,B-002,B-003,B-004,B-005,B-006,B-007,B-008,B-009,B-010}` 必须与任务
`Covers:` 并集一致。运行
`python3 checks/check_workflow.py --repo . --spec-dir specs/GH102`、
`cargo test -p argus-agent` 和 `cargo check --workspace --all-targets`。独立
reviewer lane 另行检查 spec 密度、路径锚点、完整映射与禁止特判约束。

## Handoff Notes

- 这是 security/heavy 项；spec PR 合并并把 issue 路由为
  `ready_to_implement` 后，才创建独立 implementation PR。
- `cp` 源端按 GH-102 明确要求视为配置敏感操作；若维护者要区分“读取”与
  “写入”，必须先修订 B-004，而不是在实现中静默改变范围。
- 实现不得退回全文件 regex，也不得放宽
  `ignores_literal_credential_names_and_non_executed_client_tokens` 等负例。

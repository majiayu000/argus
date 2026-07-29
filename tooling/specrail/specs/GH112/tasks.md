# Task Plan

## Linked Issue

GH-112

## Spec Packet

- Product: `product.md`
- Tech: `tech.md`

## 实现任务

- [x] `SP112-T1` 让 exec 调用的 argv 形态在 argv token 0 为受支持 shell wrapper 时复用既有有界 `shell_wrapper_invocation` 解码器，还原真实客户端与 operand 并保持 argv 的 StaticValue 形状。Covers: B-001, B-002, B-003, B-009. Owner: implementation worker. Dependencies: none. Done when: `env -S` / `--split-string` / `sudo` / 绝对路径 wrapper / wrapper 前置 assignment / 嵌套 `sudo env -S` 的 argv 正例阻断，且第二层 split-string、动态命令、非网络客户端、非文件 operand 负例保持非阻断。Verify: `cargo test -p argus-agent gh112_exec_argv_wrapper`.
- [x] `SP112-T2` 将 `Fact.redirect` 升级为类型化 `Redirect { fd, direction, target }`，未建模操作符保守归为输出；把 stdin 消费语义提取为 `client_consumes_stdin` 供管道与输入重定向共用，并让 `writes_agent_config` 只接受输出方向。Covers: B-004, B-005, B-006, B-009, B-010. Owner: implementation worker. Dependencies: none. Done when: `curl --data-binary @- … < creds`、显式 `0<`、`curl -T -`、`nc` 正例阻断；命名 operand、无 stdin 语义、`3<`、`nc -z` 负例非阻断；输入重定向不再产生 agent-config-write，输出重定向仍产生。Verify: `cargo test -p argus-agent gh112_stdin_redirect && cargo test -p argus-agent gh112_input_redirect_is_not && cargo test -p argus-agent redirect`.
- [x] `SP112-T3` 在 `reference.rs` 引入 `file_read_path`，把参数式读取与接收者式读取归一为既有 `open(<path>)` 结构化来源，仅接受字面路径。Covers: B-007, B-008, B-009. Owner: implementation worker. Dependencies: none. Done when: `Path(...).read_text()` / `read_bytes()` / `pathlib.Path` / `fs.readFileSync` 作为网络参数时阻断；动态接收者路径、非读取方法、仅路径字面值负例保持非阻断。Verify: `cargo test -p argus-agent gh112_receiver_file_read`.
- [x] `SP112-T4` 运行完整验证并锁定既有负例不退化。Covers: B-001, B-004, B-007, B-009, B-010. Owner: verification owner. Dependencies: SP112-T1, SP112-T2, SP112-T3. Done when: 三条 issue 反例阻断、既有 gh102/gh87 负例全部保持，工作区测试与工作流检查通过。Verify: `cargo test --workspace --all-targets && cargo fmt --all -- --check && cargo clippy --workspace --all-targets && python3 checks/check_workflow.py --repo . --spec-dir specs/GH112`.

## 并行拆分

- SP112-T1 与 SP112-T2 都修改 `crates/argus-agent/src/capability/classify.rs`，
  文件重叠，必须串行提交，不得并行写。
- SP112-T2 另外拥有 `capability/syntax.rs`、`syntax/redirect.rs` 与
  `syntax/bash.rs`；SP112-T3 拥有 `syntax/reference.rs`，二者文件不重叠，
  但仍与 T1/T2 共享 crate 构建，不并发运行 Cargo。
- SP112-T4 为串行 verification owner，不与任何写入任务并发运行 Cargo。

## 验证

Product invariant 集合
`{B-001,B-002,B-003,B-004,B-005,B-006,B-007,B-008,B-009,B-010}` 必须与任务
`Covers:` 并集一致。运行
`python3 checks/check_workflow.py --repo . --spec-dir specs/GH112`、
`cargo test --workspace --all-targets` 与 `cargo clippy --workspace --all-targets`。

## Handoff Notes

- 三条绕过面均来自 PR #105 合并后的连接器 P1 回报，不得用样本特判或裸
  substring 兜底关闭。
- `Fact.redirect` 的类型变更同时修正了“输入重定向被计为 agent 配置写入”的
  既有误报；若维护者认为该误报应保留为保守行为，必须先修订 B-006，而不是
  在实现中静默恢复。
- 未建模的重定向操作符保守归为输出方向，确保新增语法不会静默退出写入
  检测面。

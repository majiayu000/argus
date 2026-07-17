# Tasks — GH-86 文档能力快照校准

- [x] `SP86-T1` 完成八生态能力矩阵。Owner: docs。Dependencies: none。
  Done when: 每行包含 CLI、完整性来源、制品/检查面和限制。
  Verify: 对照 `crates/argus-cli/src/main.rs` 与 PR #49–#53。
  Covers: B-001, B-002, B-009。
- [x] `SP86-T2` 补全 README Usage、Layout、Status、headline 和 stack table。
  Owner: docs。Dependencies: SP86-T1。Done when: 五处公开描述一致、八个命令
  可发现、#22 改为历史并链接 #49–#53、pre-release 状态保留。
  Verify: `cargo run -q -p argus-cli -- --help` 与定向 `rg`。
  Covers: B-001, B-003, B-004, B-005。
- [x] `SP86-T3` 校准攻击目录。Owner: docs/security claims。Dependencies: none。
  Done when: PyPI/crates.io/crypto 过期 gap 被修正，真实事件只按现有证据给 verdict，
  汇总计数与逐行一致。Verify: 定向 `rg`、源码/fixture 对照与人工计数。
  Covers: B-006, B-007, B-008, B-009。
- [x] `SP86-T4` 执行确定性验证并记录证据。Owner: coordinator。
  Dependencies: SP86-T1, SP86-T2, SP86-T3。Done when: diff hygiene、workspace
  check/test、corpus test、CLI help 与文档定向检查全部通过。
  Verify: `git diff --check origin/main...HEAD`; `cargo check --workspace --all-targets`;
  `cargo test --workspace --all-targets`; `cargo run -q -p argus-cli -- corpus test --corpus corpus`。
  Covers: B-001, B-005, B-006, B-008, B-010。

## Invariant Coverage

Product IDs: B-001, B-002, B-003, B-004, B-005, B-006, B-007, B-008, B-009, B-010.

Task coverage union: B-001, B-002, B-003, B-004, B-005, B-006, B-007, B-008, B-009, B-010.

## Handoff Notes

- 这是 mixed implementation PR 中的 spec packet；实现仍只允许修改 manifest 所列路径。
- “支持生态”只表示对应 fetch/scan path 已在 `main`，不表示已正式发布或能检测
  该生态的全部恶意载荷。
- 弱摘要、缺失摘要、未检查 bytecode/动态代码/签名的情况必须保持显式。
- Fresh verification：`cargo fmt --all -- --check`、`cargo check --workspace --all-targets`、
  `cargo clippy --workspace --all-targets -- -D warnings`、
  `cargo test --workspace --all-targets -- --test-threads=1`、corpus `18/18`、CLI help 均通过。
- 默认并行 workspace test 在基线的 `argus-fetch` 本地 redirect server 测试中可随机
  命中 100ms read timeout（`os error 35`）；失败用例单独重跑与串行全套均通过，
  本 docs-only issue 不修改该测试夹具。

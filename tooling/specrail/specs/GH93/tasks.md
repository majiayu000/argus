# Tasks — GH-93 SARIF 2.1 output

- [x] `SP93-T1` 实现独立 SARIF renderer、稳定 descriptors、locations、properties 与 fingerprints。Covers: B-002, B-003, B-004, B-005, B-006, B-007, B-008。Owner: cli renderer。Dependencies: none。Done when: package/lockfile/agent/provenance reports 可确定性转换且无假行号。Verify: `cargo test -p argus-cli sarif`。
- [x] `SP93-T2` 将 `sarif` 接入所有 scan/fetch/agent 输出并保持 corpus eval 边界。Covers: B-001, B-004, B-010。Owner: cli orchestration。Dependencies: SP93-T1。Done when: help 显示 scan formats，agent 多报告合并，error stdout 为空，decision exit code 不变。Verify: `cargo test -p argus-cli --test sarif_cli` 与 CLI smoke。
- [x] `SP93-T3` 增加离线 snapshots 与 operational-error integration tests。Covers: B-003, B-005, B-007, B-008, B-009, B-010。Owner: cli tests。Dependencies: SP93-T1, SP93-T2。Done when: 四类 snapshot、同位置多 rule、无行号、空 report 和错误路径均有断言。Verify: `cargo test -p argus-cli`。
- [x] `SP93-T4` 增加 CI clean SARIF 生成与官方 upload smoke。Covers: B-011。Owner: CI。Dependencies: SP93-T2。Done when: unit tests 离线且 same-repo CI 用 `github/codeql-action/upload-sarif@v4` 上传无 finding SARIF，fork 只跳过网络 upload。Verify: workflow-check 与 GitHub CI。
- [x] `SP93-T5` 文档化本地生成、GitHub upload、generic consumer 和 error 边界。Covers: B-012。Owner: docs。Dependencies: SP93-T2, SP93-T4。Done when: README 包含可复制命令、permissions/action snippet 与 operational-error 声明。Verify: 定向 `rg` 与人工阅读。
- [x] `SP93-T6` 运行完整确定性验证。Covers: B-001, B-002, B-009, B-010, B-011。Owner: coordinator。Dependencies: SP93-T1, SP93-T2, SP93-T3, SP93-T4, SP93-T5。Done when: workflow、fmt、check、clippy、workspace tests、corpus 与 SARIF smoke 全部通过。Verify: `python3 checks/check_workflow.py --repo . --all-specs`; `cargo fmt --all -- --check`; `cargo check --workspace --all-targets`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace --all-targets`; corpus command。

## Invariant Coverage

Product IDs: B-001, B-002, B-003, B-004, B-005, B-006, B-007, B-008, B-009, B-010, B-011, B-012.

Task coverage union: B-001, B-002, B-003, B-004, B-005, B-006, B-007, B-008, B-009, B-010, B-011, B-012.

## Handoff Notes

- stable machine IDs、SARIF keys、paths 和 commands 保持英文；用户文档可中英混合。
- upload smoke 使用 clean fixture，避免把故意恶意 corpus finding 写入 Code Scanning alerts。
- renderer 只消费已完成 `ScanReport`；不得捕获 error 并生成空 run。

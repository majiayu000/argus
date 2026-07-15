# Tasks — GH-57 argus-agent MVP

- [x] `SP57-T1` 增加 `argus-core::ArtifactKind::AgentSurface`。Owner: core crate。Done when: 新变体可被扫描报告使用。Verify: `cargo test -p argus-core`。
- [x] `SP57-T2` 新增 `argus-agent` surface 分类器与文件收集。Owner: agent crate。Done when: agent surface 可分类和收集。Verify: `cargo test -p argus-agent surface`。
- [x] `SP57-T3` 实现 AGT-01 injection patterns 与 MCP description 提取。Owner: agent crate。Done when: 中英文正负例通过。Verify: `cargo test -p argus-agent injection`。
- [x] `SP57-T4` 实现 AGT-03 remote-exec 与 secret/egress 共现检测。Owner: agent crate。Done when: 高危组合触发且单独 secret 不触发。Verify: `cargo test -p argus-agent capability`。
- [x] `SP57-T5` 实现 AGT-05 结构化配置检查。Owner: agent crate。Done when: serde_json 正负例通过。Verify: `cargo test -p argus-agent config`。
- [x] `SP57-T6` 接入 decision 与 `scan_agent_surface`。Owner: agent crate。Done when: 扫描入口返回稳定 decision。Verify: `cargo test -p argus-agent`。
- [x] `SP57-T7` 增加六组 fixtures 与 integration tests。Owner: agent tests。Done when: 每条规则有恶意和良性断言。Verify: `cargo test -p argus-agent --test integration`。
- [x] `SP57-T8` 增加 CLI `argus agent scan`。Owner: CLI crate。Done when: 子命令可扫描 fixture。Verify: `cargo run -p argus-cli -- agent scan crates/argus-agent/tests/fixtures/agt01-malicious-skill`。
- [x] `SP57-T9` 更新 README 用法与 CHANGELOG。Owner: docs。Done when: 用户可找到 agent scan 用法。Verify: 人工阅读 README 与 CHANGELOG。
- [x] `SP57-T10` 运行 workspace 验证。Owner: verification_owner。Done when: workspace 测试零失败。Verify: `cargo test --workspace --all-targets`。

后续（另开 issue）：AGT-02 哈希基线、AGT-04 安装期 diff、registry 批量扫描。

# Tasks — GH-57 argus-agent MVP

| # | Task | Verify | Status |
| --- | --- | --- | --- |
| 1 | `argus-core`: `ArtifactKind::AgentSurface` 变体 | `cargo test -p argus-core` | done |
| 2 | 新 crate `argus-agent`：surface 分类器 + 文件收集 | `cargo test -p argus-agent surface` | done |
| 3 | AGT-01 injection.rs（中英 pattern 表 + MCP description 提取） | 单测正负例 | done |
| 4 | AGT-03 capability.rs（remote-exec + secret/egress 共现） | 单测正负例，含单独 secret 不触发 | done |
| 5 | AGT-05 config.rs（serde_json 结构化检查） | 单测正负例 | done |
| 6 | decision.rs + `scan_agent_surface` 入口 | `cargo test -p argus-agent` | done |
| 7 | fixtures ×6 + integration.rs | `cargo test -p argus-agent --test integration` | done |
| 8 | CLI `argus agent scan` 子命令 | 手动 `argus agent scan tests/fixtures/...` | done |
| 9 | README 用法段落 + CHANGELOG | 阅读 | done |
| 10 | 全 workspace 验证 | `cargo test` 退出码 0 | done |

后续（另开 issue）：AGT-02 哈希基线、AGT-04 安装期 diff、registry 批量扫描。

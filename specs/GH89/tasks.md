# Task Plan

## Linked Issue

GH-89

## Spec Packet

- Product: `product.md`
- Tech: `tech.md`

## 实现任务

- [ ] `SP89-T1` 扩展 full packument 模型并实现 `NpmAnomalyPolicy::V1` 的稳定 SemVer/time 规范化、可评估性分类和版本形状检测。Covers: B-001, B-002, B-003, B-004. Owner: implementation worker. Dependencies: none. Done when: 6 个历史版本/30 天、72 小时、major/minor 跳变、最近 5 次转换以及 prerelease/backport/乱序/同时间边界均由离线 fixture 冻结，合法历史不足产生 Info unassessed。Verify: `cargo test -p argus-fetch anomaly_insufficient`; `cargo test -p argus-fetch anomaly_ordering`; `cargo test -p argus-fetch version_shape_matrix`; `cargo test -p argus-fetch version_shape_evidence`.
- [ ] `SP89-T2` 在同一 registry base 上实现一页 npm search 候选读取、精确 `_npmUser.name`/`publisher.username` 关联、24 小时/5 包检测，以及 250 对象、2 MiB、同源/base-path、15 分钟缓存和闭集错误语义。Covers: B-005, B-006, B-008, B-009. Owner: implementation worker. Dependencies: SP89-T1. Done when: mock transport 的正负、重复/乱序、候选不足 unassessed、截断/schema/cache/redirect/transport 失败矩阵全部通过，完整 registry base URL cache key 区分同 origin 的不同 base path，单次 scan 每个 publisher 不超过一次请求。Verify: `cargo test -p argus-fetch rapid_publish_window`; `cargo test -p argus-fetch rapid_publish_benign`; `cargo test -p argus-fetch anomaly_transport`.
- [ ] `SP89-T3` 将显式 metadata anomaly 开关与可选 cache 目录接入 `FetchOptions` 和 CLI，在共享 decision 模块增加闭集 approval-only/info-only 规则并按 residual-block 优先级派生，同时保持 text/JSON/SARIF 审计字段稳定。Covers: B-007, B-008, B-010. Owner: implementation worker. Dependencies: SP89-T1, SP89-T2. Done when: 默认路径无附加请求，两个 anomaly 单独/组合/native-build 组合仅要求审批，两个 unassessed 不改变 allow，任一既有 blocking rule 与 anomaly 组合仍 block，operational error 在 report 输出前返回。Verify: `cargo test -p argus-rules anomaly_decision`; `cargo test -p argus-cli --test npm_anomaly_cli`.
- [ ] `SP89-T4` 更新 README 与攻击目录，记录两个 anomaly rule、两个 unassessed rule、`npm-anomaly-v1` 数值边界及 npm search 仅提供候选最新版本的限制。Covers: B-004, B-005, B-006, B-010. Owner: documentation owner. Dependencies: SP89-T1, SP89-T2, SP89-T3. Done when: `docs/supply-chain-attacks.md` 可追踪到实现 rule ID 与限制，README 的开关/缓存/错误行为与 CLI 一致。Verify: `rg -n "version-shape-anomaly|rapid-publish-window|unassessed|npm-anomaly-v1" README.md docs/supply-chain-attacks.md`.

## 并行拆分

- SP89-T1 与 SP89-T2 都会修改 `crates/argus-fetch/src/anomaly.rs` 及同一测试目标，
  必须串行，不得由不同 writable lane 并发修改。
- SP89-T3 在 SP89-T1/T2 稳定后拥有 `crates/argus-fetch/src/lib.rs`、
  `crates/argus-rules/src/decision.rs`、`crates/argus-cli/src/main.rs` 与 CLI
  integration tests。
- SP89-T4 可在 SP89-T3 的 rule ID/参数名冻结后由 documentation lane 执行；
  不得提前猜测 CLI 名称。
- verification owner 在所有写入停止后串行运行 workspace gates。

## 验证

- [ ] `SP89-T5` 运行 targeted、workspace、SpecRail、corpus 和覆盖率门禁。Covers: B-001, B-002, B-003, B-004, B-005, B-006, B-007, B-008, B-009, B-010. Owner: verification owner. Dependencies: SP89-T1, SP89-T2, SP89-T3, SP89-T4. Done when: 所有新旧测试通过，新代码行覆盖率至少 80%，错误负例未被放宽，fresh 输出绑定最终 head。Verify: `python3 checks/check_workflow.py --repo . --all-specs`; `cargo fmt --all -- --check`; `cargo check --workspace --all-targets`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace --all-targets`; `cargo run --quiet -p argus-cli -- corpus test --corpus corpus`; `cargo llvm-cov -p argus-fetch --summary-only`.

Product invariant 集合
`{B-001,B-002,B-003,B-004,B-005,B-006,B-007,B-008,B-009,B-010}` 与上述任务
`Covers:` 并集一致。

## Handoff Notes

- #107 是 spec/task PR；合并前不得启动代码实现。合并后重新采集 duplicate-work
  证据并运行 implement route gate，再创建独立 implementation PR。
- 当前 duplicate gate 会把引用 GH-89 的 #107 本身识别为重复工作；这是 gate
  缺少 current-spec-PR 身份的闭环缺陷，不能据此跳过 #107 合并后的 fresh gate。
- npm 官方 search API 只承诺全文 `text` 候选与响应字段，不承诺 publisher
  完整性；候选不足必须保持 Info unassessed，禁止静默输出 clean。
- 实现不得扩大到实时 registry 监控、第三方情报 feed 或默认联网。

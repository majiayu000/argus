# Product Spec

## Linked Issue

GH-80

## 用户问题

Argus 已经用 `specs/GH*/` 记录产品、技术与任务计划，但仓库没有与这些
spec 配套的确定性 SpecRail workflow pack。结果是 agent 可以看到 CI 和
GitHub review 状态，却无法在仓库内重放 `pr_gate` 与 runtime ledger gate，
也不能证明“merge-ready”结论来自同一套版本化规则。

## 目标

- 在 Argus 仓库内采用来源固定、可验证的 SpecRail workflow pack。
- 让 workflow、route、PR、review 与 runtime checkpoint gate 可离线重放。
- 保留 Argus 自有文档、Rust CI、spec packet 和产品代码。

## 非目标

- 不安装或覆盖用户全局 Codex skills。
- 不修改 Argus 产品运行时行为。
- 不让 gate 自动批准、自动发布或绕过 maintainer 权限。
- 不用 SpecRail 的 README、LICENSE 或 CHANGELOG 覆盖 Argus 对应文件。

## Behavior Invariants

1. B-001 仓库必须包含一套自洽的 SpecRail 配置、checks、schemas、templates、
   skills、tools、review/policies 与 fixture 资产；任何必要资产缺失时 workflow
   check 必须失败，不能降级成成功。
2. B-002 采用过程必须保留 Argus 的 `README.md`、`LICENSE`、`CHANGELOG.md`、
   现有 `docs/`、`specs/` 与 Rust CI；新增 pack 资产不得覆盖同名消费者文件。
3. B-003 `check_workflow.py` 必须同时验证 pack 本身和所有现有 GH spec packet；
   无效 packet、缺失配置或 schema/template 不一致必须返回非零状态。
4. B-004 `github_pr_evidence.py` 必须只读采集同仓库 PR 的当前 head、CI、
   review threads、merge state 与 linked-work 证据，不得写 issue、PR、review
   或 branch。
5. B-005 `pr_gate.py` 必须离线评估 evidence；当前 head、linked work、CI、
   review source、review threads、merge state 或授权证据缺失/陈旧时不得返回
   `allowed`。
6. B-006 `runtime_ledger_gate.py` 必须验证 queue checkpoint 的 tranche budget、
   spec coverage、PR gate evidence、reviewer lane 失败与 self-review 授权；声明
   merge-ready/merged 但证据不完整时必须阻断。
7. B-007 仓库必须新增独立 workflow-check CI，且不得删除、替换或弱化现有
   Rust `ci` workflow。
8. B-008 采用来源必须记录为固定 SpecRail commit；重复采用同一版本必须
   幂等，后续更新必须能通过 git diff 审计来源变化。

## 验收标准

- [ ] `python3 checks/check_workflow.py --repo .` 成功。
- [ ] `python3 checks/check_workflow.py --repo . --all-specs` 成功。
- [ ] `python3 -m pytest -q` 成功。
- [ ] 当前 Argus PR 可以生成 JSON evidence 并运行 `checks/pr_gate.py`。
- [ ] runtime checkpoint 可以运行 `checks/runtime_ledger_gate.py`。
- [ ] GitHub Actions 同时保留 Rust CI 与新增 workflow check。

## 边界情况清单

| 类别 | 判定（covered: B-xxx / N/A + 原因） |
| --- | --- |
| 空/缺失输入 | covered: B-001, B-003, B-005, B-006 |
| 错误与失败路径 | covered: B-001, B-003, B-005, B-006 |
| 授权/权限 | covered: B-004, B-005, B-006 |
| 并发/竞态 | N/A：本变更提供离线 gate；远端竞态由 current head/evidence freshness 契约 B-004/B-005 处理 |
| 重试/幂等 | covered: B-008 |
| 非法状态转换 | covered: B-005, B-006 |
| 兼容/迁移 | covered: B-002, B-007, B-008 |
| 降级/回退 | covered: B-001, B-003, B-005, B-006 |
| 证据与审计完整性 | covered: B-004, B-005, B-006, B-008 |
| 取消/中断 | covered: B-002, B-008；复制中断由 git worktree diff 暴露，不得提交部分 pack |

## 发布说明

这是仓库开发流程资产变更，不改变 Argus CLI 或库 API。回滚时可整体撤销
GH-80 引入的 pack 文件与 workflow-check CI，Argus 产品代码和既有 spec 保持不变。

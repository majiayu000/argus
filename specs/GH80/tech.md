# Tech Spec

## Linked Issue

GH-80

## Product Spec

见 `product.md`。

## Codebase Context

| Area | Files | Current behavior | Why relevant |
| --- | --- | --- | --- |
| 现有 CI | `.github/workflows/ci.yml:1` | 只运行 Rust fmt/clippy/test/corpus | 必须保留，并新增独立 workflow check |
| 现有 spec | `specs/GH59/product.md:1`、`specs/GH59/tech.md:1`、`specs/GH59/tasks.md:1` | 已有 SpecRail 风格 packet，但没有仓库级 evaluator | `--all-specs` 必须兼容这些 packet |
| 消费者文档 | `README.md:1`、`CHANGELOG.md:1`、`LICENSE:1` | Argus 自有内容 | 采用 pack 时明确保留 |
| SpecRail pack | `workflow.yaml`、`checks/`、`schemas/`、`templates/`、`skills/`、`tools/`（新增） | 缺失 | 提供确定性 workflow 与 gates |

## 设计方案

从同 owner 的 `majiayu000/specrail` 固定 commit
`f3251fe27e13a61c73304dbe001b1d9091c948e2` 采用仓库级 pack。复制 pack
拥有的目录与 root workflow 文件，但不覆盖 Argus 的 README、LICENSE、
CHANGELOG、既有 docs/specs 或 Rust CI。新增 `SPEC.md` 记录 pack 规范，新增
`.github/workflows/workflow-check.yml` 作为独立 CI。

采用完整依赖闭包而不是只复制三个 gate 脚本：`github_pr_evidence.py` 依赖
GitHub snapshot/reference/sensitive helpers，`pr_gate.py` 依赖 workflow policy，
`runtime_ledger_gate.py` 依赖 PR gate 与 runtime rules；`check_workflow.py` 还会
验证 schemas、templates、skills lock、review/policy 与 fixtures。

## Product-to-Test Mapping

| Behavior invariant | Implementation area | Verification |
| --- | --- | --- |
| B-001 | SpecRail root files及 `checks/ schemas/ templates/ skills/ tools/ review/ policies/ examples/ docs/` | `python3 checks/check_workflow.py --repo .` |
| B-002 | 复制清单与 git diff | `git diff --name-status origin/main...HEAD`；确认 Argus 原文件未被修改 |
| B-003 | `checks/check_workflow.py`、现有 `specs/GH*/` | `python3 checks/check_workflow.py --repo . --all-specs` |
| B-004 | `checks/github_pr_evidence.py` 及 helpers | 对 PR #75 生成 evidence；前后比较远端 PR head/state 未变化 |
| B-005 | `checks/github_review_evidence.py`、`checks/github_pr_evidence.py`、`checks/pr_gate.py` | 当前-head review artifact 可通过；missing/stale artifact 必须 blocked |
| B-006 | `checks/runtime_ledger_gate.py`、runtime schema/rules | 对 `.git/codex/implx/current.json` 的兼容副本运行 gate；缺证据负例必须 blocked |
| B-007 | `.github/workflows/workflow-check.yml` | `git diff` 保留 `.github/workflows/ci.yml`；GitHub Actions 两个 workflow 均可见 |
| B-008 | `specrail-source.json`、`specrail-manifest.json`、`checks/verify_specrail_adoption.py` | source checkout 与 143 个 managed target files 的 hash 全匹配；`git diff --check` |

## 数据流

- 输入：版本化 workflow/config、GitHub 只读 CLI evidence、repo-local checkpoint。
- 处理：Python checks 读取 YAML/JSON/Markdown，离线输出 gate decision JSON。
- 输出：`allowed`、`warn`、`needs_human` 或 `blocked` 及 blockers。
- 持久化：仅显式 evidence/checkpoint 文件；gate 不写 GitHub。
- 外部调用：只有 `github_*_evidence.py` 通过 `gh` 只读查询 GitHub。

## 备选方案

- 只复制 `pr_gate.py` 三个文件：否，直接依赖与 policy/schema 版本会漂移，
  `check_workflow.py` 无法证明 pack 自洽。
- git submodule：否，首次采用增加 checkout/CI 复杂度；复制 pack 更容易审计。
- 覆盖 Argus root 文档：否，消费者文档不属于 SpecRail pack 的替换范围。

## 风险

- Security：evidence adapter 调用 `gh`，必须保持只读；sensitive registry 检查
  防止 gate 证据泄漏秘密。
- Compatibility：完整 pack 可能对旧 GH57-GH64 packet 提出更严格格式要求；
  必须在提交前修正兼容性而不是跳过 `--all-specs`。
- Performance：新增 Python tests 与 workflow check，预期只影响开发 CI。
- Maintenance：采用的是固定快照；后续升级需要显式来源 commit 与 diff。

## 测试计划

- [ ] Unit tests：运行 consumer-portable 上游完整测试与 Argus adoption tests，`python3 -m pytest -q`。
- [ ] Integration tests：`check_workflow.py` 基础与 `--all-specs`。
- [ ] Gate smoke：为 PR #75 采集 evidence 并运行 `pr_gate.py`；验证 runtime ledger。
- [ ] Product regression：`cargo check --workspace --all-targets` 和
      `cargo test --workspace --all-targets`。

## 回滚方案

撤销 GH-80 引入的 SpecRail-owned 文件与独立 workflow-check；不改动 Argus
README、LICENSE、CHANGELOG、现有 CI、产品代码或既有 spec packet。

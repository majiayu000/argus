# Tech Spec

## Linked Issue

GH-93

## Codebase Context

| Area | Verified anchor | Current behavior | Why relevant |
| --- | --- | --- | --- |
| Report model | `crates/argus-core/src/lib.rs:53` | `Finding` 含 rule/severity/detail/location/capability/evidence/host | renderer 可无 schema 变更地转换全部字段 |
| Artifact report | `crates/argus-core/src/lib.rs:107` | `ScanReport` 含 artifact/path/package/decision/findings | artifact-level fallback 与 coordinates 来源 |
| Format enum | `crates/argus-cli/src/main.rs:260` | 仅 `Text`/`Json` | 扫描命令增加 `Sarif` |
| Single report output | `crates/argus-cli/src/main.rs:555` | report 成功后 print，再按 decision 返回 exit | 保持 error-before-output 与退出码语义 |
| Agent multi-report output | `crates/argus-cli/src/agent.rs:55` | text/JSON 分支自行输出多个 report | SARIF 需把多个 report 放入同一 run |
| Corpus eval | `crates/argus-cli/src/corpus.rs:135` | 复用 `Format` 输出评估 metrics | 显式拒绝 SARIF，避免 metrics 冒充 scan results |
| CI | `.github/workflows/ci.yml:1` | fmt/clippy/test/corpus | 增加 clean fixture 生成与官方 upload smoke |

## Proposed Design

新增私有 `crates/argus-cli/src/sarif.rs`，使用 `serde_json::Value` 构造最小、
确定性的 SARIF 2.1.0 文档：

- 一个 invocation 对应一个 run；driver 为 `argus`，带 Cargo version、
  information URI 与按 rule ID 排序的 descriptors。
- rule descriptor 由稳定 rule ID 派生 name/description/help URI/default level；
  renderer 不维护会与规则实现漂移的第二份闭集 registry。
- result 按 report/findings 原顺序输出，ruleIndex 指向排序后的 descriptor。
- 位置优先使用首个合法 `file:positive-line` evidence，其次 finding.location，
  最后 report.path；后两者不含 region。已知 `package.json:scripts` 语义 locator
  映射回真实 `package.json`，所有路径按 UTF-8 URI-reference 百分号编码。
- properties 保留 artifact kind、package name/version、decision、capability、host、
  evidence；缺失字段省略而不是填空字符串。
- 使用固定 FNV-1a 64-bit 算法生成 `argusFinding/v1` fingerprint，输入格式版本化，
  不依赖随机 hash seed。

`emit_report` 与 `cmd_agent_scan` 只在已有 report 后调用 renderer。现有 `main`
error path 仍只写 stderr/exit 2，因此不会输出误导性的 clean SARIF。

CI 使用无 finding 的临时 package fixture，生成 `target/argus-sarif-smoke.sarif`，
同仓库 push/PR 才运行 `github/codeql-action/upload-sarif@v4`；fork PR 跳过需要写权限
的 upload。unit/integration tests 只检查本地 JSON 与 CLI stdout/stderr，不访问网络。

## Planned Changes Manifest

<!-- specrail-planned-changes
{"version":1,"issue":93,"complete":true,"paths":[".github/workflows/ci.yml","README.md","crates/argus-cli/src/agent.rs","crates/argus-cli/src/corpus.rs","crates/argus-cli/src/main.rs","crates/argus-cli/src/sarif.rs","crates/argus-cli/tests/sarif_cli.rs","specs/GH93/product.md","specs/GH93/tech.md","specs/GH93/tasks.md"],"spec_refs":["specs/GH93/product.md","specs/GH93/tech.md","specs/GH93/tasks.md"]}
-->

## Product-to-Test Mapping

| Product invariant | Implementation area | Verification |
| --- | --- | --- |
| B-001 | Clap `Format`; corpus rejection | CLI help tests; `corpus eval --format sarif` exits 2 |
| B-002 | SARIF document/driver | package snapshot asserts schema/version/tool version |
| B-003 | descriptor index | same-location multi-rule snapshot asserts two descriptors/results |
| B-004 | severity mapper + unchanged exit mapping | unit severity table; CLI block SARIF exits 1 with valid stdout |
| B-005 | evidence parser/location renderer | agent line evidence、semantic locator 与 URI encoding snapshots |
| B-006 | report properties/fallback | lockfile/package snapshots |
| B-007 | fixed FNV-1a fingerprint | repeat-render equality and distinct-rule tests |
| B-008 | result properties | agent capability snapshot |
| B-009 | `sarif.rs` tests | package/lockfile/agent/provenance named snapshot tests |
| B-010 | existing main error path + CLI integration | nonexistent scan path exits 2, stdout empty, stderr non-empty |
| B-011 | CI smoke + official upload action | GitHub `upload-sarif@v4` check on same-repo runs |
| B-012 | README SARIF section | targeted documentation review and command smoke |

## Risks

- GitHub rejects overly broad or malformed SARIF. Mitigation: deterministic minimal schema,
  official upload smoke, and structural snapshots.
- Paths may not contain a parseable line. Mitigation: valid artifact-level location without region.
- Renderer could push `main.rs` over 800 lines. Mitigation: all conversion logic lives in `sarif.rs`.
- CI upload permissions are unavailable to fork PRs. Mitigation: generation/tests always run;
  only the network upload step is conditionally skipped for forks.

## Rollback Plan

Remove `Sarif` from the CLI enum/output branches, delete the renderer/tests/upload smoke, and revert
README/spec changes. Text/JSON schemas and core report types remain unchanged, so no data migration
or compatibility shim is required.

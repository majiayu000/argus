# Tech Spec

## Linked Issue

GH-86

## Codebase Context

| Area | Verified anchor | Current behavior | Why relevant |
| --- | --- | --- | --- |
| CLI command surface | `crates/argus-cli/src/main.rs:67` | `Cmd` 暴露八个生态 fetch 子命令 | README 命令必须与实际 Clap 名称一致 |
| README headline/usage | `README.md:6` | headline 与 Usage 只完整展示前三个生态 | 用户无法发现后五个命令 |
| README layout/status | `README.md:190` | Layout 缺五个 crate；`README.md:226` 仍称由 #22 跟踪 | 与 `main` 实现不一致 |
| Attack catalog ecosystem gaps | `docs/supply-chain-attacks.md:75` | PyPI/crates.io 仍标为完全 gap | 已存在对应 scanner，但仍需保留静态分析限制 |
| Crypto dictionary | `crates/argus-rules/src/name.rs:38` | 已包含 `ethers`、`web3`、`viem`、`wagmi`、`hardhat`、`truffle`、`bs58` | 目录仍称这些名称缺失 |
| Crypto regression fixture | `corpus/index.json` 与 `corpus/fixtures/crypto-key-stealer/` | 合成 fixture 已纳入 corpus | 可声明合成回归覆盖，不可夸大真实事件验证 |

## Proposed Design

1. 在 README 的产品描述后新增单一“Ecosystem capability matrix”，以八行固定
   结构记录 CLI、完整性来源、制品/检查面和限制。
2. 在 Usage 增加后五个命令的可复制示例；在 Layout 增加对应 crate。
3. 更新 Status 日期和历史链接，将 #22 标为已完成 umbrella，并链接 #49–#53；
   保留 pre-release 与从源码构建声明。
4. 修正攻击目录所有已定位的过期 PyPI/crates.io/crypto 文案。真实事件矩阵只在
   当前规则/fixture 能支持时调整 verdict，并重新计算汇总。
5. 用定向文本检查、CLI help、workspace check/test 和 corpus 回归证明文档与代码
   面一致；不新增仅为文档服务的生产 API。

## Planned Changes Manifest

<!-- specrail-planned-changes
{"version":1,"issue":86,"complete":true,"paths":["README.md","docs/supply-chain-attacks.md","specs/GH86/product.md","specs/GH86/tech.md","specs/GH86/tasks.md"],"spec_refs":["specs/GH86/product.md","specs/GH86/tech.md","specs/GH86/tasks.md"]}
-->

## Product-to-Test Mapping

| Product invariant | Implementation area | Verification |
| --- | --- | --- |
| B-001 | README Usage + capability matrix | `cargo run -q -p argus-cli -- --help`; shell loop `rg -q "argus-cli -- $cmd" README.md` for all eight commands |
| B-002 | README capability matrix | manual matrix audit against scanner crate docs/tests and PR #49–#53 bodies |
| B-003 | README Status | `rg -n '#49|#50|#51|#52|#53|#22' README.md` |
| B-004 | README Status | `rg -n 'Pre-release|Build it from source' README.md` |
| B-005 | README headline, Usage, Layout, Status, stack table | targeted `rg` plus reviewer comparison of all five sections |
| B-006 | attack catalog + `POPULAR_PACKAGES`/corpus facts | `rg -n 'PyPI not yet|npm-only|dictionary needs|PyPI parity' docs/supply-chain-attacks.md`; `cargo run -q -p argus-cli -- corpus test --corpus corpus` |
| B-007 | attack catalog incident verdicts | reviewer maps each edited row to existing rule/fixture evidence |
| B-008 | attack catalog summary | manual count of table verdicts compared with summary |
| B-009 | README matrix limitations | reviewer confirms Go/NuGet/Maven/RubyGems/Composer limitations against merged PR evidence |
| B-010 | docs/spec-only manifest | `git diff --name-only origin/main...HEAD` contains exactly five planned paths; `git diff --check origin/main...HEAD` |

## Risks

- Security claims may be overstated when integrity verification is confused with malicious-content
  detection. Mitigation: every row couples capability with an explicit limitation.
- Attack matrix counts may drift when a row is edited. Mitigation: recount after edits and require
  reviewer verification.
- README can become too dense. Mitigation: one concise matrix plus runnable examples; detailed rules
  remain in crate tests and attack catalog.

## Rollback Plan

The change is documentation/spec-only. Revert the GH86 commit/PR; no persisted data, API, schema,
release artifact, or runtime migration is involved.

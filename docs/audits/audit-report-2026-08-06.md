# Argus 全量优化与安全审计报告

> - 日期：2026-08-06
> - 分支：`chore/specrail-tooling-move`，起点 `f132051`
> - 范围：21 个 Rust crates、GitHub Action、CI/发布、SpecRail、依赖与文档
> - 方法：3 条并行只读审计线 + 主线复核、修复与回归
> - 前次审计：`docs/audits/audit-report-2026-07-13.md`

## 结论

本轮完成 49 个独立优化检查点，修复或关闭 19 个本轮及历史问题。当前台账共 25 项：
22 项 resolved，3 项 open；无 Critical。高风险修复集中在不可信文件读取、脚本覆盖、
归档资源耗尽、Sigstore 零验证、PyPI/NuGet 身份和完整性、OSV 证据保留以及多生态
超大安全源码静默跳过。

仍开放的 3 项不是本轮可安全偷改的机械缺陷：AGT-02 显式 baseline 失败策略由已批准
GH64 规格规定为 Info；Windows 的安全 OSV/intelligence 存储仍未实现；NuGet 完整版本
等价规范仍需独立规格工作。它们均已显式记录，Windows 能力边界也已写入 README。

## 49 轮优化记录

| # | 角度 | 结果 |
|---:|---|---|
| 1 | 仓库边界 | 确认产品代码与 SpecRail pack root，避免在错误 cwd 执行检查 |
| 2 | 流程 | 读取并遵循 `AGENT_USAGE.md`、workflow/state/label 与 implement skill |
| 3 | 基线 | 建立 fmt、clippy、workspace tests、SpecRail、Python tests 基线 |
| 4 | 依赖漏洞 | `cargo audit` 验证 317 个依赖无已知 RustSec 漏洞 |
| 5 | 依赖来源 | cargo-deny advisories/bans/sources 基线通过 |
| 6 | AGT-02 | 用真实 YAML 解析替换逐行 frontmatter 解析 |
| 7 | AGT-02 | 正确处理 literal/folded block、CRLF 与 chomping |
| 8 | AGT-02 | 非字符串 description/name 显式忽略 |
| 9 | AGT-02 | 增加多行正文变化必改 hash 的回归测试 |
| 10 | 脚本覆盖 | hook/skill 目录中的无扩展名文件进入脚本分析 |
| 11 | PowerShell | 新增 `.ps1`、`.psm1` 表面识别 |
| 12 | Shebang | 无扩展名 Bash/Python/Node/Deno 脚本按解释器解析 |
| 13 | PowerShell | 检测下载管道到 `iex` 的直接远程执行模式 |
| 14 | 文件边界 | 新增跨 crate 有界普通文件读取原语 |
| 15 | Unix 安全 | 使用 `NOFOLLOW`、`NONBLOCK`、descriptor 类型检查 |
| 16 | 竞态 | 同一 descriptor 上校验大小并以 `limit + 1` 捕获增长 |
| 17 | 文件测试 | 覆盖恰好上限、超限、symlink、设备文件 |
| 18 | npm 本地扫描 | `package.json` 改为有界、UTF-8、普通文件读取 |
| 19 | lockfile | CLI lockfile 输入改为共享 no-follow 有界读取 |
| 20 | baseline | baseline 文件增加 16 MiB 普通文件上限 |
| 21 | snapshot | agent snapshot 增加 64 MiB 普通文件上限 |
| 22 | corpus | corpus index 增加 16 MiB 普通文件上限 |
| 23 | npm cache | metadata cache 消除校验后再跟随路径读取的 TOCTOU 面 |
| 24 | hook 命令 | 增加有界、quote-aware tokenization |
| 25 | hook 命令 | 支持常见解释器包装的脚本 operand |
| 26 | hook 路径 | 拒绝绝对路径、`..` 与 canonical root 外路径 |
| 27 | hook 内容 | 拒绝 symlink/special file/超限/非 UTF-8，标为 unassessed |
| 28 | shell 复杂度 | pipeline、逻辑组合、inline command mode 不再误判 clean |
| 29 | 策略注册 | 新增 `AGT-05-hook-unassessed` approval-only 注册项 |
| 30 | TAR/ZIP | 增加 100,000 entry 硬上限 |
| 31 | TAR/ZIP | 增加单路径 4 KiB 与 128 层深度上限 |
| 32 | TAR/ZIP | 增加累计 64 MiB 路径字节预算和溢出检查 |
| 33 | Sigstore | 显式验证要求下零个 Verified bundle 必须阻断 |
| 34 | Sigstore CI | feature-enabled integration test 加入 CI |
| 35 | PyPI sdist | 超大 Python/build/metadata 安全文件 fail closed |
| 36 | PyPI wheel | 超大 Python、`.pth`、METADATA fail closed |
| 37 | crates.io | 超大 Rust/Cargo.toml/build surface fail closed |
| 38 | Go | 超大 `.go`/`go.mod` fail closed 并传播扫描错误 |
| 39 | Maven | 超大 embedded build/MANIFEST fail closed |
| 40 | Composer | 超大 PHP/composer.json fail closed |
| 41 | RubyGems | metadata 解压上限收紧，超大 Ruby 文件 fail closed |
| 42 | NuGet | 超大 MSBuild/PowerShell trigger 不再整文件载入或跳过 |
| 43 | NuGet 完整性 | catalog 网络、解析、异源与未知 hash 算法错误 fail closed |
| 44 | PyPI 身份 | registry coordinate 与 PEP 503/440 embedded identity 双向校验 |
| 45 | Go 契约 | report path 固定为可信 coordinate，不再显示未使用 cache_dir |
| 46 | OSV 证据 | 集成扫描在 `ScanReport.vulnerability` 保留完整 query/advisory evidence |
| 47 | Action 兼容 | 同 minor 接受 additive JSON 字段，同时严格校验已知字段类型 |
| 48 | 本地包预算 | 增加 100,000 文件、128 深度、64 MiB 累计文本预算 |
| 49 | 供应链与文档 | URL userinfo 拒绝、许可证 CI 闭集、发布例外与 Windows 边界对齐 |

## 关键修复面

### 不可信输入与资源预算

- 共享文件读取原语避免 FIFO 阻塞、symlink 跟随、无界分配及读时增长。
- tar/zip 在任何条目写盘前执行 entry/path/depth/累计预算。
- npm 本地目录除单文件上限外，再限制文件数量、深度和累计文本量。
- 所有生态的可执行/构建类源码超限均返回 operational error，不再产生虚假 clean。

### 身份、完整性与证据

- PyPI 输出只使用可信 registry coordinate；embedded metadata 不一致直接失败。
- NuGet 只有“catalog 中确实不存在 packageHash”保留显式未验证 Info，其余 catalog
  错误全部失败。
- Sigstore 显式开启时必须至少有一个 bundle 真正 Verified。
- 集成 OSV 不再只保留 findings；JSON report 同时携带完整 freshness/source/advisory
  证据。

### Agent 与自动化

- AGT-02 多行 YAML 绕过已关闭。
- hook/skill 的无扩展名和 PowerShell 脚本纳入扫描。
- hook 引用脚本只允许根内、普通、有界 UTF-8 文件；复杂命令显式进入人工审批。
- Action JSON parser 允许安全的 additive evolution，避免 `0.1.x` 内契约自相矛盾。
- cargo-deny 新增许可证 allowlist 并进入 CI；Sigstore feature integration 也成为 CI 门禁。

## 已反证或保持不变

- Go `.ziphash` 缺失不是 GOPROXY 协议违规；继续用显式
  `go-integrity-unverified` 表达，而 advertised mismatch 仍硬失败。
- AGT-02 显式 baseline 缺失/损坏的 Info 行为与 `tooling/specrail/specs/GH64/product.md`
  已批准规格一致，本轮未绕过 SpecRail 直接改产品语义。
- GitHub 线上复核显示截至本报告时没有 `v0.1.0` Release；README 的 pre-release 声明
  仍准确，不做虚假发布文案更新。

## 剩余风险与后续规格队列

| 优先级 | 项目 | 当前控制 |
|---|---|---|
| P1/spec | 显式 AGT-02 baseline 失败仍 allow-compatible | 已在台账记录；改变前必须修订 GH64 product/tech/test-plan |
| P2/platform | Windows OSV/intelligence secure cache 未实现 | 命令 fail closed；README 明示能力边界 |
| P2/spec | NuGet 完整版本等价规范 | 现有 exact/canonical checks 保留；需独立 test matrix |
| roadmap | obfuscation、全 lockfile 扫描、benchmark、weighted risk | 对应公开 issue #141/#144/#145/#146，未把规划冒充完成 |

## 验证门禁

本报告完成前要求以下命令全部通过：

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo test -p argus-fetch --features sigstore --test sigstore_integration
cargo run -q -p argus-cli -- corpus test --corpus corpus
cargo audit --json
cargo deny check advisories bans licenses sources
npm test --prefix action
npm run package --prefix action
python3 -m pytest -q scripts/tests
cd tooling/specrail && python3 checks/check_workflow.py --repo . --all-specs
cd tooling/specrail && python3 checks/verify_specrail_adoption.py --repo .
cd tooling/specrail && python3 -m pytest -q
git diff --check
```

机器可读台账：`.audit/findings.json`。

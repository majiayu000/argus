# Security Policy

## 报告漏洞

不要为 Argus 本身、发布流程或依赖中的潜在漏洞创建公开 issue。请使用仓库的
[GitHub private vulnerability reporting](https://github.com/majiayu000/argus/security/advisories/new)，
并附上受影响版本或 commit、复现条件、实际与预期结果。不要附带真实凭据或仍可执行的
恶意包。

## 发布信任边界

源码 `main`、candidate workflow 和草稿 Release 都不是发布物。只有满足以下全部条件的
SemVer tag 才能作为受支持的二进制来源：

- tag 指向 `main` 的已验证 commit，且 Cargo、CLI 与 Action 默认版本一致；
- GitHub Release 已 immutable publish；
- raw binary/archives 同时通过 GitHub REST digest、已 attested
  `release_manifest.json` SHA-256 和绑定 repo/workflow/tag/commit/GitHub-hosted
  runner 的 artifact attestation 验证；
- `v1` 仅由受保护的人工 fast-forward 指向该 release commit。

Action 不接受任意下载 URL、repository override、浮动 `latest` 或任意命令参数。它不
读取调用方 token，任何下载、摘要、attestation、版本自检或报告解析失败都作为
operational error 失败，不会返回 clean。

## 撤回与替换

immutable tag、asset 和用户 pin 不得重写或删除。发现问题后先发布 advisory，再以新的
patch version 走完整门禁；经过新的人工授权后，`v1` 只能 fast-forward 到修复版本。
文档必须明确列出受影响版本和安全替代版本。

## 发布审批边界

本仓库为个人所有（user-owned），当前只有一个具备仓库访问权的账号。GitHub
`release` environment 的 required-reviewer + prevent-self-review 要求审批者不得
是触发发布的身份，而唯一账号既是 tag 推送者也是唯一可能的审批者，因此该门禁在
单人仓库中无法被合法满足——publish job 会永久停在 awaiting review。

已接受的取舍（记录留痕）：

- 接受方：majiayu000（仓库唯一 admin）
- 日期：2026-07-23
- 放宽范围：仅移除 `.github/workflows/release.yml` publish job 中对 `release`
  environment required-reviewer / prevent-self-review / branch-policy 的断言。
- 保留不变：immutable releases 断言、tag（`v*.*.*`）与 `v1` 分支 ruleset 断言、
  全部 attestation 与确定性资产校验、发布后 `gh release verify` 复核。这些门禁
  仍然 fail closed。
- 恢复条件：一旦引入第二个可信 reviewer 账号，必须还原上述断言（`release.yml`
  publish job 的 environment 检查块），恢复四眼发布控制。

此放宽不适用于爆炸半径最大的保护：tag 与 `v1` 仍不可变/不可强推，release 字节
发布后不可替换。

# Product Spec

## Linked Issue

GH-86

complexity: medium

## 用户问题

Argus 已在 `main` 实现 npm、PyPI、crates.io、Go modules、NuGet、Maven、
RubyGems 和 Composer/Packagist 八个生态的独立扫描入口，但 README 与攻击目录
仍把五个后续生态写成未来工作，并保留 PyPI、crates.io 与 crypto/web3
typosquat 的过期 gap。这会让用户误判当前命令面、完整性保证与检测边界。

## 目标

- 让八个生态及其 CLI 子命令在 README 中可发现。
- 对每个生态明确区分完整性来源、制品格式、静态检查面与已知盲区。
- 将“已在 `main` 实现”“由测试/fixture 验证”“已正式发布”保持为三个不同状态。
- 依据当前代码与测试修正攻击目录的生态覆盖、crypto/web3 字典和 fixture 状态。

## 非目标

- 不增加或改变扫描器、规则、退出码、网络行为或 release 状态。
- 不把静态扫描描述为完整恶意代码证明，也不为未测试的真实事件宣称直接命中。
- 不重写历史事件来源或新增未经 issue 要求的攻击研究。

## 行为不变量

1. B-001 README 必须列出八个生态的实际 CLI 子命令，名称与 Clap 暴露的
   `fetch`、`pypi-fetch`、`crates-fetch`、`go-fetch`、`nuget-fetch`、
   `maven-fetch`、`gems-fetch`、`composer-fetch` 完全一致。
2. B-002 每个生态的能力矩阵必须同时说明完整性来源、制品格式、检查面与
   至少一个明确限制；弱摘要或缺失摘要不得写成强验证。
3. B-003 README 必须把五个后续生态描述为已合入 `main`，链接 PR #49–#53，
   并把已关闭的 #22 保留为历史 umbrella，而非未来工作。
4. B-004 README 必须继续明确项目为 pre-release；代码已实现不得被表述为
   已发布、已稳定或已提供二进制制品。
5. B-005 README 的 Usage、Layout、headline、Status 和 Agent Infra Stack 对
   支持生态的描述不得互相矛盾。
6. B-006 攻击目录中关于 PyPI、crates.io 和 crypto/web3 字典的描述必须与
   当前扫描器、`POPULAR_PACKAGES` 和 fixture 状态一致。
7. B-007 真实攻击条目的 verdict 必须区分静态扫描面存在与该具体事件已被
   fixture 验证；没有事件级证据时不得从 gap 直接升级为无条件 ✅。
8. B-008 攻击矩阵的汇总数字必须与更新后的逐行 verdict 一致，禁止保留旧计数。
9. B-009 文档必须说明 scanner 的 operational limitations；不允许把未检查的
   bytecode、动态代码、签名或透明日志默认为安全。
10. B-010 文档改动不得修改代码、判决、测试数据或 release 配置；同一变更
    可重复应用/审阅而不产生运行时副作用。

## Acceptance Criteria

- [ ] 每个 CLI 生态子命令可从 README 发现。
- [ ] README 不再把五个已合入生态描述为未来工作。
- [ ] 能力矩阵逐生态披露完整性、制品、扫描面和限制。
- [ ] 攻击目录的 PyPI/crates.io/crypto gap 与当前实现一致。
- [ ] “implemented”“validated”“released”保持分离，pre-release 状态不变。
- [ ] 所有剩余限制可追溯到当前源码、测试或合并 PR。

## Boundary Checklist

| Category | Verdict |
| --- | --- |
| Empty / missing input | N/A：仅修正文档，不新增输入接口。 |
| Error and failure paths | covered: B-002, B-009（缺失/弱完整性与 operational error 不得被文案掩盖）。 |
| Authorization / permission | N/A：不新增权限或授权行为。 |
| Concurrency / race / ordering | N/A：静态文档无并发状态。 |
| Retry / repetition / idempotency | covered: B-010。 |
| Illegal state transitions | covered: B-004（pre-release 不得被文案升级为 released）。 |
| Compatibility / migration | covered: B-003, B-005。 |
| Degradation / fallback | covered: B-002, B-009。 |
| Evidence and audit integrity | covered: B-006, B-007, B-008。 |
| Cancellation / interruption / partial completion | covered: B-005（各公开段落必须形成一致快照，不能只修一处）。 |

## Edge Cases

- 某生态可校验摘要但不检查主要运行载荷（如 Maven `.class`、NuGet DLL）：
  必须同时陈述完整性能力与内容盲区。
- 真实事件所属生态已支持，但没有该事件专用 fixture：只能写“具备相关静态检查面”
  或部分覆盖，不能声称已验证直接命中。
- crypto/web3 名字已进入字典且有合成 fixture：允许写为合成回归覆盖，但不得
  将其等同于真实恶意包验证。
